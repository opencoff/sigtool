// encrypt.go -- Ed25519 based encrypt/decrypt
//
// (c) 2016 Sudhi Herle <sudhi@herle.net>
//
// Licensing Terms: GPLv2
//
// If you need a commercial license for this work, please contact
// the author.
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.
//

// Implementation Notes for Encryption/Decryption:
//
// Header: has 3 parts:
//    - Fixed sized header
//    - Variable sized protobuf encoded header
//    - SHA256 sum of both above.
//
// Fixed size header:
//    - Magic: 7 bytes
//    - Version: 1 byte
//    - VLen:    4 byte
//
// Variable Length Segment:
//    - Protobuf encoded, per-recipient wrapped keys
//
// The variable length segment consists of one or more
// recipients, each with their individually wrapped keys.
//
// The input data is encrypted with an expanded random 32-byte key:
//    - hkdf-sha512 of random key, salt, context
//    - the hkdf process yields a data-encryption key, nonce and hmac key.
//    - we use the header checksum as the 'salt' for HKDF; this ensures that
//      any modification of the header yields different keys
//
// We also calculate the cumulative hmac-sha256 of the plaintext blocks.
//    - When sender identity is present, we sign the final hmac and append
//	the signature as the "trailer".
//    - When sender identity is NOT present, we put random bytes as the
//      "signature". ie in either case, there is a trailer.
//
// Note: If the trailer is missing from a sigtool encrypted file - the
// recipient has no guarantees of content immutability (ie tampering
// from one of the _other_ recipients).
//
// The input data is broken up into "chunks"; each no larger than
// maxChunkSize. The default block size is "chunkSize". Each block
// is AEAD encrypted:
//   AEAD nonce = header.nonce || block#
//   AD of AEAD = chunk length+eof marker
//
// The encrypted block (includes the AEAD tag) length is written
// as a big-endian 4-byte prefix. The high-order bit of this length
// field is set for the last-block (denoting EOF).
//

package sign

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"os"

	"github.com/opencoff/sigtool/internal/pb"
)

// Encryption chunk size = 4MB
const (
	// The latest version of the tool's output file format
	_SigtoolVersion = 3

	chunkSize    uint32 = 4 * 1048576 // 4 MB
	maxChunkSize uint32 = 1 << 30
	_EOF         uint32 = 1 << 31

	_Magic       = "SigTool"
	_MagicLen    = len(_Magic)
	_FixedHdrLen = _MagicLen + 1 + 4 // 1: version, 4: len of variable segment

	_AesKeySize    = 32
	_AEADNonceSize = 12
	_SaltSize      = 32
	_RxNonceSize   = 12 // nonce size of per-recipient encrypted blocks

	_WrapReceiver     = "Receiver Key"
	_WrapSender       = "Sender Sig"
	_DataKeyExpansion = "Data Key Expansion"
)

// Encryptor holds the encryption context
type Encryptor struct {
	pb.Header
	key []byte // root key

	nonce []byte // nonce for the data encrypting cipher
	buf   []byte // I/O buf (chunk-sized)

	ae   cipher.AEAD
	hmac hash.Hash

	// ephemeral key
	encSK []byte

	// sender identity
	sender *PrivateKey

	auth    bool // set if the sender idetity is sent
	started bool
	stream  bool
}

// Create a new Encryption context for encrypting blocks of size 'blksize'.
// If 'sk' is not nil, authenticate the sender to each receiver.
func NewEncryptor(sk *PrivateKey, blksize uint64) (*Encryptor, error) {
	var blksz uint32

	switch {
	case blksize == 0:
		blksz = chunkSize
	case blksize > uint64(maxChunkSize):
		blksz = maxChunkSize
	default:
		blksz = uint32(blksize)
	}

	// generate ephemeral Curve25519 keys
	esk, epk, err := newSender()
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	key := randBuf(_AesKeySize)
	salt := randBuf(_SaltSize)

	e := &Encryptor{
		Header: pb.Header{
			ChunkSize: blksz,
			Salt:      salt,
			Pk:        epk,
		},

		key:    key,
		encSK:  esk,
		sender: sk,
	}

	if err = e.addSenderSig(sk); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	return e, nil
}

// Add a new recipient to this encryption context.
func (e *Encryptor) AddRecipient(pk *PublicKey) error {
	if e.started {
		return ErrEncStarted
	}

	w, err := e.wrapKey(pk)
	if err == nil {
		e.Keys = append(e.Keys, w)
	}

	return err
}

// Encrypt the input stream 'rd' and write encrypted stream to 'wr'
func (e *Encryptor) Encrypt(rd io.Reader, wr io.WriteCloser) error {
	if e.stream {
		return ErrEncIsStream
	}

	if !e.started {
		err := e.start(wr)
		if err != nil {
			return err
		}
	}

	buf := make([]byte, e.ChunkSize)

	var i uint32
	var eof bool
	for !eof {
		n, err := io.ReadAtLeast(rd, buf, int(e.ChunkSize))
		if err != nil {
			switch err {
			case io.EOF, io.ErrClosedPipe, io.ErrUnexpectedEOF:
				eof = true
			default:
				return fmt.Errorf("encrypt: I/O read error: %w", err)
			}
		}

		if n >= 0 {
			err = e.encrypt(buf[:n], wr, i, eof)
			if err != nil {
				return err
			}

			i++
		}
	}

	return wr.Close()
}

// Begin the encryption process by writing the header
func (e *Encryptor) start(wr io.Writer) error {
	varSize := e.Size()

	buffer := make([]byte, _FixedHdrLen+varSize+sha256.Size)
	fixHdr := buffer[:_FixedHdrLen]
	varHdr := buffer[_FixedHdrLen : _FixedHdrLen+varSize]
	sumHdr := buffer[_FixedHdrLen+varSize:]

	// Now assemble the fixed header
	copy(fixHdr[:], []byte(_Magic))
	fixHdr[_MagicLen] = _SigtoolVersion
	binary.BigEndian.PutUint32(fixHdr[_MagicLen+1:], uint32(varSize))

	// Now marshal the variable portion
	_, err := e.MarshalTo(varHdr[:varSize])
	if err != nil {
		return fmt.Errorf("encrypt: can't marshal header: %w", err)
	}

	h := sha256.New()
	h.Write(buffer[:_FixedHdrLen+varSize])
	cksum := h.Sum(sumHdr[:0])

	// now make the data encryption keys, nonces etc.
	outbuf := make([]byte, sha256.Size+_AesKeySize+_AEADNonceSize)

	// we mix the header checksum (and it captures the sigtool version, sender
	// identity, etc.)
	buf := expand(outbuf, e.key, cksum, []byte(_DataKeyExpansion))

	var dkey, hmackey []byte

	e.nonce, buf = buf[:_AEADNonceSize], buf[_AEADNonceSize:]
	dkey, buf = buf[:_AesKeySize], buf[_AesKeySize:]
	hmackey = buf

	aes, err := aes.NewCipher(dkey)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if e.ae, err = cipher.NewGCM(aes); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Finally write out the header
	err = fullwrite(buffer, wr)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	e.hmac = hmac.New(sha256.New, hmackey)
	e.buf = make([]byte, e.ChunkSize+4+uint32(e.ae.Overhead()))
	e.started = true

	debug("encrypt:\n\thdr-cksum: %x\n\taes-key: %x\n\tnonce: %x\n\thmac-key: %x\n",
		cksum, dkey, e.nonce, hmackey)

	return nil
}

// encrypt exactly _one_ block of data
// The nonce is constructed from the salt, block# and block-size.
// This protects the output stream from re-ordering attacks and length
// modification attacks. The encoded length & block number is used as
// additional data in the AEAD construction.
func (e *Encryptor) encrypt(pt []byte, wr io.Writer, i uint32, eof bool) error {
	var z uint32 = uint32(len(pt))
	var nonce [_AEADNonceSize]byte

	// mark last block
	if eof {
		z |= _EOF
	}

	copy(nonce[:], e.nonce)

	// now change the upper bytes to track the block#; we use the len+eof as AD
	binary.BigEndian.PutUint32(nonce[:4], i)

	// put the encoded length+eof at the start of the output buf
	b := e.buf[:4]
	ctbuf := e.buf[4:]

	binary.BigEndian.PutUint32(b, z)
	ct := e.ae.Seal(ctbuf[:0], nonce[:], pt, b)

	// total number of bytes written
	n := len(ct) + 4
	err := fullwrite(e.buf[:n], wr)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	e.hmac.Write(b)
	e.hmac.Write(pt)

	if eof {
		return e.writeTrailer(wr)
	}
	return nil
}

// Write a trailer:
//   - if authenticating sender, sign the hmac and put the signature in the trailer
//   - if not authenticating sender, write random bytes to the trailer
func (e *Encryptor) writeTrailer(wr io.Writer) error {
	var tr []byte

	switch e.auth {
	case true:
		var hmac [sha256.Size]byte

		e.hmac.Sum(hmac[:0])

		// We know sender is non null.
		sig, err := e.sender.SignMessage(hmac[:], "")
		if err != nil {
			return fmt.Errorf("encrypt: trailer: %w", err)
		}
		tr = sig.Sig

	case false:
		tr = randBuf(ed25519.SignatureSize)

	}

	if err := fullwrite(tr, wr); err != nil {
		return fmt.Errorf("encrypt: trailer %w", err)
	}
	return nil
}

// Decryptor holds the decryption context
type Decryptor struct {
	pb.Header

	ae   cipher.AEAD
	hmac hash.Hash

	sender *PublicKey

	rd    io.Reader
	buf   []byte
	nonce []byte // nonce for the data decrypting cipher

	key    []byte // Decrypted root key
	hdrsum []byte // cached header checksum
	auth   bool   // flag set to true if sender signed the key
	eof    bool
	stream bool
}

// Create a new decryption context and if 'pk' is given, check that it matches
// the sender
func NewDecryptor(rd io.Reader) (*Decryptor, error) {
	var b [_FixedHdrLen]byte

	_, err := io.ReadFull(rd, b[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt: err while reading header: %w", err)
	}

	if bytes.Compare(b[:_MagicLen], []byte(_Magic)) != 0 {
		return nil, ErrNotSigTool
	}

	// Version check
	if b[_MagicLen] != _SigtoolVersion {
		return nil, fmt.Errorf("decrypt: Unsupported version %d; this tool only supports v%d",
			b[_MagicLen], _SigtoolVersion)
	}

	varSize := binary.BigEndian.Uint32(b[_MagicLen+1:])

	// sanity check on variable segment length
	if varSize > 1048576 {
		return nil, ErrHeaderTooBig
	}
	if varSize < 32 {
		return nil, ErrHeaderTooSmall
	}

	// SHA256 is the trailer part of the file-header
	varBuf := make([]byte, varSize+sha256.Size)

	_, err = io.ReadFull(rd, varBuf)
	if err != nil {
		return nil, fmt.Errorf("decrypt: error while reading header: %w", err)
	}

	// The checksum in the header
	verify := varBuf[varSize:]

	// the checksum we calculated
	var csum [sha256.Size]byte

	h := sha256.New()
	h.Write(b[:])
	h.Write(varBuf[:varSize])
	cksum := h.Sum(csum[:0])

	if subtle.ConstantTimeCompare(verify, cksum) == 0 {
		return nil, ErrBadHeader
	}

	d := &Decryptor{
		rd:     rd,
		hdrsum: cksum,
	}

	err = d.Unmarshal(varBuf[:varSize])
	if err != nil {
		return nil, fmt.Errorf("decrypt: decode error: %w", err)
	}

	if d.ChunkSize == 0 || d.ChunkSize >= maxChunkSize {
		return nil, fmt.Errorf("decrypt: invalid chunkSize %d", d.ChunkSize)
	}

	if len(d.Salt) != _SaltSize {
		return nil, fmt.Errorf("decrypt: invalid nonce length %d", len(d.Salt))
	}

	if len(d.Keys) == 0 {
		return nil, ErrNoWrappedKeys
	}

	// sanity check on the wrapped keys
	for i, w := range d.Keys {
		if len(w.DKey) <= _AesKeySize {
			return nil, fmt.Errorf("decrypt: wrapped key %d: wrong-size encrypted key", i)
		}
	}

	return d, nil
}

// Use Private Key 'sk' to decrypt the encrypted keys in the header and optionally validate
// the sender
func (d *Decryptor) SetPrivateKey(sk *PrivateKey, senderPk *PublicKey) error {
	var err error
	var key []byte

	for i, w := range d.Keys {
		key, err = d.unwrapKey(w, sk)
		if err != nil {
			return fmt.Errorf("decrypt: can't unwrap key %d: %w", i, err)
		}
		if key != nil {
			d.key = key
			d.sender = senderPk
			goto havekey
		}
	}

	return ErrBadKey

havekey:
	if err := d.verifySender(key, senderPk); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	outbuf := make([]byte, sha256.Size+_AesKeySize+_AEADNonceSize)

	buf := expand(outbuf, d.key, d.hdrsum, []byte(_DataKeyExpansion))

	var dkey, hmackey []byte

	d.nonce, buf = buf[:_AEADNonceSize], buf[_AEADNonceSize:]
	dkey, buf = buf[:_AesKeySize], buf[_AesKeySize:]
	hmackey = buf

	d.hmac = hmac.New(sha256.New, hmackey)

	aes, err := aes.NewCipher(dkey)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	d.ae, err = cipher.NewGCM(aes)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	debug("decrypt:\n\thdr-cksum: %x\n\taes-key: %x\n\tnonce: %x\n\thmac-key: %x\n",
		d.hdrsum, dkey, d.nonce, hmackey)

	// We have a separate on-stack buffer for reading the header (4 bytes).
	// Thus, the actual I/O buf will never be larger than the chunksize + AEAD Overhead
	d.buf = make([]byte, int(d.ChunkSize)+d.ae.Overhead())
	return nil
}

// AuthenticatedSender returns true if the sender authenticated themselves
// (the data-encryption key is signed).
func (d *Decryptor) AuthenticatedSender() bool {
	return d.auth
}

// Decrypt the file and write to 'wr'
func (d *Decryptor) Decrypt(wr io.Writer) error {
	if d.key == nil {
		return ErrNoKey
	}

	if d.stream {
		return ErrDecStarted
	}

	if d.eof {
		return io.EOF
	}

	var i uint32
	for i = 0; ; i++ {
		c, eof, err := d.decrypt(i)
		if err != nil {
			return err
		}
		if len(c) > 0 {
			err = fullwrite(c, wr)
			if err != nil {
				return fmt.Errorf("decrypt: %w", err)
			}
		}

		if eof {
			d.eof = true
			return nil
		}
	}
}

// Decrypt exactly one chunk of data
func (d *Decryptor) decrypt(i uint32) ([]byte, bool, error) {
	var ovh uint32 = uint32(d.ae.Overhead())
	var b [4]byte
	var nonce [_AEADNonceSize]byte

	n, err := io.ReadFull(d.rd, b[:])
	if err != nil || n == 0 {
		return nil, false, fmt.Errorf("decrypt: premature EOF while reading header block %d", i)
	}

	m := binary.BigEndian.Uint32(b[:])
	eof := (m & _EOF) > 0
	m &= (_EOF - 1)

	// Sanity check - in case of corrupt header
	switch {
	case m > uint32(d.ChunkSize):
		return nil, false, fmt.Errorf("decrypt: chunksize is too large (%d)", m)

	case m == 0:
		if !eof {
			return nil, false, fmt.Errorf("decrypt: block %d: zero-sized chunk without EOF", i)
		}
		return nil, eof, nil

	default:
	}

	// make the nonce - top 4 bytes are the counter
	copy(nonce[:], d.nonce)
	binary.BigEndian.PutUint32(nonce[:4], i)

	z := m + ovh
	n, err = io.ReadFull(d.rd, d.buf[:z])
	if err != nil {
		return nil, false, fmt.Errorf("decrypt: premature EOF while reading block %d: %w", i, err)
	}

	pt, err := d.ae.Open(d.buf[:0], nonce[:], d.buf[:n], b[:])
	if err != nil {
		return nil, false, fmt.Errorf("decrypt: can't decrypt chunk %d: %w", i, err)
	}

	if uint32(len(pt)) != m {
		return nil, false, fmt.Errorf("decrypt: partial unsealed bytes; exp %d, saw %d", m, len(pt))
	}

	d.hmac.Write(b[:])
	d.hmac.Write(pt)

	if eof {
		return d.processTrailer(pt, eof)
	}

	return pt, eof, nil
}

func (d *Decryptor) processTrailer(pt []byte, eof bool) ([]byte, bool, error) {
	var rd [ed25519.SignatureSize]byte

	_, err := io.ReadFull(d.rd, rd[:])
	if err != nil {
		return nil, false, fmt.Errorf("decrypt: premature EOF while reading trailer: %w", err)
	}

	if !d.auth {
		// these are random bytes; ignore em
		return pt, eof, nil
	}

	var hmac [sha256.Size]byte

	cksum := d.hmac.Sum(hmac[:0])
	ss := &Signature{
		Sig: rd[:],
	}

	if ok := d.sender.VerifyMessage(cksum, ss); !ok {
		return nil, eof, ErrBadTrailer
	}

	return pt, eof, nil
}

// optionally sign the checksum and encrypt everything
func (e *Encryptor) addSenderSig(sk *PrivateKey) error {
	var zero [ed25519.SignatureSize]byte
	var auth bool
	sig := zero[:]

	if e.sender != nil {
		var csum [sha256.Size]byte

		// We capture essential meta-data from the sender; viz:
		//  - Sender tool version
		//  - Sender generated curve25519 PK
		//  - session salt, root key

		h := sha256.New()
		h.Write([]byte(_Magic))
		h.Write([]byte{_SigtoolVersion})
		h.Write(e.Pk)
		h.Write(e.Salt)
		h.Write(e.key)
		cksum := h.Sum(csum[:0])

		xsig, err := e.sender.SignMessage(cksum, "")
		if err != nil {
			return fmt.Errorf("wrap: can't sign: %w", err)
		}
		sig = xsig.Sig
		auth = true
	}

	buf := make([]byte, _AesKeySize+_AEADNonceSize)
	buf = expand(buf, e.key, e.Salt, []byte(_WrapSender))

	ekey, nonce := buf[:_AesKeySize], buf[_AesKeySize:]

	aes, err := aes.NewCipher(ekey)
	if err != nil {
		return fmt.Errorf("senderId: %w", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return fmt.Errorf("senderId: %w", err)
	}

	outbuf := make([]byte, ed25519.SignatureSize+ae.Overhead())
	buf = ae.Seal(outbuf[:0], nonce, sig, nil)

	e.auth = auth
	e.Sender = buf

	return nil
}

// unwrap sender's signature using 'key' and extract the signature
// Optionally, verify the signature using the sender's PK (if provided).
func (d *Decryptor) verifySender(key []byte, senderPk *PublicKey) error {
	outbuf := make([]byte, _AEADNonceSize+_AesKeySize)
	buf := expand(outbuf, key, d.Salt, []byte(_WrapSender))

	ekey, nonce := buf[:_AesKeySize], buf[_AesKeySize:]

	aes, err := aes.NewCipher(ekey)
	if err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}

	var sigbuf [ed25519.SignatureSize]byte
	var zero [ed25519.SignatureSize]byte

	sig, err := ae.Open(sigbuf[:0], nonce, d.Sender, nil)
	if err != nil {
		return fmt.Errorf("unwrap: can't open sender info: %w", err)
	}

	// Did the sender actually sign anything?
	if subtle.ConstantTimeCompare(zero[:], sig) == 0 {
		if senderPk == nil {
			return ErrNoSenderPK
		}

		var csum [sha256.Size]byte

		h := sha256.New()
		h.Write([]byte(_Magic))
		h.Write([]byte{_SigtoolVersion})
		h.Write(d.Pk)
		h.Write(d.Salt)
		h.Write(key)
		cksum := h.Sum(csum[:0])

		ss := &Signature{
			Sig: sig,
		}

		if ok := senderPk.VerifyMessage(cksum, ss); !ok {
			return ErrBadSender
		}

		// we set this to indicate that the sender authenticated themselves;
		d.auth = true
	}

	return nil
}

// Wrap data encryption key 'k' with the sender's PK and our ephemeral curve SK
//
//	basically, we do a scalarmult: Ephemeral encryption/decryption SK x receiver PK
func (e *Encryptor) wrapKey(pk *PublicKey) (*pb.WrappedKey, error) {
	rxPK := pk.ToCurve25519PK()
	sekrit, err := curve25519.X25519(e.encSK, rxPK)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	var shasum [sha256.Size]byte

	rbuf := randBuf(_RxNonceSize)

	h := sha256.New()
	h.Write(e.Salt)
	h.Write(rbuf[:])
	h.Sum(shasum[:0])

	out := make([]byte, _AesKeySize+_RxNonceSize)
	buf := expand(out[:], sekrit, shasum[:], []byte(_WrapReceiver))

	kek, nonce := buf[:_AesKeySize], buf[_AesKeySize:]

	aes, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	ekey := make([]byte, ae.Overhead()+len(e.key))
	w := &pb.WrappedKey{
		DKey:  ae.Seal(ekey[:0], nonce, e.key, pk.Pk),
		Nonce: rbuf,
	}

	return w, nil
}

// Unwrap a wrapped key using the receivers Ed25519 secret key 'sk' and
// senders ephemeral PublicKey
func (d *Decryptor) unwrapKey(w *pb.WrappedKey, sk *PrivateKey) ([]byte, error) {
	ourSK := sk.ToCurve25519SK()
	sekrit, err := curve25519.X25519(ourSK, d.Pk)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}

	var shasum [sha256.Size]byte

	h := sha256.New()
	h.Write(d.Salt)
	h.Write(w.Nonce)
	h.Sum(shasum[:0])

	out := make([]byte, _AesKeySize+_RxNonceSize)
	buf := expand(out[:], sekrit, shasum[:], []byte(_WrapReceiver))

	kek, nonce := buf[:_AesKeySize], buf[_AesKeySize:]

	aes, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	want := _AesKeySize + ae.Overhead()
	if len(w.DKey) != want {
		return nil, fmt.Errorf("unwrap: incorrect decrypt bytes (need %d, saw %d)", want, len(w.DKey))
	}

	pk := sk.PublicKey()
	dkey := make([]byte, _AesKeySize) // decrypted data decryption key

	// we indicate incorrect receiver SK by returning a nil key
	dkey, err = ae.Open(dkey[:0], nonce, w.DKey, pk.Pk)
	if err != nil {
		return nil, nil
	}

	// we have successfully found the correct recipient
	return dkey, nil
}

// Write _all_ bytes of buffer 'buf'
func fullwrite(buf []byte, wr io.Writer) error {
	n := len(buf)

	for n > 0 {
		m, err := wr.Write(buf)
		if err != nil {
			return err
		}

		n -= m
		buf = buf[m:]
	}
	return nil
}

// generate a KEK from a shared DH key and a Pub Key
func expand(out []byte, shared, salt, ad []byte) []byte {
	h := hkdf.New(sha512.New, shared, salt, ad)
	_, err := io.ReadFull(h, out)
	if err != nil {
		panic(fmt.Sprintf("hkdf: failed to generate %d bytes: %s", len(out), err))
	}
	return out
}

func newSender() (sk, pk []byte, err error) {
	var csk [32]byte

	randRead(csk[:])
	clamp(csk[:])
	pk, err = curve25519.X25519(csk[:], curve25519.Basepoint)
	sk = csk[:]
	return
}

// do sha256 on a list of byte slices
func sha256Slices(v ...[]byte) []byte {
	h := sha256.New()
	for _, x := range v {
		h.Write(x)
	}
	return h.Sum(nil)[:]
}

var _debug int = 0

// Enable debugging of this module;
// level > 0 elicits debug messages on os.Stderr
func Debug(level int) {
	_debug = level
}

func debug(s string, v ...interface{}) {
	if _debug <= 0 {
		return
	}

	z := fmt.Sprintf(s, v...)
	if n := len(z); z[n-1] != '\n' {
		z += "\n"
	}
	os.Stderr.WriteString(z)
	os.Stderr.Sync()
}

// EOF
