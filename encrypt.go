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
//    - hkdf-sha3 of random key, salt, context
//    - the hkdf process yields a data-encryption key, nonce and hmac key.
//    - we use the header checksum as the 'salt' for HKDF; this ensures that
//      any modification of the header yields different keys
//    - By using the entire header (including the recipient PKs), we
//      ensure that any recipient cannot further modify the plaintext
//      if/when they send to a different recipient.
//
// We also calculate the cumulative hmac-sha3 of the plaintext blocks.
//    - When sender identity is present, we sign the final hmac and append
//	the signature as the "trailer".
//    - When sender identity is NOT present, we simply send the actual
//      hmac without a signature. In either case, there is a trailer.
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

package sigtool

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha3"
	"crypto/subtle"
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
	_SigtoolVersion = 4

	_chunkSize    uint32 = 128 * 1024
	_maxChunkSize uint32 = 1 << 30
	_EOF          uint32 = 1 << 31

	_Magic       = "SigTool"
	_MagicLen    = len(_Magic)
	_FixedHdrLen = _MagicLen + 1 + 4 // 1: version, 4: len of variable segment

	_Sha3Size      = 64
	_Sha3Size256   = 32
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

	// reader and writer
	rd io.Reader
	wr io.WriteCloser

	auth    bool // set if the sender idetity is sent
	started bool
}

// NewEncryptor creates a new Encryption context for encrypting blocks of size 'blksize'
// by reading from input stream 'rd' and writing to stream 'wr'.
// If 'sk' is not nil, authenticate the sender to each receiver.
func NewEncryptor(sk *PrivateKey, rx *PublicKey, rd io.Reader, wr io.WriteCloser, blksize uint64) (*Encryptor, error) {
	if rx == nil {
		return nil, fmt.Errorf("encrypt: Need at least one recipient")
	}

	var blksz uint32

	switch {
	case blksize == 0:
		blksz = _chunkSize
	case blksize > uint64(_maxChunkSize):
		blksz = _maxChunkSize
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

		rd: rd,
		wr: wr,
	}

	if err = e.addSenderSig(sk); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	if err = e.AddRecipient(rx); err != nil {
		return nil, err
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

// Encrypt starts the encryption for the input stream 'rd' and writes
// the encrypted output to the writer 'wr'.
func (e *Encryptor) Encrypt() error {
	if !e.started {
		err := e.start()
		if err != nil {
			return err
		}
	}

	buf := make([]byte, e.ChunkSize)

	var i uint32
	var eof bool
	for !eof {
		n, err := io.ReadAtLeast(e.rd, buf, int(e.ChunkSize))
		if err != nil {
			switch err {
			case io.EOF, io.ErrClosedPipe, io.ErrUnexpectedEOF:
				eof = true
			default:
				return fmt.Errorf("encrypt: I/O read error: %w", err)
			}
		}

		if n >= 0 {
			err = e.encrypt(buf[:n], i, eof)
			if err != nil {
				return err
			}

			i++
		}
	}

	return e.wr.Close()
}

// encrypt exactly _one_ block of data
// The nonce is constructed from the salt, block# and block-size.
// This protects the output stream from re-ordering attacks and length
// modification attacks. The encoded length & block number is used as
// additional data in the AEAD construction.
func (e *Encryptor) encrypt(pt []byte, i uint32, eof bool) error {

	ptlen := uint32(len(pt))
	if eof {
		ptlen |= _EOF
	}

	ad, ct := e.buf[:4], e.buf[4:]

	// always tag the length of each chunk
	enc32(ad, ptlen)

	ct = e.ae.Seal(ct[:0], e.nonce, pt, ad)

	incrNonce(e.nonce)

	n := len(ct) + len(ad)
	err := fullwrite(e.buf[:n], e.wr)
	if err != nil {
		return fmt.Errorf("encrypt: chunk %d: %w", i, err)
	}

	e.hmac.Write(ad[:])
	e.hmac.Write(pt)

	if eof {
		return e.writeTrailer()
	}
	return nil
}

// Begin the encryption process by writing the header
func (e *Encryptor) start() error {
	varSize := e.Size()

	buffer := make([]byte, _FixedHdrLen+varSize+_Sha3Size)
	fixHdr := buffer[:_FixedHdrLen]
	varHdr := buffer[_FixedHdrLen : _FixedHdrLen+varSize]
	sumHdr := buffer[_FixedHdrLen+varSize:]

	// scrub the encoded header
	//defer clear(buffer)

	// Now assemble the fixed header
	copy(fixHdr[:], []byte(_Magic))
	fixHdr[_MagicLen] = _SigtoolVersion
	enc32(fixHdr[_MagicLen+1:], uint32(varSize))

	// Now marshal the variable portion
	_, err := e.MarshalTo(varHdr[:varSize])
	if err != nil {
		return fmt.Errorf("encrypt: can't marshal header: %w", err)
	}

	h := sha3.New512()
	h.Write(buffer[:_FixedHdrLen+varSize])
	cksum := h.Sum(sumHdr[:0])

	// now make the data encryption keys, nonces etc.
	outbuf := make([]byte, _Sha3Size+_AesKeySize+_AEADNonceSize)

	// we mix the header checksum (and it captures the sigtool version, sender
	// identity, etc.)
	buf := expand(outbuf, e.key, cksum, []byte(_DataKeyExpansion))

	// scrub the buffer used for keys
	//defer clear(buf)

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

	// create the hmac for the chunks
	e.hmac = hmac.New(func() hash.Hash {
		return sha3.New512()
	}, hmackey)

	// and the working buffer for each chunk
	e.buf = make([]byte, 4+e.ChunkSize+uint32(e.ae.Overhead()))

	// Finally write out the header
	err = fullwrite(buffer, e.wr)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	e.started = true

	debug("encrypt: chunksize %d\n\thdr-cksum: %x\n\taes-key: %x\n\tnonce: %x\n\thmac-key: %x\n\n",
		e.ChunkSize, cksum, dkey, e.nonce, hmackey)

	return nil
}

// Write a trailer:
//   - we always write the hmac
//   - if authenticating sender, sign the hmac and put the signature in the trailer
//   - if not authenticating sender, we put random bytes as the signature
func (e *Encryptor) writeTrailer() error {
	var hmac [_Sha3Size]byte
	var tr []byte

	e.hmac.Sum(hmac[:0])

	if err := fullwrite(hmac[:], e.wr); err != nil {
		return fmt.Errorf("encrypt: hmac trailer %w", err)
	}

	if e.auth {
		// We know sender is non null.
		sig, err := e.sender.SignMessage(hmac[:])
		if err != nil {
			return fmt.Errorf("encrypt: trailer: %w", err)
		}
		tr = []byte(sig)
	} else {
		tr = []byte(randSig())
	}

	if err := fullwrite(tr, e.wr); err != nil {
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

	rd io.Reader
	wr io.WriteCloser

	buf   []byte
	nonce []byte // nonce for the data decrypting cipher

	hdrsum []byte // cached header checksum
	auth   bool   // flag set to true if sender signed the key
	eof    bool
}

// NewDecryptor begins the decryption of recipient 'sk' using the public key of
// the sender 'senderPk' - by reading encrypted stream 'rd' and writing decrypted
// content to 'wr'.
func NewDecryptor(sk *PrivateKey, senderPk *PublicKey, rd io.Reader, wr io.WriteCloser) (*Decryptor, error) {
	var b [_FixedHdrLen]byte

	_, err := io.ReadFull(rd, b[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt: header: %w", err)
	}

	if bytes.Compare(b[:_MagicLen], []byte(_Magic)) != 0 {
		return nil, ErrNotSigTool
	}

	// Version check
	if b[_MagicLen] != _SigtoolVersion {
		return nil, fmt.Errorf("decrypt: Unsupported version %d; this tool only supports v%d",
			b[_MagicLen], _SigtoolVersion)
	}

	_, varSize := dec32[uint32](b[_MagicLen+1:])

	// sanity check on variable segment length
	if varSize > 1048576 {
		return nil, ErrHeaderTooBig
	}
	if varSize < 32 {
		return nil, ErrHeaderTooSmall
	}

	// SHA3 is the trailer part of the file-header
	varBuf := make([]byte, varSize+_Sha3Size)

	// Now read the variable sized header
	_, err = io.ReadFull(rd, varBuf)
	if err != nil {
		return nil, fmt.Errorf("decrypt: var header: %w", err)
	}

	// The checksum in the header
	verify := varBuf[varSize:]

	// the checksum we calculated
	var csum [_Sha3Size]byte

	h := sha3.New512()
	h.Write(b[:])
	h.Write(varBuf[:varSize])
	cksum := h.Sum(csum[:0])

	if subtle.ConstantTimeCompare(verify, cksum) == 0 {
		return nil, ErrBadHeader
	}

	d := &Decryptor{
		sender: senderPk,
		rd:     rd,
		wr:     wr,
		hdrsum: cksum,
	}

	err = d.Unmarshal(varBuf[:varSize])
	if err != nil {
		return nil, fmt.Errorf("decrypt: header decode: %w", err)
	}

	if d.ChunkSize == 0 || d.ChunkSize >= _maxChunkSize {
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

		key, err := d.unwrapKey(w, sk)
		if err != nil {
			return nil, fmt.Errorf("decrypt: can't unwrap key %d: %w", i, err)
		}

		// We found a matching recipient key
		if key != nil {
			return d.start(key)
		}
	}

	return nil, ErrBadKey
}

// AuthenticatedSender returns true if the sender authenticated themselves
// (the data-encryption key is signed).
func (d *Decryptor) AuthenticatedSender() bool {
	return d.auth
}

// Decrypt starts the decryption by reading from the reader and writing to the writer.
func (d *Decryptor) Decrypt() error {
	if d.ae == nil {
		return ErrNoKey
	}

	if d.eof {
		return io.EOF
	}

	var i uint32
	for i = 0; ; i++ {
		eof, err := d.decrypt(i)
		if err != nil {
			return err
		}

		if eof {
			break
		}
	}

	return d.wr.Close()
}

// Decrypt exactly one chunk of data
func (d *Decryptor) decrypt(i uint32) (bool, error) {
	var ad [4]byte

	n, err := io.ReadFull(d.rd, ad[:])
	if err != nil {
		return false, fmt.Errorf("decrypt: read chunk %d: %w", i, err)
	}

	ovh := d.ae.Overhead()
	_, ptlen := dec32[uint32](ad[:])

	eof := (ptlen & _EOF) > 0
	ptlen &= (_EOF - 1)

	switch {
	case ptlen > d.ChunkSize:
		return false, fmt.Errorf("decrypt: chunk %d: too large %d", i, ptlen)

	case ptlen == 0:
		if eof {
			return true, nil
		}
		return false, fmt.Errorf("decrypt: chunk %d: empty chunk without EOF", i)
	}

	n, err = io.ReadFull(d.rd, d.buf[:int(ptlen)+ovh])
	if err != nil {
		return false, fmt.Errorf("decrypt: read chunk %d: %w", i, err)
	}

	ct := d.buf[:n]
	pt, err := d.ae.Open(ct[:0], d.nonce, ct, ad[:])
	if err != nil {
		return false, fmt.Errorf("decrypt: chunk %d: %w", i, err)
	}

	if len(pt) != int(ptlen) {
		return false, fmt.Errorf("decrypt: chunk %d: unseal exp %d, saw %d", i, ptlen, len(pt))
	}

	incrNonce(d.nonce)

	d.hmac.Write(ad[:])
	d.hmac.Write(pt)
	d.eof = eof

	if len(pt) > 0 {
		err = fullwrite(pt, d.wr)
		if err != nil {
			return false, fmt.Errorf("decrypt: write chunk %d: %w", i, err)
		}
	}

	if eof {
		return true, d.processTrailer()
	}

	return eof, nil
}

// Setup the decryption keys and prepare to decrypt stream
func (d *Decryptor) start(key []byte) (*Decryptor, error) {
	if err := d.verifySender(key, d.sender); err != nil {
		return nil, fmt.Errorf("decrypt: verify sender: %w", err)
	}

	outbuf := make([]byte, _Sha3Size+_AesKeySize+_AEADNonceSize)

	buf := expand(outbuf, key, d.hdrsum, []byte(_DataKeyExpansion))

	var dkey, hmackey []byte

	d.nonce, buf = buf[:_AEADNonceSize], buf[_AEADNonceSize:]
	dkey, buf = buf[:_AesKeySize], buf[_AesKeySize:]
	hmackey = buf

	d.hmac = hmac.New(func() hash.Hash {
		return sha3.New512()
	}, hmackey)

	aes, err := aes.NewCipher(dkey)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	d.ae, err = cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	d.buf = make([]byte, int(d.ChunkSize)+d.ae.Overhead())

	debug("decrypt: chunksize %d\n\thdr-cksum: %x\n\taes-key: %x\n\tnonce: %x\n\thmac-key: %x\n\n",
		d.ChunkSize, d.hdrsum, dkey, d.nonce, hmackey)

	return d, nil
}

func (d *Decryptor) processTrailer() error {
	var hmac [_Sha3Size]byte

	// first read the hmac
	_, err := io.ReadFull(d.rd, hmac[:])
	if err != nil {
		return fmt.Errorf("decrypt: premature EOF while reading hmac trailer: %w", err)
	}

	cksum := d.hmac.Sum(nil)
	if subtle.ConstantTimeCompare(hmac[:], cksum) == 0 {
		return ErrBadTrailer
	}

	sigbuf := make([]byte, sigLen())

	// Now read the sig
	_, err = io.ReadFull(d.rd, sigbuf)
	if err != nil {
		return fmt.Errorf("decrypt: premature EOF while reading trailer: %w", err)
	}

	if d.auth {
		ok, err := d.sender.VerifyMessage(cksum, string(sigbuf))
		if err != nil {
			return fmt.Errorf("decrypt: trailer: %w", err)
		}

		if !ok {
			return fmt.Errorf("decrypt: trailer: %w", ErrBadTrailer)
		}
	}

	return nil
}

// optionally sign the checksum and encrypt everything
func (e *Encryptor) addSenderSig(sk *PrivateKey) error {
	var auth bool
	var sig string

	if e.sender != nil {
		var csum [_Sha3Size256]byte
		var err error

		// We capture essential meta-data from the sender; viz:
		//  - Sender tool version
		//  - Sender generated curve25519 PK
		//  - session salt, root key

		h := sha3.New256()
		h.Write([]byte(_Magic))
		h.Write([]byte{_SigtoolVersion})
		h.Write(e.Pk)
		h.Write(e.Salt)
		h.Write(e.key)
		cksum := h.Sum(csum[:0])

		if sig, err = e.sender.SignMessage(cksum); err != nil {
			return fmt.Errorf("wrap: can't sign: %w", err)
		}
		auth = true
	} else {
		sig = nullSig() // empty signature
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

	outbuf := make([]byte, len(sig)+ae.Overhead())
	buf = ae.Seal(outbuf[:0], nonce, []byte(sig), nil)

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

	sigbuf := make([]byte, sigLen())
	sig, err := ae.Open(sigbuf[:0], nonce, d.Sender, nil)
	if err != nil {
		return fmt.Errorf("unwrap: can't open sender info: %w", err)
	}

	nullsig := nullSig()

	// Did the sender actually sign anything?
	if subtle.ConstantTimeCompare([]byte(nullsig), sig) == 0 {
		if senderPk == nil {
			return ErrNoSenderPK
		}

		var csum [_Sha3Size256]byte

		h := sha3.New256()
		h.Write([]byte(_Magic))
		h.Write([]byte{_SigtoolVersion})
		h.Write(d.Pk)
		h.Write(d.Salt)
		h.Write(key)
		cksum := h.Sum(csum[:0])

		ok, err := senderPk.VerifyMessage(cksum, string(sig))
		if err != nil {
			return fmt.Errorf("decrypt: verify sender: %w", err)
		}

		if !ok {
			return fmt.Errorf("decrypt: verify sender: %w", ErrBadSender)
		}

		// we set this to indicate that the sender authenticated themselves;
		d.auth = true
	}

	return nil
}

// Wrap data encryption key 'k' with the sender's PK and our ephemeral curve SK
// basically, we do a scalarmult: Ephemeral encryption/decryption SK x receiver PK
func (e *Encryptor) wrapKey(pk *PublicKey) (*pb.WrappedKey, error) {
	rxPK := pk.ToCurve25519()
	sekrit, err := curve25519.X25519(e.encSK, rxPK)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	salt := randBuf(_RxNonceSize)

	out := make([]byte, _AesKeySize+_RxNonceSize)

	// We entangle the sender & receiver PKs when we expand the shared secret
	buf := expand(out[:], sekrit, salt, pk.pk, e.Pk, []byte(_WrapReceiver))

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
		DKey: ae.Seal(ekey[:0], nonce, e.key, pk.pk),
		Salt: salt,
	}

	return w, nil
}

// Unwrap a wrapped key using the receivers Ed25519 secret key 'sk' and
// senders ephemeral PublicKey
func (d *Decryptor) unwrapKey(w *pb.WrappedKey, sk *PrivateKey) ([]byte, error) {
	ourSK := sk.ToCurve25519()
	sekrit, err := curve25519.X25519(ourSK, d.Pk)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}

	pk := sk.PublicKey()
	out := make([]byte, _AesKeySize+_RxNonceSize)
	buf := expand(out[:], sekrit, w.Salt, pk.pk, d.Pk, []byte(_WrapReceiver))

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

	dkey := make([]byte, _AesKeySize) // decrypted data decryption key

	dkey, err = ae.Open(dkey[:0], nonce, w.DKey, pk.pk)
	if err != nil {
		// we indicate incorrect receiver SK by returning a nil key
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
func expand(out []byte, shared, salt []byte, ad ...[]byte) []byte {
	var z [_Sha3Size]byte

	s := sha3.New512()
	for i := range ad {
		s.Write(ad[i])
	}

	s.Sum(z[:0])

	h := hkdf.New(func() hash.Hash {
		return sha3.New512()
	}, shared, salt, z[:])
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

// increment the nonce starting from MSB
func incrNonce(nonce []byte) []byte {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i] += 1
		if nonce[i] != 0 {
			break
		}
	}
	return nonce
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
