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
//    - Shasum:  32 bytes (SHA256 of full header)
//
// The variable length segment consists of one or more
// recipients, each with their wrapped keys. This is encoded as
// a protobuf message. This protobuf encoded message immediately
// follows the fixed length header.
//
// The input data is encrypted with an expanded random 32-byte key:
//    - Prefix_string = "Encrypt Nonce"
//    - datakey = SHA256(Prefix_string || header_checksum || random_key)
//    - The header checksum is mixed in the above process to ensure we
//      catch any malicious modification of the header.
//
// The input data is broken up into "chunks"; each no larger than
// maxChunkSize. The default block size is "chunkSize". Each block
// is AEAD encrypted:
//   AEAD nonce = header.salt || block# || block-size
//
// The encrypted block (includes the AEAD tag) length is written
// as a big-endian 4-byte prefix. The high-order bit of this length
// field is set for the last-block (denoting EOF).
//
// The encrypted blocks use an opinionated nonce length of 32 (_AEADNonceLen).

package sign

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"

	"github.com/opencoff/sigtool/internal/pb"
)

// Encryption chunk size = 4MB
const (
	chunkSize    uint32 = 4 * 1048576
	maxChunkSize uint32 = 1 << 30
	_EOF         uint32 = 1 << 31

	_Magic          = "SigTool"
	_MagicLen       = len(_Magic)
	_SigtoolVersion = 2
	_AEADNonceLen   = 32
	_FixedHdrLen    = _MagicLen + 1 + 4

	_WrapReceiverNonce = "Receiver Key Nonce"
	_WrapSenderNonce   = "Sender Sig Nonce"
	_EncryptNonce      = "Encrypt Nonce"
)

// Encryptor holds the encryption context
type Encryptor struct {
	pb.Header
	key []byte // file encryption key

	ae cipher.AEAD

	// ephemeral key
	encSK []byte

	started bool

	hdrsum []byte
	buf    []byte
	stream bool
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

	key := make([]byte, 32)
	salt := make([]byte, _AEADNonceLen)

	randRead(key)
	randRead(salt)

	wSig, err := wrapSenderSig(sk, key, salt)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	e := &Encryptor{
		Header: pb.Header{
			ChunkSize:  blksz,
			Salt:       salt,
			Pk:         epk,
			SenderSign: wSig,
		},

		key:   key,
		encSK: esk,
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
	varHdr := buffer[_FixedHdrLen:]
	sumHdr := varHdr[varSize:]

	// Now assemble the fixed header
	copy(fixHdr[:], []byte(_Magic))
	fixHdr[_MagicLen] = _SigtoolVersion
	binary.BigEndian.PutUint32(fixHdr[_MagicLen+1:], uint32(varSize))

	// Now marshal the variable portion
	_, err := e.MarshalTo(varHdr[:varSize])
	if err != nil {
		return fmt.Errorf("encrypt: can't marshal header: %w", err)
	}

	// Now calculate checksum of everything
	h := sha256.New()
	h.Write(buffer[:_FixedHdrLen+varSize])
	h.Sum(sumHdr[:0])

	// Finally write it out
	err = fullwrite(buffer, wr)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// we mix the header checksum to create the encryption key
	h = sha256.New()
	h.Write([]byte(_EncryptNonce))
	h.Write(e.key)
	h.Write(sumHdr)
	key := h.Sum(nil)

	aes, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	ae, err := cipher.NewGCMWithNonceSize(aes, _AEADNonceLen)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	e.buf = make([]byte, e.ChunkSize+4+uint32(ae.Overhead()))
	e.ae = ae

	e.started = true
	return nil
}

// encrypt exactly _one_ block of data
// The nonce is constructed from the salt, block# and block-size.
// This protects the output stream from re-ordering attacks and length
// modification attacks. The encoded length & block number is used as
// additional data in the AEAD construction.
func (e *Encryptor) encrypt(buf []byte, wr io.Writer, i uint32, eof bool) error {
	var z uint32 = uint32(len(buf))
	var nbuf [_AEADNonceLen]byte

	// mark last block
	if eof {
		z |= _EOF
	}

	b := e.buf[:8]
	binary.BigEndian.PutUint32(b[:4], z)
	binary.BigEndian.PutUint32(b[4:], i)

	nonce := makeNonceV2(nbuf[:], e.Salt, b)

	cbuf := e.buf[4:]
	c := e.ae.Seal(cbuf[:0], nonce, buf, b[:])

	// total number of bytes written
	n := len(c) + 4
	err := fullwrite(e.buf[:n], wr)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return nil
}

// Decryptor holds the decryption context
type Decryptor struct {
	pb.Header

	ae     cipher.AEAD
	rd     io.Reader
	buf    []byte
	hdrsum []byte

	// flag set to true if sender signed the key
	auth bool

	// Decrypted key
	key    []byte
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

	verify := varBuf[varSize:]

	h := sha256.New()
	h.Write(b[:])
	h.Write(varBuf[:varSize])
	cksum := h.Sum(nil)

	if subtle.ConstantTimeCompare(verify, cksum[:]) == 0 {
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

	if len(d.Salt) != _AEADNonceLen {
		return nil, fmt.Errorf("decrypt: invalid nonce length %d", len(d.Salt))
	}

	if len(d.Keys) == 0 {
		return nil, ErrNoWrappedKeys
	}

	// sanity check on the wrapped keys
	for i, w := range d.Keys {
		if len(w.DKey) <= 32 {
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
			goto havekey
		}
	}

	return ErrBadKey

havekey:
	if err := d.verifySender(key, sk, senderPk); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	d.key = key

	// we mix the header checksum into the key
	h := sha256.New()
	h.Write([]byte(_EncryptNonce))
	h.Write(d.key)
	h.Write(d.hdrsum)
	key = h.Sum(nil)

	aes, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	d.ae, err = cipher.NewGCMWithNonceSize(aes, _AEADNonceLen)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
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
	var b [8]byte
	var nonceb [32]byte
	var ovh uint32 = uint32(d.ae.Overhead())
	var p []byte

	n, err := io.ReadFull(d.rd, b[:4])
	if err != nil || n == 0 {
		return nil, false, fmt.Errorf("decrypt: premature EOF while reading header block %d", i)
	}

	m := binary.BigEndian.Uint32(b[:4])
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
		return p, eof, nil

	default:
	}

	binary.BigEndian.PutUint32(b[4:], i)
	nonce := makeNonceV2(nonceb[:], d.Salt, b[:])

	z := m + ovh
	n, err = io.ReadFull(d.rd, d.buf[:z])
	if err != nil {
		return nil, false, fmt.Errorf("decrypt: premature EOF while reading block %d: %w", i, err)
	}

	p, err = d.ae.Open(d.buf[:0], nonce, d.buf[:n], b[:])
	if err != nil {
		return nil, false, fmt.Errorf("decrypt: can't decrypt chunk %d: %w", i, err)
	}

	return p[:m], eof, nil
}

// Wrap sender's signature of the encryption key
// if sender has provided their identity to authenticate, we sign the data-enc key
// and encrypt the signature. At no point will we send the sender's identity.
func wrapSenderSig(sk *PrivateKey, key, salt []byte) ([]byte, error) {
	var zero [ed25519.SignatureSize]byte
	var sig []byte

	switch {
	case sk == nil:
		sig = zero[:]

	default:
		xsig, err := sk.SignMessage(key, "")
		if err != nil {
			return nil, fmt.Errorf("wrap: can't sign: %w", err)
		}

		sig = xsig.Sig
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	tagsize := ae.Overhead()
	nonceSize := ae.NonceSize()

	nonce := sha256Slices([]byte(_WrapSenderNonce), salt)[:nonceSize]
	esig := make([]byte, tagsize+len(sig))

	return ae.Seal(esig[:0], nonce, sig, nil), nil
}

// unwrap sender's signature using 'key' and extract the signature
// Optionally, verify the signature using the sender's PK (if provided).
func (d *Decryptor) verifySender(key []byte, sk *PrivateKey, senderPK *PublicKey) error {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}

	nonceSize := ae.NonceSize()
	nonce := sha256Slices([]byte(_WrapSenderNonce), d.Salt)[:nonceSize]
	sig := make([]byte, ed25519.SignatureSize)
	sig, err = ae.Open(sig[:0], nonce, d.SenderSign, nil)
	if err != nil {
		return fmt.Errorf("unwrap: can't open sender info: %w", err)
	}

	var zero [ed25519.SignatureSize]byte

	// Did the sender actually sign anything?
	if subtle.ConstantTimeCompare(zero[:], sig) == 0 {
		// we set this to indicate that the sender authenticated themselves;
		d.auth = true

		if senderPK != nil {
			ss := &Signature{
				Sig: sig,
			}

			if ok := senderPK.VerifyMessage(key, ss); !ok {
				return fmt.Errorf("unwrap: sender verification failed")
			}
		}
	}
	return nil
}

// Wrap data encryption key 'k' with the sender's PK and our ephemeral curve SK
//  basically, we do a scalarmult: Ephemeral encryption/decryption SK x receiver PK
func (e *Encryptor) wrapKey(pk *PublicKey) (*pb.WrappedKey, error) {
	rxPK := pk.toCurve25519PK()
	dkek, err := curve25519.X25519(e.encSK, rxPK)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	aes, err := aes.NewCipher(dkek)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}

	tagsize := ae.Overhead()
	nonceSize := ae.NonceSize()

	nonceR := sha256Slices([]byte(_WrapReceiverNonce), e.Salt)[:nonceSize]
	ekey := make([]byte, tagsize+len(e.key))

	w := &pb.WrappedKey{
		DKey: ae.Seal(ekey[:0], nonceR, e.key, pk.Pk),
	}

	return w, nil
}

// Unwrap a wrapped key using the receivers Ed25519 secret key 'sk' and
// senders ephemeral PublicKey
func (d *Decryptor) unwrapKey(w *pb.WrappedKey, sk *PrivateKey) ([]byte, error) {
	ourSK := sk.toCurve25519SK()
	dkek, err := curve25519.X25519(ourSK, d.Pk)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}

	aes, err := aes.NewCipher(dkek)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}

	// 32 == AES-256 key size
	want := 32 + ae.Overhead()
	if len(w.DKey) != want {
		return nil, fmt.Errorf("unwrap: incorrect decrypt bytes (need %d, saw %d)", want, len(w.DKey))
	}

	nonceSize := ae.NonceSize()

	nonceR := sha256Slices([]byte(_WrapReceiverNonce), d.Salt)[:nonceSize]
	pk := sk.PublicKey()

	dkey := make([]byte, 32) // decrypted data decryption key

	// we indicate incorrect receiver SK by returning a nil key
	dkey, err = ae.Open(dkey[:0], nonceR, w.DKey, pk.Pk)
	if err != nil {
		return nil, nil
	}

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

// make aead nonce from salt, chunk-size and block#
// First 8 bytes are chunk-size and nonce (in 'ad')
func makeNonceV2(dest []byte, salt []byte, ad []byte) []byte {
	n := len(ad)
	copy(dest, ad)
	copy(dest[n:], salt)
	return dest
}

// make aead nonce from salt, chunk-size and block# for v1
// This is here for historical documentation purposes
func makeNonceV1(dest []byte, salt []byte, ad []byte) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(ad)
	return h.Sum(dest[:0])
}

// generate a KEK from a shared DH key and a Pub Key
func expand(shared, pk []byte) ([]byte, error) {
	kek := make([]byte, 32)
	h := hkdf.New(sha512.New, shared, pk, nil)
	_, err := io.ReadFull(h, kek)
	return kek, err
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

// EOF
