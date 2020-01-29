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
// recipients, their wrapped keys etc. This is encoded as
// a protobuf message. This protobuf encoded message immediately
// follows the fixed length header.
//
// The input data is broken up into "chunks"; each no larger than
// maxChunkSize. The default block size is "chunkSize". Each block
// is AEAD encrypted:
//   AEAD nonce = SHA256(header.salt || block# || block-size)
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
	"math/big"
)

// Encryption chunk size = 4MB
const (
	chunkSize    uint32 = 4 * 1048576
	maxChunkSize uint32 = 16 * 1048576
	_EOF         uint32 = 1 << 31

	_Magic        = "SigTool"
	_MagicLen     = len(_Magic)
	_AEADNonceLen = 32
	_FixedHdrLen  = _MagicLen + 1 + 4
)

// Encryptor holds the encryption context
type Encryptor struct {
	Header
	key [32]byte // file encryption key

	ae      cipher.AEAD
	sender  *PrivateKey
	started bool

	buf []byte
}

// Create a new Encryption context and use the optional private key 'sk' for
// signing any recipient keys. If 'sk' is nil, then ephmeral Curve25519 keys
// are generated and used with recipient's public key.
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

	e := &Encryptor{
		Header: Header{
			ChunkSize: blksz,
			Salt:      make([]byte, _AEADNonceLen),
		},

		sender: sk,
	}

	randread(e.key[:])
	randread(e.Salt)

	aes, err := aes.NewCipher(e.key[:])
	if err != nil {
		return nil, fmt.Errorf("encrypt: %s", err)
	}

	e.ae, err = cipher.NewGCMWithNonceSize(aes, _AEADNonceLen)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %s", err)
	}

	e.buf = make([]byte, blksz+4+uint32(e.ae.Overhead()))
	return e, nil
}

// Add a new recipient to this encryption context.
func (e *Encryptor) AddRecipient(pk *PublicKey) error {
	if e.started {
		return fmt.Errorf("encrypt: can't add new recipient after encryption has started")
	}

	var w *WrappedKey
	var err error

	if e.sender != nil {
		w, err = e.sender.WrapKey(pk, e.key[:])
	} else {
		w, err = pk.WrapKeyEphemeral(e.key[:])
	}
	if err != nil {
		return err
	}

	e.Keys = append(e.Keys, w)
	return nil
}

// Encrypt the input stream 'rd' and write encrypted stream to 'wr'
func (e *Encryptor) Encrypt(rd io.Reader, wr io.Writer) error {
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
		eof = err == io.EOF || err == io.ErrClosedPipe || err == io.ErrUnexpectedEOF
		if n >= 0 {
			err = e.encrypt(buf[:n], wr, i, eof)
			if err != nil {
				return err
			}

			i++
			continue
		}

		if err != nil && err != io.EOF && err != io.ErrClosedPipe {
			return fmt.Errorf("encrypt: I/O read error: %s", err)
		}
	}
	return nil
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
	fixHdr[_MagicLen] = 1 // version #
	binary.BigEndian.PutUint32(fixHdr[_MagicLen+1:], uint32(varSize))

	// Now marshal the variable portion
	_, err := e.MarshalToSizedBuffer(varHdr[:varSize])
	if err != nil {
		return fmt.Errorf("encrypt: can't marshal header: %s", err)
	}

	// Now calculate checksum of everything
	h := sha256.New()
	h.Write(buffer[:_FixedHdrLen+varSize])
	h.Sum(sumHdr[:0])

	// Finally write it out
	err = fullwrite(buffer, wr)
	if err != nil {
		return fmt.Errorf("encrypt: %s", err)
	}

	e.started = true
	return nil
}

// Write _all_ bytes of buffer 'buf'
func fullwrite(buf []byte, wr io.Writer) error {
	n := len(buf)

	for n > 0 {
		m, err := wr.Write(buf)
		if err != nil {
			return fmt.Errorf("I/O error: %s", err)
		}

		n -= m
		buf = buf[m:]
	}
	return nil
}

// encrypt exactly _one_ block of data
// The nonce for the block is: sha256(salt || chunkLen || block#)
// This protects the output stream from re-ordering attacks and length
// modification attacks. The encoded length & block number is used as
// additional data in the AEAD construction.
func (e *Encryptor) encrypt(buf []byte, wr io.Writer, i uint32, eof bool) error {
	var b [8]byte
	var noncebuf [32]byte
	var z uint32 = uint32(len(buf))

	// mark last block
	if eof {
		z |= _EOF
	}

	binary.BigEndian.PutUint32(b[:4], z)
	binary.BigEndian.PutUint32(b[4:], i)

	h := sha256.New()
	h.Write(e.Salt)
	h.Write(b[:])
	nonce := h.Sum(noncebuf[:0])

	copy(e.buf[:4], b[:4])
	cbuf := e.buf[4:]
	c := e.ae.Seal(cbuf[:0], nonce, buf, b[:])

	// total number of bytes written
	n := len(c) + 4
	err := fullwrite(e.buf[:n], wr)
	if err != nil {
		return fmt.Errorf("encrypt: %s", err)
	}
	return nil
}

// Decryptor holds the decryption context
type Decryptor struct {
	Header

	ae  cipher.AEAD
	rd  io.Reader
	buf []byte

	// Decrypted key
	key []byte
	eof bool
}

// Create a new decryption context and if 'pk' is given, check that it matches
// the sender
func NewDecryptor(rd io.Reader) (*Decryptor, error) {
	var b [_FixedHdrLen]byte

	_, err := io.ReadFull(rd, b[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt: err while reading header: %s", err)
	}

	if bytes.Compare(b[:_MagicLen], []byte(_Magic)) != 0 {
		return nil, fmt.Errorf("decrypt: Not a sigtool encrypted file?")
	}

	if b[_MagicLen] != 1 {
		return nil, fmt.Errorf("decrypt: Unsupported version %d", b[_MagicLen])
	}

	varSize := binary.BigEndian.Uint32(b[_MagicLen+1:])

	// sanity check on variable segment length
	if varSize > 1048576 {
		return nil, fmt.Errorf("decrypt: header too large (max 1048576)")
	}
	if varSize < 32 {
		return nil, fmt.Errorf("decrypt: header too small (min 32)")
	}

	// SHA256 is the trailer part of the file-header
	varBuf := make([]byte, varSize+sha256.Size)

	_, err = io.ReadFull(rd, varBuf)
	if err != nil {
		return nil, fmt.Errorf("decrypt: err while reading header: %s", err)
	}

	verify := varBuf[varSize:]

	h := sha256.New()
	h.Write(b[:])
	h.Write(varBuf[:varSize])
	cksum := h.Sum(nil)

	if subtle.ConstantTimeCompare(verify, cksum[:]) == 0 {
		return nil, fmt.Errorf("decrypt: header corrupted")
	}

	d := &Decryptor{
		rd: rd,
	}

	err = d.Header.Unmarshal(varBuf[:varSize])
	if err != nil {
		return nil, fmt.Errorf("decrypt: decode error: %s", err)
	}

	if d.ChunkSize == 0 || d.ChunkSize >= maxChunkSize {
		return nil, fmt.Errorf("decrypt: invalid chunkSize %d", d.ChunkSize)
	}

	if len(d.Salt) != _AEADNonceLen {
		return nil, fmt.Errorf("decrypt: invalid nonce length %d", len(d.Salt))
	}

	if len(d.Keys) == 0 {
		return nil, fmt.Errorf("decrypt: no wrapped keys")
	}

	// sanity check on the wrapped keys
	for i, w := range d.Keys {
		if len(w.PkHash) != PKHashLength {
			return nil, fmt.Errorf("decrypt: wrapped key %d: invalid PkHash", i)
		}

		if len(w.Pk) != 32 {
			return nil, fmt.Errorf("decrypt: wrapped key %d: invalid Curve25519 PK", i)
		}

		// XXX Default AES-256-GCM Nonce size is 12
		if len(w.Nonce) != 12 {
			return nil, fmt.Errorf("decrypt: wrapped key %d: invalid Nonce", i)
		}

		if len(w.Key) == 0 {
			return nil, fmt.Errorf("decrypt: wrapped key %d: missing encrypted key", i)
		}

	}

	return d, nil
}

// Use Private Key 'sk' to decrypt the encrypted keys in the header and optionally validate
// the sender
func (d *Decryptor) SetPrivateKey(sk *PrivateKey, senderPk *PublicKey) error {
	var err error

	pkh := sk.PublicKey().Hash()
	for i, w := range d.Keys {
		if subtle.ConstantTimeCompare(pkh, w.PkHash) == 1 {
			d.key, err = w.UnwrapKey(sk, senderPk)
			if err != nil {
				return fmt.Errorf("decrypt: can't unwrap key %d: %s", i, err)
			}
			goto havekey
		}
	}

	return fmt.Errorf("decrypt: Can't find any public key to match the given private key")

havekey:
	aes, err := aes.NewCipher(d.key)
	if err != nil {
		return fmt.Errorf("decrypt: %s", err)
	}

	d.ae, err = cipher.NewGCMWithNonceSize(aes, _AEADNonceLen)
	if err != nil {
		return fmt.Errorf("decrypt: %s", err)
	}
	d.buf = make([]byte, int(d.ChunkSize)+d.ae.Overhead())
	return nil
}

// Return a list of Wrapped keys in the encrypted file header
func (d *Decryptor) WrappedKeys() []*WrappedKey {
	return d.Keys
}

// Decrypt the file and write to 'wr'
func (d *Decryptor) Decrypt(wr io.Writer) error {
	if d.key == nil {
		return fmt.Errorf("decrypt: wrapped-key not decrypted (missing SetPrivateKey()?")
	}

	if d.eof {
		return fmt.Errorf("decrypt: input stream has reached EOF")
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
				return fmt.Errorf("decrypt: %s", err)
			}
		}

		if eof {
			d.eof = true
			return nil
		}

	}
	return nil
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

	case m < ovh:
		return nil, false, fmt.Errorf("decrypt: chunksize is too small (%d)", m)

	default:
	}

	binary.BigEndian.PutUint32(b[4:], i)
	h := sha256.New()
	h.Write(d.Salt)
	h.Write(b[:])
	nonce := h.Sum(nonceb[:0])

	z := m + ovh
	n, err = io.ReadFull(d.rd, d.buf[:z])
	if err != nil {
		return nil, false, fmt.Errorf("decrypt: premature EOF while reading block %d: %s", i, err)
	}

	p, err = d.ae.Open(d.buf[:0], nonce, d.buf[:n], b[:])
	if err != nil {
		return nil, false, fmt.Errorf("decrypt: can't decrypt chunk %d: %s", i, err)
	}

	return p[:m], eof, nil
}

// Wrap a shared key with the recipient's public key 'pk' by generating an ephemeral
// Curve25519 keypair. This function does not identify the sender (non-repudiation).
func (pk *PublicKey) WrapKeyEphemeral(key []byte) (*WrappedKey, error) {
	var newSK [32]byte

	randread(newSK[:])
	clamp(newSK[:])

	return wrapKey(pk, key, newSK[:])
}

// given a file-encryption-key, wrap it in the identity of the recipient 'pk' using our
// secret key. This function identifies the sender.
func (sk *PrivateKey) WrapKey(pk *PublicKey, key []byte) (*WrappedKey, error) {
	return wrapKey(pk, key, sk.toCurve25519SK())
}

func wrapKey(pk *PublicKey, k []byte, ourSK []byte) (*WrappedKey, error) {
	curvePK, err := curve25519.X25519(ourSK, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	shared, err := curve25519.X25519(ourSK, pk.toCurve25519PK())
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	ek, nonce, err := aeadSeal(k, shared, pk.Pk)
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	return &WrappedKey{
		PkHash: pk.hash,
		Pk:     curvePK,
		Nonce:  nonce,
		Key:    ek,
	}, nil
}

// Unwrap a wrapped key using the private key 'sk'
func (w *WrappedKey) UnwrapKey(sk *PrivateKey, senderPk *PublicKey) ([]byte, error) {
	ourSK := sk.toCurve25519SK()
	shared, err := curve25519.X25519(ourSK, w.Pk)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %s", err)
	}

	if senderPk != nil {
		shared2, err := curve25519.X25519(ourSK, senderPk.toCurve25519PK())
		if err != nil {
			return nil, fmt.Errorf("unwrap: %s", err)
		}

		if subtle.ConstantTimeCompare(shared2, shared) != 1 {
			return nil, fmt.Errorf("unwrap: sender validation failed")
		}
	}

	pk := sk.PublicKey()
	key, err := aeadOpen(w.Key, w.Nonce, shared[:], pk.Pk)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Convert an Ed25519 Private Key to Curve25519 Private key
func (sk *PrivateKey) toCurve25519SK() []byte {
	if sk.ck == nil {
		var ek [64]byte

		h := sha512.New()
		h.Write(sk.Sk[:32])
		h.Sum(ek[:0])

		sk.ck = clamp(ek[:32])
	}

	return sk.ck
}

// from github.com/FiloSottile/age
var curve25519P, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

// Convert an Ed25519 Public Key to Curve25519 public key
// from github.com/FiloSottile/age
func (pk *PublicKey) toCurve25519PK() []byte {
	if pk.ck != nil {
		return pk.ck
	}

	// ed25519.PublicKey is a little endian representation of the y-coordinate,
	// with the most significant bit set based on the sign of the x-ccordinate.
	bigEndianY := make([]byte, ed25519.PublicKeySize)
	for i, b := range pk.Pk {
		bigEndianY[ed25519.PublicKeySize-i-1] = b
	}
	bigEndianY[0] &= 0b0111_1111

	// The Montgomery u-coordinate is derived through the bilinear map
	//
	//     u = (1 + y) / (1 - y)
	//
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption.
	y := new(big.Int).SetBytes(bigEndianY)
	denom := big.NewInt(1)
	denom.ModInverse(denom.Sub(denom, y), curve25519P) // 1 / (1 - y)
	u := y.Mul(y.Add(y, big.NewInt(1)), denom)
	u.Mod(u, curve25519P)

	out := make([]byte, 32)
	uBytes := u.Bytes()
	n := len(uBytes)
	for i, b := range uBytes {
		out[n-i-1] = b
	}

	pk.ck = out
	return out
}

// generate a KEK from a shared DH key and a Pub Key
func expand(shared, pk []byte) ([]byte, error) {
	kek := make([]byte, 32)
	h := hkdf.New(sha512.New, shared, pk, nil)
	_, err := io.ReadFull(h, kek)
	return kek, err
}

// seal the data via AEAD after suitably expanding 'shared'
func aeadSeal(data, shared, pk []byte) ([]byte, []byte, error) {
	kek, err := expand(shared[:], pk)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap: %s", err)
	}

	aes, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap: %s", err)
	}

	noncesize := ae.NonceSize()
	tagsize := ae.Overhead()

	buf := make([]byte, tagsize+len(kek))
	nonce := make([]byte, noncesize)

	randread(nonce)

	out := ae.Seal(buf[:0], nonce, data, nil)
	return out, nonce, nil
}

func aeadOpen(data, nonce, shared, pk []byte) ([]byte, error) {
	// hkdf or HMAC-sha-256
	kek, err := expand(shared, pk)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %s", err)
	}
	aes, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %s", err)
	}

	want := 32 + ae.Overhead()
	if len(data) != want {
		return nil, fmt.Errorf("unwrap: incorrect decrypt bytes (need %d, saw %d)", want, len(data))
	}

	c, err := ae.Open(data[:0], nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %s", err)
	}

	return c, nil
}

func clamp(k []byte) []byte {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}
