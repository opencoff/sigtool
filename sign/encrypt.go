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
	maxChunkSize uint32 = 16 * 1048576
	_EOF         uint32 = 1 << 31

	_Magic        = "SigTool"
	_MagicLen     = len(_Magic)
	_AEADNonceLen = 32
	_FixedHdrLen  = _MagicLen + 1 + 4
)

// Encryptor holds the encryption context
type Encryptor struct {
	pb.Header
	key []byte // file encryption key

	ae cipher.AEAD

	// sender ephemeral curve 25519 SK
	// the corresponding PK is in Header above
	senderSK []byte

	started bool

	hdrsum []byte
	buf    []byte
	stream bool
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

	csk, cpk, err := newSender()
	if err != nil {
		return nil, fmt.Errorf("encrypt: %s", err)
	}

	key := make([]byte, 32)
	salt := make([]byte, _AEADNonceLen)

	pb.Randread(key)
	pb.Randread(salt)

	// if sender has provided their identity to authenticate, we will use their PK
	senderPK := cpk
	if sk != nil {
		epk := sk.PublicKey()
		senderPK = epk.toCurve25519PK()
	}

	wPk, err := pb.WrapSenderPK(senderPK, key, salt)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %s", err)
	}

	e := &Encryptor{
		Header: pb.Header{
			ChunkSize: blksz,
			Salt:      salt,
			Pk:        cpk,
			SenderPk: &pb.Sender{
				Pk: wPk,
			},
		},

		key:      key,
		senderSK: csk,
	}

	return e, nil
}

// Add a new recipient to this encryption context.
func (e *Encryptor) AddRecipient(pk *PublicKey) error {
	if e.started {
		return fmt.Errorf("encrypt: can't add new recipient after encryption has started")
	}

	w, err := wrapKey(pk, e.key, e.senderSK, e.Salt)
	if err == nil {
		e.Keys = append(e.Keys, w)
	}

	return err
}

// Encrypt the input stream 'rd' and write encrypted stream to 'wr'
func (e *Encryptor) Encrypt(rd io.Reader, wr io.WriteCloser) error {
	if e.stream {
		return fmt.Errorf("encrypt: can't use Encrypt() after using streaming I/O")
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
				return fmt.Errorf("encrypt: I/O read error: %s", err)
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
	fixHdr[_MagicLen] = 1 // version #
	binary.BigEndian.PutUint32(fixHdr[_MagicLen+1:], uint32(varSize))

	// Now marshal the variable portion
	_, err := e.MarshalTo(varHdr[:varSize])
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

	// we mix the header checksum to create the encryption key
	h = sha256.New()
	h.Write([]byte("Encrypt Nonce"))
	h.Write(e.key)
	h.Write(sumHdr)
	key := h.Sum(nil)

	aes, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("encrypt: %s", err)
	}

	ae, err := cipher.NewGCMWithNonceSize(aes, _AEADNonceLen)
	if err != nil {
		return fmt.Errorf("encrypt: %s", err)
	}

	e.buf = make([]byte, e.ChunkSize+4+uint32(ae.Overhead()))
	e.ae = ae

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
	pb.Header

	ae     cipher.AEAD
	rd     io.Reader
	buf    []byte
	hdrsum []byte

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
		rd:     rd,
		hdrsum: cksum,
	}

	err = d.Unmarshal(varBuf[:varSize])
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
		if len(w.Key) <= 32+12 {
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
		key, err = unwrapKey(w.Key, sk, d.Pk, d.Salt)
		if err != nil {
			return fmt.Errorf("decrypt: can't unwrap key %d: %s", i, err)
		}
		if key != nil {
			goto havekey
		}
	}

	return fmt.Errorf("decrypt: wrong key")

havekey:
	if senderPk != nil {
		hpk, err := d.SenderPk.UnwrapPK(key, d.Salt)
		if err != nil {
			return fmt.Errorf("decrypt: can't unwrap sender PK: %s", err)
		}

		cpk := senderPk.toCurve25519PK()
		if subtle.ConstantTimeCompare(cpk, hpk) == 0 {
			return fmt.Errorf("decrypt: sender verification failed")
		}
	}

	// XXX do we need to verify d.Header.Sender.Key vs. d.Header.PK?

	d.key = key

	// we mix the header checksum into the key
	h := sha256.New()
	h.Write([]byte("Encrypt Nonce"))
	h.Write(d.key)
	h.Write(d.hdrsum)
	key = h.Sum(nil)

	aes, err := aes.NewCipher(key)
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

// Wrap data encryption key 'k' with the sender's PK and our ephemeral curve SK
func wrapKey(pk *PublicKey, k, ourSK, salt []byte) (*pb.WrappedKey, error) {
	shared, err := curve25519.X25519(ourSK, pk.toCurve25519PK())
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	aes, err := aes.NewCipher(shared)
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	tagsize := ae.Overhead()

	nonce := pb.MakeNonce([]byte(pb.WrapReceiverNonce), salt)
	buf := make([]byte, tagsize+len(shared))
	out := ae.Seal(buf[:0], nonce[:ae.NonceSize()], k, pk.Pk)
	return &pb.WrappedKey{
		Key: out,
	}, nil
}

// Unwrap a wrapped key using the receivers Ed25519 secret key 'sk' and
// senders ephemeral PublicKey
func unwrapKey(wkey []byte, sk *PrivateKey, curvePK, salt []byte) ([]byte, error) {
	ourSK := sk.toCurve25519SK()
	shared, err := curve25519.X25519(ourSK, curvePK)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %s", err)
	}

	aes, err := aes.NewCipher(shared)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %s", err)
	}

	want := 32 + ae.Overhead()
	if len(wkey) != want {
		return nil, fmt.Errorf("unwrap: incorrect decrypt bytes (need %d, saw %d)", want, len(wkey))
	}

	nonce := pb.MakeNonce([]byte(pb.WrapReceiverNonce), salt)
	pk := sk.PublicKey()
	out := make([]byte, 32)
	c, err := ae.Open(out[:0], nonce[:ae.NonceSize()], wkey, pk.Pk)

	// we indicate incorrect receiver SK by returning a nil key
	if err != nil {
		return nil, nil
	}
	return c, nil
}

// Return a list of Wrapped keys in the encrypted file header
func (d *Decryptor) WrappedKeys() []*pb.WrappedKey {
	return d.Keys
}

// Decrypt the file and write to 'wr'
func (d *Decryptor) Decrypt(wr io.Writer) error {
	if d.key == nil {
		return fmt.Errorf("decrypt: wrapped-key not decrypted (missing SetPrivateKey()?")
	}

	if d.stream {
		return fmt.Errorf("decrypt: can't use Decrypt() after using streaming I/O")
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

// generate a KEK from a shared DH key and a Pub Key
func expand(shared, pk []byte) ([]byte, error) {
	kek := make([]byte, 32)
	h := hkdf.New(sha512.New, shared, pk, nil)
	_, err := io.ReadFull(h, kek)
	return kek, err
}

func newSender() (sk, pk []byte, err error) {
	var csk [32]byte

	pb.Randread(csk[:])
	pb.Clamp(csk[:])
	pk, err = curve25519.X25519(csk[:], curve25519.Basepoint)
	sk = csk[:]
	return
}
