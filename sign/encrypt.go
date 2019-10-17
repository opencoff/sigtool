// cipher.go -- Ed25519 based encrypt/decrypt
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

package sign

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"bytes"
	"encoding/binary"
)


// Encryption chunk size = 4MB
const chunkSize int = 4 * 1048576

const _Magic = "SigTool"
const _MagicLen = len(_Magic)
const _AEADNonceLen = 32


// Encryptor holds the encryption context
type Encryptor struct {
	Header
	key [32]byte  // file encryption key

	ae  cipher.AEAD
	sender *PrivateKey
	started bool

	buf []byte
}

// Create a new Encryption context and use the optional private key 'sk' for 
// signing any recipient keys. If 'sk' is nil, then ephmeral Curve25519 keys
// are generated and used with recipient's public key.
func NewEncryptor(sk *PrivateKey) (*Encryptor, error) {

	e := &Encryptor{
		Header: Header{
			ChunkSize: uint32(chunkSize),
			Salt:	   make([]byte, _AEADNonceLen),
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

	e.buf = make([]byte, chunkSize + 4 + e.ae.Overhead())
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


// Begin the encryption process by writing the header
func (e *Encryptor) start(wr io.Writer) error {
	msize := e.Size()

	// marshal the header and recipients
	hdrlen := _MagicLen + 1 + 4 + sha256.Size

	buf := make([]byte, hdrlen + msize)
	hdrbuf := buf[hdrlen:]

	copy(buf[:], []byte(_Magic))

	buf[_MagicLen] = 1  // file version#

	// The fixed header is the magic _and _ the length of the variable segment.
	// So, we capture the length of the variable portion first.
	binary.BigEndian.PutUint32(buf[_MagicLen + 1:], uint32(sha256.Size + msize))

	// Now marshal the variable portion
	_, err := e.MarshalToSizedBuffer(hdrbuf)
	if err != nil {
		return fmt.Errorf("encrypt: can't marshal header: %s", err)
	}

	// and calculate the header checksum
	cksum := buf[_MagicLen + 1 + 4:]
	h := sha256.New()
	h.Write(hdrbuf)
	h.Sum(cksum[:0])

	// Finally write it out
	err = fullwrite(buf, wr)
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


// Encrypt the input stream 'rd' and write encrypted stream to 'wr'
func (e *Encryptor) Encrypt(rd io.Reader, wr io.Writer) error {
	if !e.started {
		err := e.start(wr)
		if err != nil {
			return err
		}
	}

	buf := make([]byte, e.ChunkSize)
	i := 0

	for {
		n, err := io.ReadAtLeast(rd, buf, int(e.ChunkSize))
		if n == 0 {
			return nil
		}
		if n > 0 {
			err = e.encrypt(buf[:n], wr, i)
			if err != nil {
				return err
			}

			i++
			continue
		}

		if err != nil && err != io.EOF {
			return fmt.Errorf("encrypt: I/O read error: %s", err)
		}
	}
}

// encrypt exactly _one_ block of data
// The nonce for the block is: sha256(salt || chunkLen || block#)
// This protects the output stream from re-ordering attacks and length
// modification attacks. The encoded length & block number is used as
// additional data in the AEAD construction.
func (e *Encryptor) encrypt(buf []byte, wr io.Writer, i int) error {
	var b [8]byte
	var noncebuf [32]byte

	binary.BigEndian.PutUint32(b[:4], uint32(e.ae.Overhead() + len(buf)))
	binary.BigEndian.PutUint32(b[4:], uint32(i))

	h := sha256.New()
	h.Write(e.Salt)
	h.Write(b[:])
	nonce := h.Sum(noncebuf[:0])

	copy(e.buf[:4], b[:4])
	cbuf := e.buf[4:]
	c := e.ae.Seal(cbuf[:0], nonce, buf, b[:])

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

	ae cipher.AEAD
	rd io.Reader
	buf []byte

	// Decrypted key
	key []byte
}


// Create a new decryption context and if 'pk' is given, check that it matches
// the sender
func NewDecryptor(rd io.Reader, pk *PublicKey) (*Decryptor, error) {
	var  b [12]byte

	_, err := io.ReadFull(rd,  b[:])
	if err != nil {
		return nil, err
	}

	if bytes.Compare(b[:_MagicLen], []byte(_Magic)) != 0 {
		return nil, fmt.Errorf("decrypt: Not a sigtool encrypted file?")
	}

	if b[_MagicLen] != 1 {
		return nil, fmt.Errorf("decrypt: Unsupported version %d", b[_MagicLen])
	}

	hdrlen := binary.BigEndian.Uint32(b[_MagicLen+1:])
	if hdrlen > 65536 {
		return nil, fmt.Errorf("decrypt: header too large (max 65536)")
	}
	if hdrlen < 32 {
		return nil, fmt.Errorf("decrypt: header too small (min 32)")
	}

	hdr := make([]byte, hdrlen)

	_, err = io.ReadFull(rd, hdr)
	if err != nil {
		return nil, err
	}

	verify := hdr[:32]
	hdr = hdr[32:]

	cksum := sha256.Sum256(hdr)
	if subtle.ConstantTimeCompare(verify, cksum[:]) == 0 {
		return nil, fmt.Errorf("decrypt: header corrupted")
	}

	d := &Decryptor{
		rd:  rd,
	}

	err = d.Header.Unmarshal(hdr)
	if err != nil {
		return nil, fmt.Errorf("decrypt: decode error: %s", err)
	}

	if d.ChunkSize == 0 || d.ChunkSize > (16 * 1048576) {
		return nil, fmt.Errorf("decrypt: invalid chunkSize %d", d.ChunkSize)
	}

	if len(d.Salt) != 32 {
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

	d.buf = make([]byte, d.ChunkSize)
	if pk != nil {
		validSender := false
		pkh := pk.Hash()
		for _, w := range d.Keys {
			if subtle.ConstantTimeCompare(pkh, w.PkHash) == 1 {
				validSender = true
			}
		}

		if !validSender {
			return nil, fmt.Errorf("decrypt: Can't find sender's public key in the header")
		}
	}

	return d, nil
}

// Use Private Key 'sk' to decrypt the encrypted keys in the header
func (d *Decryptor) SetPrivateKey(sk *PrivateKey) error {
	var err error

	pkh := sk.PublicKey().Hash()
	for i, w := range d.Keys {
		if subtle.ConstantTimeCompare(pkh, w.PkHash) == 1 {
			d.key, err = w.UnwrapKey(sk)
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

	for i := 0; ; i++ {
		c, err := d.decrypt(i)
		if err != nil {
			return err
		}
		if len(c) == 0 {
			return nil
		}
		
		if len(c) > 0 {
			err = fullwrite(c, wr)
			if err != nil {
				return fmt.Errorf("decrypt: %s", err)
			}
		}
	}
	return nil
}

// Decrypt exactly one chunk of data
func (d *Decryptor) decrypt(i int) ([]byte, error) {
	var b [8]byte
	var nonceb [32]byte

	n, err := io.ReadFull(d.rd, b[:4])
	if n == 0 || err == io.EOF {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("decrypt: can't read chunk %d length: %s", i, err)
	}


	chunklen := int(binary.BigEndian.Uint32(b[:4]))
	binary.BigEndian.PutUint32(b[4:], uint32(i))
	h := sha256.New()
	h.Write(d.Salt)
	h.Write(b[:])
	nonce := h.Sum(nonceb[:0])

	n, err = io.ReadFull(d.rd, d.buf[:chunklen])
	if n == 0 || err == io.EOF {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt: can't read chunk %d: %s", i, err)
	}

	p, err := d.ae.Open(d.buf[:0], nonce, d.buf[:chunklen], b[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt: can't decrypt chunk %d: %s", i, err)
	}

	return p, nil
}

// given a file-encryption-key, wrap it in the identity of the recipient 'pk' using our
// secret key. This function identifies the sender.
func (sk *PrivateKey) WrapKey(pk *PublicKey, key []byte) (*WrappedKey, error) {
	var shared, theirPK, ourSK [32]byte

	copy(ourSK[:], sk.toCurve25519SK())
	copy(theirPK[:], pk.toCurve25519PK())

	curve25519.ScalarMult(&shared, &ourSK, &theirPK)

	return wrapKey(pk, key, theirPK[:], shared[:])

}

// Unwrap a wrapped key using the private key 'sk'
func (w *WrappedKey) UnwrapKey(sk *PrivateKey) ([]byte, error) {
	var shared, theirPK, ourSK [32]byte

	pk := sk.PublicKey()
	copy(ourSK[:], sk.toCurve25519SK())
	copy(theirPK[:], w.Pk)
	curve25519.ScalarMult(&shared, &ourSK, &theirPK)

	key, err := aeadOpen(w.Key, w.Nonce, shared[:], pk.Pk)
	if err != nil {
		return nil, err
	}
	return key, nil
}


// Wrap a shared key with the recipient's public key 'pk' by generating an ephemeral
// Curve25519 keypair. This function does not identify the sender (non-repudiation).
func (pk *PublicKey) WrapKeyEphemeral(key []byte) (*WrappedKey, error) {
	var shared, newSK, newPK, theirPK [32]byte

	randread(newSK[:])

	copy(theirPK[:], pk.toCurve25519PK())
	curve25519.ScalarBaseMult(&newPK, &newSK)
	curve25519.ScalarMult(&shared, &newSK, &theirPK)

	// we throw away newSK after deriving the shared key.
	// The recipient can derive the same key using theirSK and newPK.
	// (newPK will be marshalled and returned by this function)

	return wrapKey(pk, key, newPK[:], shared[:])
}

func wrapKey(pk *PublicKey, k, theirPK, shared []byte) (*WrappedKey, error) {
	ek, nonce, err := aeadSeal(k, shared[:], pk.Pk)
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	return &WrappedKey{
		PkHash: pk.hash,
		Pk:     theirPK,
		Nonce:  nonce,
		Key:    ek,
	}, nil
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

	buf := make([]byte, tagsize + len(kek))
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
