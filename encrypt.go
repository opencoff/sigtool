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

// Implementation Notes for Encryption/Decryption (wire format v5):
//
// Header: has 3 parts
//    - Fixed sized header
//    - Variable sized protobuf encoded header
//    - SHA3-512 sum of both above
//
// Fixed size header:
//    - Magic:   7 bytes ("SigTool")
//    - Version: 1 byte
//    - VLen:    4 bytes (big-endian, length of the protobuf segment)
//
// Variable length segment (protobuf):
//    - chunk_size, master salt, sender's ephemeral curve25519 PK
//    - a list of per-recipient wrapped_key entries
//
// Each wrapped_key entry holds:
//    - d_key: AES-GCM-256 ciphertext of (root_key || capsule_sig), sealed
//      under a KEK derived from DH(ephemeral_SK, recipient_PK). Plaintext is
//      96 bytes (32 + 64); ciphertext is 96 + 16 = 112 bytes. The signature
//      is carried *inside* the AEAD blob — never in plaintext — so an
//      eavesdropper cannot tell from the header whether the file was
//      authenticated by the sender.
//    - salt: per-capsule random salt feeding the KEK HKDF.
//
// Sender authentication:
//    - The sender signs one signature per recipient, over:
//        capsule_hash = SHA3-512(header_hash || recipient_PK || sender_PK)
//      where:
//        header_hash  = SHA3-512(ephemeral_PK || master_salt || root_key)
//    - This binds the signature to (sender, this recipient, this file's keys).
//      A recipient cannot re-target the signature at a different recipient,
//      because cap_hash changes with recipient_PK.
//    - Unauthenticated files carry 64 zero bytes in the signature slot.
//      Only the recipient, after successful AEAD unwrap, can tell.
//
// Data encryption:
//    - Root key: random 32 bytes. HKDF-SHA3 expands (root_key, header_cksum)
//      into the AES-GCM key, nonce, and chunk-HMAC key.
//    - Using the header checksum as HKDF salt binds every data chunk to the
//      full header — any header modification invalidates decryption.
//    - Data is split into chunks (default 128 KiB, max 1 GiB). Each chunk
//      is individually AEAD-sealed; the chunk length and index form the AD.
//      The top bit of the chunk length marks EOF.
//
// Trailer:
//    - Cumulative HMAC-SHA3-512 of the chunk ADs (detects truncation/reordering).
//    - When the sender is authenticated, the trailer also carries an Ed25519
//      signature over the HMAC. Unauthenticated files carry a random-looking
//      trailer sig so files are indistinguishable in length/shape.
//

package sigtool

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	Ed "crypto/ed25519"
	"crypto/hmac"
	"crypto/sha3"
	"crypto/subtle"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"

	"github.com/opencoff/sigtool/internal/pb"
)

const (
	// The latest version of the tool's output file format
	_SigtoolVersion = 5

	_chunkSize    uint32 = 128 * 1024
	_maxChunkSize uint32 = 1 << 30
	_EOF          uint32 = 1 << 31

	_Magic       = "SigTool"
	_MagicLen    = len(_Magic)
	_FixedHdrLen = _MagicLen + 1 + 4 // 1: version, 4: len of variable segment

	_Sha3Size      = 64
	_AesKeySize    = 32
	_AEADNonceSize = 12
	_SaltSize      = 32
	_RxNonceSize   = 12 // nonce size of per-recipient encrypted blocks

	_WrapReceiver     = "Receiver Key"
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

	// hash binding ephemeral PK, salt and root key — fed into each per-capsule sig
	hdrHash []byte

	// reader and writer
	rd io.Reader
	wr io.WriteCloser

	auth    bool // set if the sender identity is signed into each capsule
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
		nonce:  make([]byte, _AEADNonceSize),
		encSK:  esk,
		sender: sk,
		auth:   sk != nil,

		rd: rd,
		wr: wr,
	}

	e.hdrHash = headerHash(e.Pk, e.Salt, e.key)

	if err = e.AddRecipient(rx); err != nil {
		return nil, err
	}

	return e, nil
}

// headerHash binds the sender's ephemeral PK, the master salt, and the root
// data-encryption key. It feeds every per-capsule signature so that any
// modification to these inputs invalidates authentication.
func headerHash(ephPk, salt, key []byte) []byte {
	var out [_Sha3Size]byte
	h := sha3.New512()
	h.Write(ephPk)
	h.Write(salt)
	h.Write(key)
	return h.Sum(out[:0])
}

// capsuleHash is what the sender signs for each recipient. It binds the
// header hash to the specific (recipient, sender) pair.
func capsuleHash(hdrHash, recipientPk, senderPk []byte) []byte {
	var out [_Sha3Size]byte
	h := sha3.New512()
	h.Write(hdrHash)
	h.Write(recipientPk)
	h.Write(senderPk)
	return h.Sum(out[:0])
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
	// Error path: ensure output file is closed. Cleared on the happy path
	// so we don't double-close.
	closed := false
	defer func() {
		if !closed {
			e.wr.Close()
		}
	}()

	if !e.started {
		err := e.start()
		if err != nil {
			return err
		}
	}

	buf := make([]byte, e.ChunkSize)

	var i uint32
	var eof bool
	var sz uint64
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

		}
		i++
		sz += uint64(n)
	}

	if err := e.writeTrailer(i, sz); err != nil {
		return err
	}

	closed = true
	return e.wr.Close()
}

// encrypt exactly _one_ block of data
func (e *Encryptor) encrypt(pt []byte, i uint32, eof bool) error {

	ptlen := uint32(len(pt))
	if eof {
		ptlen |= _EOF
	}

	var ad [8]byte

	lbuf, ct := e.buf[:4], e.buf[4:]

	// we record the length of each chunk as the first
	enc32(lbuf, ptlen)

	// construct the AD
	copy(ad[:4], lbuf)
	enc32(ad[4:], i)

	ct = e.ae.Seal(ct[:0], e.nonce, pt, ad[:])

	incrNonce(e.nonce)

	n := len(ct) + len(lbuf)
	err := fullwrite(e.buf[:n], e.wr)
	if err != nil {
		return fmt.Errorf("encrypt: chunk %d: %w", i, err)
	}

	e.hmac.Write(ad[:])

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
	defer clear(buffer)

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

	// scrub the buffer used for keys. While this is good hygiene, the go-stdlib
	// doesn't clear the AES key schedule nor the HMAC ipad/opad. These would likely
	// require the language to have a formal notion of "destructor" (beyond just
	// `runtime.SetFinalizer()`).
	defer clear(outbuf)

	// we mix the header checksum (and it captures the sigtool version, sender
	// identity, etc.)
	buf := expand(outbuf, e.key, cksum, []byte(_DataKeyExpansion))

	nonce, buf := buf[:_AEADNonceSize], buf[_AEADNonceSize:]
	dkey, buf := buf[:_AesKeySize], buf[_AesKeySize:]
	hmackey := buf

	// make sure we save the nonce; it will get zero'd out otherwise
	// (see defer above!)
	copy(e.nonce, nonce)

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

	return nil
}

// Write a trailer:
//   - trailer: total blocks and total size
//   - we always write the hmac
//   - if authenticating sender, sign the hmac and put the signature in the trailer
//   - if not authenticating sender, we put random bytes as the signature
func (e *Encryptor) writeTrailer(nblks uint32, sz uint64) error {
	var hmac [_Sha3Size]byte
	var tr [8 + 4]byte

	enc32(tr[:4], nblks)
	enc64(tr[4:], sz)

	e.hmac.Write(tr[:])
	e.hmac.Sum(hmac[:0])

	if err := fullwrite(hmac[:], e.wr); err != nil {
		return fmt.Errorf("encrypt: hmac trailer %w", err)
	}

	var b []byte
	if e.auth {
		// We know sender is non null.
		sig, err := e.sender.SignMessage(hmac[:])
		if err != nil {
			return fmt.Errorf("encrypt: trailer: %w", err)
		}
		b = []byte(sig)
	} else {
		b = []byte(randSig())
	}

	if err := fullwrite(b, e.wr); err != nil {
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

	hdrsum  []byte // cached header checksum
	hdrHash []byte // cached H(ephemeral_PK || master_salt || root_key); populated once root_key is unwrapped
	auth    bool   // flag set to true if sender signed the key
	eof     bool
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

	if !bytes.Equal(b[:_MagicLen], []byte(_Magic)) {
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
		nonce:  make([]byte, _AEADNonceSize),
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
		return nil, fmt.Errorf("decrypt: invalid salt length %d", len(d.Salt))
	}

	if len(d.Keys) == 0 {
		return nil, ErrNoWrappedKeys
	}

	// Iterate capsules. unwrapKey performs an exact length check against
	// (_AesKeySize + Ed.SignatureSize + AEAD overhead); AEAD failure means
	// "not this recipient's capsule" — move on.
	for i, w := range d.Keys {
		key, sig, err := d.unwrapKey(w, sk)
		if err != nil {
			return nil, fmt.Errorf("decrypt: can't unwrap key %d: %w", i, err)
		}

		if key != nil {
			d.hdrHash = headerHash(d.Pk, d.Salt, key)
			if err := d.verifyCapsule(sk, sig); err != nil {
				return nil, fmt.Errorf("decrypt: capsule %d: %w", i, err)
			}
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

	// Error path: ensure output file is closed. Cleared on the happy path
	// so we don't double-close.
	closed := false
	defer func() {
		if !closed {
			d.wr.Close()
		}
	}()

	if d.ae == nil {
		return ErrNoKey
	}

	if d.eof {
		return io.EOF
	}

	var i uint32
	var sz uint64
	var eof bool
	for !eof {
		var n int
		var err error

		eof, n, err = d.decrypt(i)
		if err != nil {
			return err
		}

		i++
		sz += uint64(n)
	}

	// process the trailer
	if err := d.processTrailer(i, sz); err != nil {
		return err
	}

	closed = true
	return d.wr.Close()
}

// Decrypt exactly one chunk of data
func (d *Decryptor) decrypt(i uint32) (bool, int, error) {
	var ad [8]byte

	n, err := io.ReadFull(d.rd, ad[:4])
	if err != nil {
		return false, 0, fmt.Errorf("decrypt: read chunk %d: %w", i, err)
	}

	_, ptlen := dec32[uint32](ad[:4])

	// construct the AD
	enc32(ad[4:], i)

	d.hmac.Write(ad[:])

	eof := (ptlen & _EOF) > 0
	ptlen &= (_EOF - 1)

	switch {
	case ptlen > d.ChunkSize:
		return false, 0, fmt.Errorf("decrypt: chunk %d: too large %d", i, ptlen)

	case ptlen == 0:
		if !eof {
			return false, 0, fmt.Errorf("decrypt: chunk %d: empty chunk without EOF", i)
		}
	}

	ovh := d.ae.Overhead()
	n, err = io.ReadFull(d.rd, d.buf[:int(ptlen)+ovh])
	if err != nil {
		return false, 0, fmt.Errorf("decrypt: read chunk %d: %w", i, err)
	}

	ct := d.buf[:n]
	pt, err := d.ae.Open(ct[:0], d.nonce, ct, ad[:])
	if err != nil {
		return false, 0, fmt.Errorf("decrypt: chunk %d: %w", i, err)
	}

	if len(pt) != int(ptlen) {
		return false, 0, fmt.Errorf("decrypt: chunk %d: unseal exp %d, saw %d", i, ptlen, len(pt))
	}

	incrNonce(d.nonce)

	d.eof = eof

	if len(pt) > 0 {
		err = fullwrite(pt, d.wr)
		if err != nil {
			return false, 0, fmt.Errorf("decrypt: write chunk %d: %w", i, err)
		}
	}

	return eof, int(ptlen), nil
}

// Setup the decryption keys and prepare to decrypt stream
func (d *Decryptor) start(key []byte) (*Decryptor, error) {
	// make sure we scrub this shared key
	defer clear(key)

	outbuf := make([]byte, _Sha3Size+_AesKeySize+_AEADNonceSize)
	defer clear(outbuf)

	buf := expand(outbuf, key, d.hdrsum, []byte(_DataKeyExpansion))

	nonce, buf := buf[:_AEADNonceSize], buf[_AEADNonceSize:]
	dkey, buf := buf[:_AesKeySize], buf[_AesKeySize:]
	hmackey := buf

	// make sure we save the nonce; it will get zero'd out otherwise
	// (see defer above!)
	copy(d.nonce, nonce)

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

	return d, nil
}

func (d *Decryptor) processTrailer(nblks uint32, sz uint64) error {
	var hmac [_Sha3Size]byte
	var tr [8 + 4]byte

	enc32(tr[:4], nblks)
	enc64(tr[4:], sz)

	// first read the hmac
	_, err := io.ReadFull(d.rd, hmac[:])
	if err != nil {
		return fmt.Errorf("decrypt: premature EOF while reading hmac trailer: %w", err)
	}

	d.hmac.Write(tr[:])
	cksum := d.hmac.Sum(nil)

	if subtle.ConstantTimeCompare(hmac[:], cksum) == 0 {
		return fmt.Errorf("decrypt: trailer MAC: %w", ErrBadTrailer)
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

// verifyCapsule checks the per-capsule signature on the wrapped key we just
// unwrapped. If the signature is the all-zero sentinel, the file is
// unauthenticated; otherwise the sender PK is required and must verify.
func (d *Decryptor) verifyCapsule(sk *PrivateKey, sig []byte) error {
	if len(sig) != Ed.SignatureSize {
		return fmt.Errorf("decrypt: capsule sig: bad length %d", len(sig))
	}

	var nullsig [Ed.SignatureSize]byte

	// Unauthenticated sentinel: all-zero signature. Check BEFORE demanding
	// sender PK — an unauthenticated file decrypts fine without one.
	if subtle.ConstantTimeCompare(sig, nullsig[:]) == 1 {
		d.auth = false
		return nil
	}

	// Authenticated: sender PK is required.
	if d.sender == nil {
		return ErrNoSenderPK
	}

	ch := capsuleHash(d.hdrHash, sk.pk.pk, d.sender.pk)

	if !d.sender.verifyRaw(ch, sig) {
		return ErrBadSender
	}
	d.auth = true
	return nil
}

// Wrap data encryption key 'k' with the sender's PK and our ephemeral curve SK
// basically, we do a scalarmult: Ephemeral encryption/decryption SK x receiver PK.
// Also signs a per-capsule Ed25519 signature binding (header_hash, recipient_pk,
// sender_pk) so the recipient can authenticate the sender.
func (e *Encryptor) wrapKey(pk *PublicKey) (*pb.WrappedKey, error) {
	rxPK := pk.ToCurve25519()
	sekrit, err := curve25519.X25519(e.encSK, rxPK)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}
	defer clear(sekrit)

	salt := randBuf(_RxNonceSize)

	out := make([]byte, _AesKeySize+_RxNonceSize)
	defer clear(out)

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

	// Build the capsule plaintext: 32-byte root key || 64-byte capsule sig.
	// Binding both inside one AEAD blob (rather than storing the sig in a
	// separate plaintext field) keeps the wire format indistinguishable
	// between authenticated and unauthenticated encrypts: an observer can
	// not tell from the header whether the sender signed.
	var pt [_AesKeySize + Ed.SignatureSize]byte
	defer clear(pt[:])

	copy(pt[:_AesKeySize], e.key)

	if e.sender != nil {
		ch := capsuleHash(e.hdrHash, pk.pk, e.sender.pk.pk)
		sig, err := e.sender.signRaw(ch)
		if err != nil {
			return nil, fmt.Errorf("wrap: sign capsule: %w", err)
		}
		copy(pt[_AesKeySize:], sig)
	}
	// unauthenticated: pt[_AesKeySize:] stays zero — the null-sig sentinel

	ekey := make([]byte, ae.Overhead()+len(pt))
	w := &pb.WrappedKey{
		DKey: ae.Seal(ekey[:0], nonce, pt[:], pk.pk),
		Salt: salt,
	}

	return w, nil
}

// Unwrap a wrapped key using the receivers Ed25519 secret key 'sk' and
// senders ephemeral PublicKey
func (d *Decryptor) unwrapKey(w *pb.WrappedKey, sk *PrivateKey) (key, sig []byte, err error) {
	ourSK := sk.ToCurve25519()
	sekrit, err := curve25519.X25519(ourSK, d.Pk)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrap: %w", err)
	}
	defer clear(sekrit)

	pk := sk.PublicKey()

	out := make([]byte, _AesKeySize+_RxNonceSize)
	defer clear(out)

	buf := expand(out[:], sekrit, w.Salt, pk.pk, d.Pk, []byte(_WrapReceiver))

	kek, nonce := buf[:_AesKeySize], buf[_AesKeySize:]

	aes, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap: %w", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap: %w", err)
	}

	want := _AesKeySize + Ed.SignatureSize + ae.Overhead()
	if len(w.DKey) != want {
		return nil, nil, fmt.Errorf("unwrap: incorrect decrypt bytes (need %d, saw %d)", want, len(w.DKey))
	}

	pt := make([]byte, 0, _AesKeySize+Ed.SignatureSize)
	pt, err = ae.Open(pt, nonce, w.DKey, pk.pk)
	if err != nil {
		// not this recipient's capsule — signal with all-nil
		return nil, nil, nil
	}

	key = pt[:_AesKeySize]
	sig = pt[_AesKeySize:]
	return key, sig, nil
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

// increment the nonce as a big-endian counter (carry propagates from LSB)
func incrNonce(nonce []byte) []byte {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i] += 1
		if nonce[i] != 0 {
			break
		}
	}
	return nonce
}

// EOF
