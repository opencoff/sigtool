// keys.go -- Ed25519 keys management
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

// This file implements:
//   - key generation, and key I/O
//   - sign/verify of files and byte strings

package sigtool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"

	Ed "crypto/ed25519"
	"golang.org/x/crypto/argon2"

	"github.com/opencoff/sigtool/internal/pb"
)

// Private Ed25519 key
type PrivateKey struct {
	sk []byte

	// User provided comment string
	Comment string

	// Encryption key: Curve25519 point corresponding to this Ed25519 key
	ck []byte

	// Cached copy of the public key
	pk *PublicKey
}

// Public Ed25519 key
type PublicKey struct {
	pk []byte

	// User provided comment string
	Comment string

	// Curve25519 point corresponding to this Ed25519 key
	ck []byte

	// fingerprint
	fp []byte
}

// constants we use in this module
const (
	_FpSize = 16 // Length of Ed25519 Public Key Hash

	// Algorithm used in the encrypted private key
	_SkAlgo = "sha3-argon2id"

	// PEM Block header
	_SigtoolSK = "SIGTOOL PRIVATE KEY"
	_SigtoolPK = "SIGTOOL PUBLIC KEY"

	// These are comforable margins exceeding
	// NIST 2024 guidelines
	_Argon2idMem  uint32 = 64 * 1024
	_Argon2idTime uint32 = 2
	_Argon2idProc uint32 = 8
)

// given a public key, generate a deterministic short-hash of it.
func pkhash(pk []byte) []byte {
	z := sha3.Sum256(pk)
	return z[:_FpSize]
}

// NewPrivateKey generates a new Ed25519 private key
func NewPrivateKey(comment string) (*PrivateKey, error) {
	pkb, skb, err := Ed.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	sk := &PrivateKey{
		sk:      []byte(skb),
		Comment: comment,
		ck:      ed25519SKToCurve([]byte(skb)),
		pk: &PublicKey{
			pk:      []byte(pkb),
			Comment: comment,
			ck:      ed25519PKToCurve([]byte(pkb)),
			fp:      pkhash([]byte(pkb)),
		},
	}
	return sk, nil
}

// ParsePrivateKey makes a new private key from a previously serialized
// byte stream
func ParsePrivateKey(b []byte, getpw func() ([]byte, error)) (*PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("sigtool: PrivateKey: No PEM")
	}

	if blk.Type == "OPENSSH PRIVATE KEY" {
		return parseSSHPrivateKey(b, getpw)
	}

	if blk.Type != _SigtoolSK {
		return nil, fmt.Errorf("sigtool: PrivateKey: Not sigtool")
	}

	// validate the headers; without KDF and Algo, we're dead.
	kdf, ok := blk.Headers["kdf"]
	if !ok {
		return nil, fmt.Errorf("sigtool: PrivateKey: Malformed PEM, no KDF")
	}

	_, a, err := parseKDF(kdf)
	if err != nil {
		return nil, fmt.Errorf("sigtool: PrivateKey: %w", err)
	}

	// Unmarshal first
	var ssk pb.Sk

	if err := ssk.UnmarshalVT(blk.Bytes); err != nil {
		return nil, fmt.Errorf("sigtool: PrivateKey: %w", err)
	}

	var pw []byte

	// we are now ready to decrypt
	// but first get the user passphrase
	if getpw != nil {
		pwx, err := getpw()
		if err != nil {
			return nil, fmt.Errorf("sigtool: PrivateKey: parse: %w", err)
		}
		pw = pwx
	}

	skb, err := skDecrypt(pw, &ssk, a)
	if err != nil {
		return nil, fmt.Errorf("sigtool: PrivateKey: decrypt: %w", err)
	}

	// Now turn the raw bytes into a proper key
	sk, err := makeSK(skb, blk.Headers["comment"])
	if err != nil {
		return nil, fmt.Errorf("sigtool: PrivateKey: parse: %w", err)
	}

	return sk, nil
}

// ReadPrivateKey reads a file containing a private key. The private key
// can be an OpenSSH Private key (PEM) or a sigtool Private key (PEM).
func ReadPrivateKey(fn string, getpw func() ([]byte, error)) (*PrivateKey, error) {
	skb, err := os.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("private key: %s: %w", fn, err)
	}

	sk, err := ParsePrivateKey(skb, getpw)
	if err != nil {
		return nil, fmt.Errorf("private key %s: %w", fn, err)
	}
	return sk, nil
}

// PublicKey returns the public key corresponding to this private key
func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pk
}

// Fingerprint returns the fingerprint of this key
// (A fingerprint is a truncated hash of the public key)
func (sk *PrivateKey) Fingerprint() string {
	return sk.pk.Fingerprint()
}

// Equal returns true if the two PrivateKeys are equal and false otherwise
func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	return subtle.ConstantTimeCompare(sk.sk, other.sk) == 1
}

// ToCurve25519 returns the Curve25519 private key corresponding to this
// Ed25519 private key. The value is computed at construction time.
func (sk *PrivateKey) ToCurve25519() []byte {
	return sk.ck
}

// Marshal marshals the private key into sigtool native format by encrypting
// the private key with the user supplied function to get a passphrase
func (sk *PrivateKey) Marshal(getpw func() ([]byte, error)) ([]byte, error) {
	var pw []byte

	// first get the user passphrase
	if getpw != nil {
		pwx, err := getpw()
		if err != nil {
			return nil, fmt.Errorf("sigtool: PrivateKey %s: marshal: %w", sk.Comment, err)
		}
		pw = pwx
	}

	// AES Encrypt the sk
	esk, salt, err := sk.encrypt(pw)
	if err != nil {
		return nil, fmt.Errorf("sigtool: PrivateKey %s: marshal: %w", sk.Comment, err)
	}

	kdf, err := encodeKDF(salt)
	if err != nil {
		return nil, fmt.Errorf("sigtool: PrivateKey %s: marshal: %w", sk.Comment, err)
	}

	ssk := &pb.Sk{
		Esk: esk,
	}

	skb, err := ssk.MarshalVT()
	if err != nil {
		return nil, fmt.Errorf("sigtool: PrivateKey %s: marshal: %w", sk.Comment, err)
	}

	// Put this in a PEM Block
	blk := &pem.Block{
		Type: _SigtoolSK,
		Headers: map[string]string{
			"comment":     sk.Comment,
			"fingerprint": sk.pk.Fingerprint(),
			"kdf":         kdf,
		},
		Bytes: skb,
	}

	b := pem.EncodeToMemory(blk)
	return b, nil
}

// encrypt the private key bytes with user supplied passphrase and using
// default argon2id params
func (sk *PrivateKey) encrypt(pw []byte) ([]byte, []byte, error) {
	pwb := sha3.Sum512(pw)
	defer clear(pwb[:])

	salt := randBuf(32)
	buf := argonKDF(_AEADNonceSize+_AesKeySize, pwb[:], salt)
	defer clear(buf)

	key, nonce := buf[:_AesKeySize], buf[_AesKeySize:]

	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	ae, err := cipher.NewGCM(ciph)
	if err != nil {
		return nil, nil, err
	}

	esk := ae.Seal(nil, nonce, sk.sk, nil)

	return esk, salt, nil
}

// decrypt an encrypted Sk using the given user passphrase and KDF params
func skDecrypt(pw []byte, ssk *pb.Sk, a *pb.Argon) ([]byte, error) {
	if err := validateArgonParams(a); err != nil {
		return nil, err
	}

	pwb := sha3.Sum512(pw)
	defer clear(pwb[:])

	buf := argon2.IDKey(pwb[:], a.Salt, a.Time,
		a.Mem, uint8(a.Proc), uint32(_AEADNonceSize+_AesKeySize))
	defer clear(buf)

	key, nonce := buf[:_AesKeySize], buf[_AesKeySize:]

	ciph, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ae, err := cipher.NewGCM(ciph)
	if err != nil {
		return nil, err
	}

	skb, err := ae.Open(nil, nonce, ssk.Esk, nil)
	if err != nil {
		return nil, err
	}

	return skb, nil
}

// -- public key methods --

// ParsePublicKey makes a new public key from a previously serialized byte
// stream
func ParsePublicKey(b []byte) (*PublicKey, error) {
	// We first try to parse this as a openssh public key string
	if pk, err := parseEncPubKey(b, "cli-openssh-string"); err == nil {
		return pk, nil
	}

	// Ok that didn't work; let's try to decode as openssh key
	if pk, err := parseSSHPublicKey(b); err == nil {
		return pk, nil
	}

	// Finally, try to decode as a sigtool key
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("sigtool: PublicKey: No PEM")
	}

	if blk.Type != _SigtoolPK {
		return nil, fmt.Errorf("sigtool: PublicKey: Not sigtool")
	}

	// Unmarshal first
	var spk pb.Pk

	if err := spk.UnmarshalVT(blk.Bytes); err != nil {
		return nil, fmt.Errorf("sigtool: PublicKey: %w", err)
	}

	pk, err := makePK(spk.Pk, blk.Headers["comment"])
	if err != nil {
		return nil, fmt.Errorf("sigtool: PublicKey: %w", err)
	}
	return pk, nil
}

// ReadPublicKey reads a public key from a file. The public key can be one of:
// - a string containing the openssh PK
// - a file containing the openssh PK
// - a file containing native sigtool PK
func ReadPublicKey(fn string) (*PublicKey, error) {
	// first see if we can read the file
	pkb, err := os.ReadFile(fn)
	if err != nil {
		// we couldn't; let's treat it as a string
		pkb = []byte(fn)
	}

	// Now parse the public key
	pk, err := ParsePublicKey(pkb)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// Fingerprint returns the fingerprint of this public key
func (pk *PublicKey) Fingerprint() string {
	return tob64(pk.fp)
}

// Equal returns true if the two PrivateKeys are equal and false otherwise
func (pk *PublicKey) Equal(other *PublicKey) bool {
	return subtle.ConstantTimeCompare(pk.pk, other.pk) == 1
}

// ToCurve25519 returns the Curve25519 public key corresponding to this
// Ed25519 public key. The value is computed at construction time.
func (pk *PublicKey) ToCurve25519() []byte {
	return pk.ck
}

// Marshal marshals the public key in sigtool native format
func (pk *PublicKey) Marshal() ([]byte, error) {
	spk := &pb.Pk{
		Pk: pk.pk,
	}

	pkb, err := spk.MarshalVT()
	if err != nil {
		return nil, fmt.Errorf("sigtool: PublicKey %s: marshal: %w", pk.Comment, err)
	}

	blk := &pem.Block{
		Type: _SigtoolPK,
		Headers: map[string]string{
			"comment":     pk.Comment,
			"fingerprint": pk.Fingerprint(),
		},
		Bytes: pkb,
	}

	b := pem.EncodeToMemory(blk)
	return b, nil
}

// from github.com/FiloSottile/age
var curve25519P, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

// -- Internal Utility Functions --

func makeSK(skb []byte, comm string) (*PrivateKey, error) {
	if len(skb) != 64 {
		return nil, fmt.Errorf("SK too small (%d)", len(skb))
	}

	edsk := Ed.PrivateKey(skb)
	edpk := []byte(edsk.Public().(Ed.PublicKey))

	pk := &PublicKey{
		pk:      edpk,
		Comment: comm,
		ck:      ed25519PKToCurve(edpk),
		fp:      pkhash(edpk),
	}

	sk := &PrivateKey{
		sk:      skb,
		Comment: comm,
		ck:      ed25519SKToCurve(skb),
		pk:      pk,
	}

	return sk, nil
}

func makePK(pkb []byte, comm string) (*PublicKey, error) {
	if len(pkb) != 32 {
		return nil, fmt.Errorf("PK len wrong (%d)", len(pkb))
	}

	pk := &PublicKey{
		pk:      pkb,
		Comment: comm,
		ck:      ed25519PKToCurve(pkb),
		fp:      pkhash(pkb),
	}
	return pk, nil
}

func clamp(k []byte) []byte {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}

// ed25519SKToCurve derives the Curve25519 private scalar from an Ed25519
// private key (64-byte seed||pk form). The result is a fresh 32-byte slice.
func ed25519SKToCurve(sk []byte) []byte {
	h := sha512.Sum512(sk[:32])
	defer clear(h[:])

	out := make([]byte, 32)
	copy(out, h[:32])
	return clamp(out)
}

// ed25519PKToCurve derives the Curve25519 public point from an Ed25519
// public key via the birational map. From github.com/FiloSottile/age.
func ed25519PKToCurve(pk []byte) []byte {
	// ed25519.PublicKey is a little-endian representation of the y-coordinate,
	// with the most significant bit set based on the sign of the x-coordinate.
	bigEndianY := make([]byte, Ed.PublicKeySize)
	for i, b := range pk {
		bigEndianY[Ed.PublicKeySize-i-1] = b
	}
	bigEndianY[0] &= 0b0111_1111

	// The Montgomery u-coordinate is derived through the bilinear map
	//     u = (1 + y) / (1 - y)
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption.
	y := new(big.Int).SetBytes(bigEndianY)
	denom := big.NewInt(1)
	denom.ModInverse(denom.Sub(denom, y), curve25519P)
	u := y.Mul(y.Add(y, big.NewInt(1)), denom)
	u.Mod(u, curve25519P)

	out := make([]byte, 32)
	uBytes := u.Bytes()
	n := len(uBytes)
	for i, b := range uBytes {
		out[n-i-1] = b
	}
	return out
}

func argonKDF(n int, secret, salt []byte) []byte {
	return argon2.IDKey(secret, salt, _Argon2idTime,
		_Argon2idMem, uint8(0xff&_Argon2idProc), uint32(n))
}

// bounds for attacker-supplied Argon2id parameters when parsing a sigtool
// PEM. These gates exist because the stdlib argon2 package panics on Time=0,
// truncates Proc silently, and will happily allocate terabytes for large Mem.
const (
	_ArgonMinTime uint32 = 1
	_ArgonMaxTime uint32 = 1024
	_ArgonMinMem  uint32 = 8       // argon2 requires >= 8 KiB per lane
	_ArgonMaxMem  uint32 = 1 << 20 // 1 GiB — ours is 64 MiB
	_ArgonMinProc uint32 = 1
	_ArgonMaxProc uint32 = 255 // must fit in uint8
	_ArgonMinSalt int    = 8   // argon2 spec minimum
	_ArgonMaxSalt int    = 128
)

// validateArgonParams range-checks attacker-controlled Argon2id parameters
// before we hand them to the argon2 library.
func validateArgonParams(a *pb.Argon) error {
	if a == nil {
		return ErrBadKDFParams
	}
	if a.Time < _ArgonMinTime || a.Time > _ArgonMaxTime {
		return ErrBadKDFParams
	}
	if a.Mem < _ArgonMinMem || a.Mem > _ArgonMaxMem {
		return ErrBadKDFParams
	}
	if a.Proc < _ArgonMinProc || a.Proc > _ArgonMaxProc {
		return ErrBadKDFParams
	}
	if n := len(a.Salt); n < _ArgonMinSalt || n > _ArgonMaxSalt {
		return ErrBadKDFParams
	}
	return nil
}

func encodeKDF(salt []byte) (string, error) {
	a := &pb.Argon{
		Mem:  _Argon2idMem,
		Time: _Argon2idTime,
		Proc: _Argon2idProc,
		Salt: salt,
	}

	b, err := a.MarshalVT()
	if err != nil {
		return "", fmt.Errorf("kdf: marshal: %w", err)
	}

	s := fmt.Sprintf("%s:%s", _SkAlgo, tob64(b))
	return s, nil
}

func parseKDF(s string) (string, *pb.Argon, error) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", nil, fmt.Errorf("kdf: malformed string")
	}
	algo, s := s[:i], s[i+1:]

	if algo != _SkAlgo {
		return "", nil, fmt.Errorf("kdf: %s: unsupported algorithm", algo)
	}

	// now we have a b64url encoded protobuf.
	b, err := fromb64(s)
	if err != nil {
		return "", nil, fmt.Errorf("kdf: malformed KDF params")
	}

	var a pb.Argon
	if err = a.UnmarshalVT(b); err != nil {
		return "", nil, fmt.Errorf("kdf: unmarshal: %w", err)
	}

	return algo, &a, nil
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
