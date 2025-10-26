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
	_Sk_algo = "sha3-argon2id"

	// PEM Block header
	_Sigtool_SK = "SIGTOOL PRIVATE KEY"
	_Sigtool_PK = "SIGTOOL PUBLIC KEY"

	// These are comforable margins exceeding
	// NIST 2024 guidelines
	_Argon2id_mem  uint32 = 64 * 1024
	_Argon2id_time uint32 = 2
	_Argon2id_proc uint32 = 8
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
		pk: &PublicKey{
			pk:      []byte(pkb),
			Comment: comment,
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

	if blk.Type != _Sigtool_SK {
		return nil, fmt.Errorf("sigtool: PrivateKey: Not sigtool")
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

	skb, err := skDecrypt(pw, &ssk)
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

// ToCurve25519 converts an ed25519 private key to its corresponding
// curve25519 private key
func (sk *PrivateKey) ToCurve25519() []byte {
	if sk.ck == nil {
		var ek [64]byte

		h := sha512.New()
		h.Write(sk.sk[:32])
		h.Sum(ek[:0])

		sk.ck = clamp(ek[:32])
	}

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
		return nil, fmt.Errorf("sigtool: PrivateKey %s: encrypt: %w", sk.Comment, err)
	}

	ssk := &pb.Sk{
		Esk:  esk,
		Salt: salt,
		Algo: _Sk_algo,
		Kdf: &pb.Argon{
			Mem:  _Argon2id_mem,
			Time: _Argon2id_time,
			Proc: _Argon2id_proc,
		},
	}

	skb, err := ssk.MarshalVT()
	if err != nil {
		return nil, fmt.Errorf("sigtool: PrivateKey %s: marshal: %w", sk.Comment, err)
	}

	// Put this in a PEM Block
	blk := &pem.Block{
		Type: _Sigtool_SK,
		Headers: map[string]string{
			"comment":     sk.Comment,
			"fingerprint": sk.pk.Fingerprint(),
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
	salt := randBuf(32)
	buf := argonKDF(_AEADNonceSize+_AesKeySize, pwb[:], salt)
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
func skDecrypt(pw []byte, ssk *pb.Sk) ([]byte, error) {
	if ssk.Algo != _Sk_algo {
		return nil, fmt.Errorf("unknown KDF: %s", ssk.Algo)
	}

	pwb := sha3.Sum512(pw)
	kdf := ssk.Kdf
	buf := argon2.IDKey(pwb[:], ssk.Salt, kdf.Time,
		kdf.Mem, uint8(0xff&kdf.Proc), uint32(_AEADNonceSize+_AesKeySize))
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
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("sigtool: PublicKey: No PEM")
	}

	if blk.Type != _Sigtool_PK {
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

// Fingerprint returns the fingerprint of this public key
func (pk *PublicKey) Fingerprint() string {
	return tob64(pk.fp)
}

// Equal returns true if the two PrivateKeys are equal and false otherwise
func (pk *PublicKey) Equal(other *PublicKey) bool {
	return subtle.ConstantTimeCompare(pk.pk, other.pk) == 1
}

// ToCurve25519 converts an Ed25519 Public Key to its corresponding Curve25519
// public key. This is directly from github.com/FiloSottile/age.
func (pk *PublicKey) ToCurve25519() []byte {
	if pk.ck != nil {
		return pk.ck
	}

	// ed25519.PublicKey is a little endian representation of the y-coordinate,
	// with the most significant bit set based on the sign of the x-ccordinate.
	bigEndianY := make([]byte, Ed.PublicKeySize)
	for i, b := range pk.pk {
		bigEndianY[Ed.PublicKeySize-i-1] = b
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
		Type: _Sigtool_PK,
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
		fp:      pkhash(edpk),
	}

	sk := &PrivateKey{
		sk:      skb,
		Comment: comm,
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

func argonKDF(n int, secret, salt []byte) []byte {
	return argon2.IDKey(secret, salt, _Argon2id_time,
		_Argon2id_mem, uint8(0xff&_Argon2id_proc), uint32(n))
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
