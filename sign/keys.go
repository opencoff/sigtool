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

package sign

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"

	Ed "crypto/ed25519"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/yaml.v2"
)

// Private Ed25519 key
type PrivateKey struct {
	Sk []byte

	// Encryption key: Curve25519 point corresponding to this Ed25519 key
	ck []byte

	// Cached copy of the public key
	pk *PublicKey
}

// Public Ed25519 key
type PublicKey struct {
	Pk []byte

	// Comment string
	Comment string

	// Curve25519 point corresponding to this Ed25519 key
	ck []byte

	hash []byte
}

// Length of Ed25519 Public Key Hash
const PKHashLength = 16

// constants we use in this module
const (
	// Scrypt parameters
	_N int = 1 << 19
	_r int = 8
	_p int = 1

	// Algorithm used in the encrypted private key
	sk_algo  = "scrypt-sha256"
	sig_algo = "sha512-ed25519"
)

// Encrypted Private key
type serializedPrivKey struct {
	Comment string `yaml:"comment,omitempty"`

	// Encrypted Sk
	Esk  string `yaml:"esk"`
	Salt string `yaml:"salt,omitempty"`

	// Algorithm used for checksum and KDF
	Algo string `yaml:"algo,omitempty"`

	// These are params for scrypt.Key()
	// CPU Cost parameter; must be a power of 2
	N int `yaml:"Z,flow,omitempty"`

	// r * p should be less than 2^30
	R int `yaml:"r,flow,omitempty"`
	P int `yaml:"p,flow,omitempty"`
}

// serialized representation of public key
type serializedPubKey struct {
	Comment string `yaml:"comment,omitempty"`
	Pk      string `yaml:"pk"`
	Hash    string `yaml:"hash"`
}

// Serialized signature
type signature struct {
	Comment   string `yaml:"comment,omitempty"`
	Pkhash    string `yaml:"pkhash,omitempty"`
	Signature string `yaml:"signature"`
}

// given a public key, generate a deterministic short-hash of it.
func pkhash(pk []byte) []byte {
	z := sha256.Sum256(pk)
	return z[:PKHashLength]
}

// NewPrivateKey generates a new Ed25519 private key
func NewPrivateKey() (*PrivateKey, error) {
	pkb, skb, err := Ed.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	sk := &PrivateKey{
		Sk: []byte(skb),
		pk: &PublicKey{
			Pk:   []byte(pkb),
			hash: pkhash([]byte(pkb)),
		},
	}
	return sk, nil
}

// Read the private key in 'fn', optionally decrypting it using
// password 'pw' and create new instance of PrivateKey
func ReadPrivateKey(fn string, getpw func() ([]byte, error)) (*PrivateKey, error) {
	yml, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	var sk PrivateKey
	if err = sk.UnmarshalBinary(yml, getpw); err != nil {
		return nil, err
	}
	return &sk, nil
}

// Make a private key from bytes 'yml' using optional caller provided
// getpw() function to read the password if needed.
// are assumed to be serialized version of the private key.
func MakePrivateKey(yml []byte, getpw func() ([]byte, error)) (*PrivateKey, error) {
	var sk PrivateKey

	err := sk.UnmarshalBinary(yml, getpw)
	if err != nil {
		return nil, err
	}
	return &sk, nil
}

// make a PrivateKey from a byte array containing ed25519 raw SK
func makePrivateKeyFromBytes(sk *PrivateKey, buf []byte) error {
	if len(buf) != 64 {
		return fmt.Errorf("private key is malformed (len %d!)", len(buf))
	}

	skb := make([]byte, 64)
	copy(skb, buf)

	edsk := Ed.PrivateKey(skb)
	edpk := edsk.Public().(Ed.PublicKey)

	pk := &PublicKey{
		Pk:   []byte(edpk),
		hash: pkhash([]byte(edpk)),
	}
	sk.Sk = skb
	sk.pk = pk
	return nil
}

/*
// Make a private key from 64-bytes of extended Ed25519 key
func PrivateKeyFromBytes(buf []byte) (*PrivateKey, error) {
	var sk PrivateKey

	return makePrivateKeyFromBytes(&sk, buf)
}
*/

// Given a secret key, return the corresponding Public Key
func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pk
}

// Convert an Ed25519 Private Key to Curve25519 Private key
func (sk *PrivateKey) ToCurve25519SK() []byte {
	if sk.ck == nil {
		var ek [64]byte

		h := sha512.New()
		h.Write(sk.Sk[:32])
		h.Sum(ek[:0])

		sk.ck = clamp(ek[:32])
	}

	return sk.ck
}

// Serialize the private key to file 'fn' using human readable
// 'comment' and encrypt the key with supplied passphrase 'pw'.
func (sk *PrivateKey) Serialize(fn, comment string, ovwrite bool, pw []byte) error {
	b, err := sk.MarshalBinary(comment, pw)
	if err == nil {
		return writeFile(fn, b, ovwrite, 0600)
	}
	return err
}

// MarshalBinary marshals the private key with a caller provided
// passphrase 'pw' and human readable 'comment'
func (sk *PrivateKey) MarshalBinary(comment string, pw []byte) ([]byte, error) {
	// expand the password into 64 bytes
	pass := sha512.Sum512(pw)
	salt := make([]byte, 32)

	randRead(salt)

	// "32" == Length of AES-256 key
	key, err := scrypt.Key(pass[:], salt, _N, _r, _p, 32)
	if err != nil {
		return nil, fmt.Errorf("marshal: can't derive scrypt key: %s", err)
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("marshal: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("marshal: %s", err)
	}

	tl := ae.Overhead()
	buf := make([]byte, tl+len(sk.Sk))
	esk := ae.Seal(buf[:0], salt[:ae.NonceSize()], sk.Sk, nil)

	enc := base64.StdEncoding.EncodeToString

	ssk := serializedPrivKey{
		Comment: comment,
		Esk:     enc(esk),
		Salt:    enc(salt),
		Algo:    sk_algo,
		N:       _N,
		R:       _r,
		P:       _p,
	}

	// We won't protect the Scrypt parameters with the hash above
	// because it is not needed. If the parameters are wrong, the
	// derived key will be wrong and thus, the hash will not match.

	return yaml.Marshal(&ssk)
}

// UnmarshalBinary unmarshals the private key and optionally invokes the
// caller provided getpw() function to read the password if needed. If the
// input byte stream 'b' is an OpenSSH ed25519 key, this function transparently
// decodes it.
func (sk *PrivateKey) UnmarshalBinary(b []byte, getpw func() ([]byte, error)) error {
	if bytes.Index(b, []byte("OPENSSH PRIVATE KEY-")) > 0 {
		xk, err := parseSSHPrivateKey(b, getpw)
		if err != nil {
			return err
		}
		*sk = *xk
		return nil
	}

	var pw []byte
	if getpw != nil {
		var err error
		pw, err = getpw()
		if err != nil {
			return err
		}
	}

	// We take short passwords and extend them
	pwb := sha512.Sum512(pw)

	var ssk serializedPrivKey

	err := yaml.Unmarshal(b, &ssk)
	if err != nil {
		return fmt.Errorf("unmarshal priv key: can't parse YAML: %s", err)
	}

	if len(ssk.Salt) == 0 || len(ssk.Esk) == 0 {
		return fmt.Errorf("unmarshal priv key: not YAML format")
	}

	b64 := base64.StdEncoding.DecodeString

	salt, err := b64(ssk.Salt)
	if err != nil {
		return fmt.Errorf("unmarshal priv key: can't decode salt: %s", err)
	}

	esk, err := b64(ssk.Esk)
	if err != nil {
		return fmt.Errorf("unmarshal priv key: can't decode key: %s", err)
	}

	// "32" == Length of AES-256 key
	key, err := scrypt.Key(pwb[:], salt, ssk.N, ssk.R, ssk.P, 32)
	if err != nil {
		return fmt.Errorf("unmarshal priv key: can't derive key: %s", err)
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("unmarshal priv key: aes failure: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return fmt.Errorf("unmarshal priv key: aes failure: %s", err)
	}

	skb := make([]byte, 64)
	skb, err = ae.Open(skb[:0], salt[:ae.NonceSize()], esk, nil)
	if err != nil {
		return fmt.Errorf("unmarshal priv key: wrong password")
	}

	return makePrivateKeyFromBytes(sk, skb)
}

//  --- Public Key Methods ---

// Read the public key from 'fn' and create new instance of
// PublicKey
func ReadPublicKey(fn string) (*PublicKey, error) {
	var err error
	var yml []byte

	if yml, err = ioutil.ReadFile(fn); err != nil {
		return nil, err
	}

	var pk PublicKey
	if err = pk.UnmarshalBinary(yml); err != nil {
		return nil, err
	}
	return &pk, nil
}

// Parse a serialized public in 'yml' and return the resulting
// public key instance
func MakePublicKey(yml []byte) (*PublicKey, error) {
	var pk PublicKey
	if err := pk.UnmarshalBinary(yml); err != nil {
		return nil, err
	}
	return &pk, nil
}

func makePublicKeyFromBytes(pk *PublicKey, b []byte) error {
	if len(b) != 32 {
		return fmt.Errorf("public key is malformed (len %d!)", len(b))
	}

	pk.Pk = make([]byte, 32)
	pk.hash = pkhash(b)
	copy(pk.Pk, b)

	return nil
}

/*
// Make a public key from a byte string
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var pk PublicKey

	makePublicKeyFromBytes(&pk, b)
}
*/

// Serialize a PublicKey into file 'fn' with a human readable 'comment'.
// If 'ovwrite' is true, overwrite the file if it exists.
func (pk *PublicKey) Serialize(fn, comment string, ovwrite bool) error {
	out, err := pk.MarshalBinary(comment)
	if err == nil {
		return writeFile(fn, out, ovwrite, 0644)
	}

	return err
}

// from github.com/FiloSottile/age
var curve25519P, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

// Convert an Ed25519 Public Key to Curve25519 public key
// from github.com/FiloSottile/age
func (pk *PublicKey) ToCurve25519PK() []byte {
	if pk.ck != nil {
		return pk.ck
	}

	// ed25519.PublicKey is a little endian representation of the y-coordinate,
	// with the most significant bit set based on the sign of the x-ccordinate.
	bigEndianY := make([]byte, Ed.PublicKeySize)
	for i, b := range pk.Pk {
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

// Public Key Hash
func (pk *PublicKey) Hash() []byte {
	return pk.hash
}

// MarshalBinary marshals a PublicKey into a byte array
func (pk *PublicKey) MarshalBinary(comment string) ([]byte, error) {
	b64 := base64.StdEncoding.EncodeToString
	spk := &serializedPubKey{
		Comment: comment,
		Pk:      b64(pk.Pk),
		Hash:    b64(pk.hash),
	}

	return yaml.Marshal(spk)
}

// UnmarshalBinary constructs a PublicKey from a previously
// marshaled byte stream instance. In addition, it is also
// capable of parsing an OpenSSH ed25519 public key.
func (pk *PublicKey) UnmarshalBinary(yml []byte) error {

	// first try to parse as a ssh key
	if xk, err := parseSSHPublicKey(yml); err == nil {
		*pk = *xk
		return nil
	}

	// OK Yaml it is.

	var spk serializedPubKey
	var err error

	if err = yaml.Unmarshal(yml, &spk); err != nil {
		return fmt.Errorf("can't parse YAML: %s", err)
	}

	if len(spk.Pk) == 0 {
		return fmt.Errorf("sign: not a YAML public key")
	}

	b64 := base64.StdEncoding.DecodeString
	var pkb []byte

	if pkb, err = b64(spk.Pk); err != nil {
		return fmt.Errorf("can't decode YAML:Pk: %s", err)
	}

	return makePublicKeyFromBytes(pk, pkb)
}

// -- Internal Utility Functions --

func clamp(k []byte) []byte {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}

// EOF
// vim: noexpandtab:ts=8:sw=8:tw=92:
