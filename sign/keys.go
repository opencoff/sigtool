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
	"encoding/binary"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	"os"

	Ed "crypto/ed25519"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/yaml.v2"

	"github.com/opencoff/go-utils"
	"github.com/opencoff/sigtool/internal/pb"
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

// Ed25519 key pair
type Keypair struct {
	Sec PrivateKey
	Pub PublicKey
}

// An Ed25519 Signature
type Signature struct {
	Sig    []byte // Ed25519 sig bytes
	pkhash []byte // [0:16] SHA256 hash of public key needed for verification
}

// Length of Ed25519 Public Key Hash
const PKHashLength = 16

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

func pkhash(pk []byte) []byte {
	z := sha256.Sum256(pk)
	return z[:PKHashLength]
}

// Generate a new Ed25519 keypair
func NewKeypair() (*Keypair, error) {
	//kp := &Keypair{Sec: PrivateKey{N: 1 << 17, r: 64, p: 1}}
	kp := &Keypair{}
	sk := &kp.Sec
	pk := &kp.Pub
	sk.pk = pk

	p, s, err := Ed.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Can't generate Ed25519 keys: %s", err)
	}

	pk.Pk = []byte(p)
	sk.Sk = []byte(s)
	pk.hash = pkhash(pk.Pk)

	return kp, nil
}

// Serialize the keypair to two separate files. The basename of the
// file is 'bn'; the public key goes in $bn.pub and the private key
// goes in $bn.key.
// If password is non-empty, then the private key is encrypted
// before writing to disk.
func (kp *Keypair) Serialize(bn, comment string, getpw func() ([]byte, error)) error {

	sk := &kp.Sec
	pk := &kp.Pub

	skf := fmt.Sprintf("%s.key", bn)
	pkf := fmt.Sprintf("%s.pub", bn)

	err := pk.serialize(pkf, comment)
	if err != nil {
		return fmt.Errorf("Can't serialize to %s: %s", pkf, err)
	}

	err = sk.serialize(skf, comment, getpw)
	if err != nil {
		return fmt.Errorf("Can't serialize to %s: %s", pkf, err)
	}

	return nil
}

// Read the private key in 'fn', optionally decrypting it using
// password 'pw' and create new instance of PrivateKey
func ReadPrivateKey(fn string, getpw func() ([]byte, error)) (*PrivateKey, error) {
	yml, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	if bytes.Index(yml, []byte("OPENSSH PRIVATE KEY-")) > 0 {
		return parseSSHPrivateKey(yml, getpw)
	}

	if pw, err := getpw(); err == nil {
		return MakePrivateKey(yml, pw)
	}
	return nil, err
}

// Make a private key from bytes 'yml' and password 'pw'. The bytes
// are assumed to be serialized version of the private key.
func MakePrivateKey(yml []byte, pw []byte) (*PrivateKey, error) {
	var ssk serializedPrivKey

	err := yaml.Unmarshal(yml, &ssk)
	if err != nil {
		return nil, fmt.Errorf("make priv key: can't parse YAML: %s", err)
	}

	if len(ssk.Salt) == 0 || len(ssk.Esk) == 0 {
		return nil, fmt.Errorf("sign: not YAML private key")
	}

	b64 := base64.StdEncoding.DecodeString

	salt, err := b64(ssk.Salt)
	if err != nil {
		return nil, fmt.Errorf("make priv key: can't decode salt: %s", err)
	}

	esk, err := b64(ssk.Esk)
	if err != nil {
		return nil, fmt.Errorf("make priv key: can't decode key: %s", err)
	}

	// We take short passwords and extend them
	pwb := sha512.Sum512(pw)

	// "32" == Length of AES-256 key
	key, err := scrypt.Key(pwb[:], salt, ssk.N, ssk.R, ssk.P, 32)
	if err != nil {
		return nil, fmt.Errorf("make priv key: can't derive key: %s", err)
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("make priv key: aes failure: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("make priv key: aes failure: %s", err)
	}

	skb, err := ae.Open(nil, salt[:ae.NonceSize()], esk, nil)
	if err != nil {
		return nil, fmt.Errorf("make priv key: wrong password")
	}

	return PrivateKeyFromBytes(skb)
}

// Make a private key from 64-bytes of extended Ed25519 key
func PrivateKeyFromBytes(buf []byte) (*PrivateKey, error) {
	if len(buf) != 64 {
		return nil, fmt.Errorf("private key is malformed (len %d!)", len(buf))
	}

	skb := make([]byte, 64)
	copy(skb, buf)

	edsk := Ed.PrivateKey(skb)
	edpk := edsk.Public().(Ed.PublicKey)

	pk := &PublicKey{
		Pk:   []byte(edpk),
		hash: pkhash([]byte(edpk)),
	}
	sk := &PrivateKey{
		Sk: skb,
		pk: pk,
	}

	return sk, nil
}

// Given a secret key, return the corresponding Public Key
func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.pk
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

// Serialize the private key to a file
// AEAD encryption for protecting the private key
// Format: YAML
// All []byte are in base64 (RawEncoding)
func (sk *PrivateKey) serialize(fn, comment string, getpw func() ([]byte, error)) error {
	pw, err := getpw()
	if err != nil {
		return err
	}

	// expand the password into 64 bytes
	pass := sha512.Sum512(pw)
	salt := make([]byte, 32)

	pb.Randread(salt)

	// "32" == Length of AES-256 key
	key, err := scrypt.Key(pass[:], salt, _N, _r, _p, 32)
	if err != nil {
		return fmt.Errorf("marshal: can't derive scrypt key: %s", err)
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("marshal: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return fmt.Errorf("marshal: %s", err)
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

	out, err := yaml.Marshal(&ssk)
	if err != nil {
		return fmt.Errorf("can't marahal to YAML: %s", err)
	}

	return writeFile(fn, out, 0600)
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

	// first try to parse as a ssh key
	pk, err := parseSSHPublicKey(yml)
	if err != nil {
		pk, err = MakePublicKey(yml)
	}
	return pk, err
}

// Parse a serialized public in 'yml' and return the resulting
// public key instance
func MakePublicKey(yml []byte) (*PublicKey, error) {
	var spk serializedPubKey
	var err error

	if err = yaml.Unmarshal(yml, &spk); err != nil {
		return nil, fmt.Errorf("can't parse YAML: %s", err)
	}

	if len(spk.Pk) == 0 {
		return nil, fmt.Errorf("sign: not a YAML public key")
	}

	b64 := base64.StdEncoding.DecodeString
	var pkb []byte

	if pkb, err = b64(spk.Pk); err != nil {
		return nil, fmt.Errorf("can't decode YAML:Pk: %s", err)
	}

	if pk, err := PublicKeyFromBytes(pkb); err == nil {
		pk.Comment = spk.Comment
		return pk, nil
	}
	return nil, err
}

// Make a public key from a byte string
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("public key is malformed (len %d!)", len(b))
	}

	pk := &PublicKey{
		Pk:   make([]byte, 32),
		hash: pkhash(b),
	}

	copy(pk.Pk, b)
	return pk, nil
}

// Serialize Public Keys
func (pk *PublicKey) serialize(fn, comment string) error {
	b64 := base64.StdEncoding.EncodeToString
	spk := &serializedPubKey{
		Comment: comment,
		Pk:      b64(pk.Pk),
		Hash:    b64(pk.hash),
	}

	out, err := yaml.Marshal(spk)
	if err != nil {
		return fmt.Errorf("can't marahal to YAML: %s", err)
	}

	return writeFile(fn, out, 0644)
}

// -- Internal Utility Functions --

// Unlink a file.
func unlink(f string) {
	st, err := os.Stat(f)
	if err == nil {
		if !st.Mode().IsRegular() {
			panic(fmt.Sprintf("%s can't be unlinked. Not a regular file?", f))
		}

		os.Remove(f)
		return
	}
}

// Simple function to reliably write data to a file.
// Does MORE than ioutil.WriteFile() - in that it doesn't trash the
// existing file with an incomplete write.
func writeFile(fn string, b []byte, mode uint32) error {
	tmp := fmt.Sprintf("%s.tmp", fn)
	unlink(tmp)

	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(mode))
	if err != nil {
		return fmt.Errorf("Can't create file %s: %s", tmp, err)
	}

	_, err = fd.Write(b)
	if err != nil {
		fd.Close()
		// XXX Do we delete the tmp file?
		return fmt.Errorf("Can't write %v bytes to %s: %s", len(b), tmp, err)
	}

	fd.Close() // we ignore close(2) errors; unrecoverable anyway.

	os.Rename(tmp, fn)
	return nil
}

// Generate file checksum out of hash function h
func fileCksum(fn string, h hash.Hash) ([]byte, error) {

	fd, err := os.Open(fn)
	if err != nil {
		return nil, fmt.Errorf("can't open %s: %s", fn, err)
	}

	defer fd.Close()

	sz, err := utils.MmapReader(fd, 0, 0, h)
	if err != nil {
		return nil, err
	}

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(sz))
	h.Write(b[:])

	return h.Sum(nil), nil
}

func clamp(k []byte) []byte {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}

// EOF
// vim: noexpandtab:ts=8:sw=8:tw=92:
