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
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"strings"
)

// A File-encryption-key wrapped by the Ed25519 public key of the recipient
type WrappedKey struct {
	Key    []byte // KEK - wrapped with the Curve25519 PK of recipient
	Pk     []byte // Curve25519 PK used to wrap
	PkHash []byte // hash of the corresponding Ed25519 PK
}

func hx(b []byte) string {
	return hex.EncodeToString(b)
}

func unhx(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func (w *WrappedKey) ToString() string {
	return fmt.Sprintf("(ed25519 to=%x, pk=%x, kek=%x)",
		hx(w.PkHash), hx(w.Pk), hx(w.Key))
}

func parseErr(s string, v ...interface{}) error {
	return fmt.Errorf(s, v...)
}

// Given an marshalled stream of bytes, return the PubKey, encrypted key
func ParseWrappedKey(s string) (*WrappedKey, error) {
	s = strings.TrimSpace(s)
	if s[0] != '(' {
		return nil, parseErr("missing '(' in wrapped key")
	}

	if s[len(s)-1] != ')' {
		return nil, parseErr("missing ')' in wrapped key")
	}

	s = s[1 : len(s)-1]
	v := strings.Fields(s)
	if len(v) != 3 {
		return nil, parseErr("Incorrect number of elements (exp 3, saw %d) in wrapped key", len(v))
	}

	var w WrappedKey

	for _, z := range v {
		kw := strings.Split(z, "=")
		if len(kw) != 2 {
			return nil, parseErr("malformed key=value pair (%s) in wrapped key", z)
		}

		var err error
		switch strings.ToLower(kw[0]) {
		case "to":
			w.PkHash, err = unhx(kw[1])

		case "pk":
			w.Pk, err = unhx(kw[1])

		case "kek":
			w.Key, err = unhx(kw[1])

		default:
			return nil, parseErr("unknown keyword %s in wrapped key", kw[0])
		}

		if err != nil {
			return nil, parseErr("can't parse value for %s in wrapped key", kw[0])
		}
	}

	if len(w.PkHash) != 16 {
		return nil, parseErr("invalid PkHash length (exp 16, saw %d) in wrapped key", len(w.PkHash))
	}

	if len(w.Pk) != 32 {
		return nil, parseErr("invalid Public Key length (exp 32, saw %d) in wrapped key", len(w.Pk))
	}

	if len(w.Key) != 32 {
		return nil, parseErr("invalid Key length (exp 32, saw %d) in wrapped key", len(w.Key))
	}

	return &w, nil
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

	// hkdf or HMAC-sha-256
	kek, err := expand(shared[:], pk.Pk)
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	ek, err := aeadSeal(k, kek)
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	return &WrappedKey{
		Key:    ek,
		Pk:     theirPK,
		PkHash: pk.hash,
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

func aeadSeal(data, key []byte) ([]byte, error) {
	var salt [32]byte
	var nonceb [64]byte

	randread(salt[:])

	h := sha512.New()
	h.Write(salt[:])
	h.Write(key)
	nonce := h.Sum(nonceb[:0])[:32]

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ae, err := cipher.NewGCMWithNonceSize(aes, len(nonce))
	if err != nil {
		return nil, err
	}

	c := ae.Seal(nil, nonce, data, nil)
	c = append(c, salt[:]...)
	return c, nil
}

func aeadOpen(data, key []byte) ([]byte, error) {
	var nonceb [64]byte
	// GCM tag: 16 bytes
	// salt: 32 bytes
	// last 32 bytes: salt

	n := len(data)
	if n < (32 + 16) {
		return nil, fmt.Errorf("aead: too few decrypt bytes (min 48, saw %d)", n)
	}

	salt := data[n-32:]
	data = data[:n-32]

	h := sha512.New()
	h.Write(salt)
	h.Write(key)
	nonce := h.Sum(nonceb[:0])[:32]

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ae, err := cipher.NewGCMWithNonceSize(aes, len(nonce))
	if err != nil {
		return nil, err
	}

	c, err := ae.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func clamp(k []byte) []byte {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}
