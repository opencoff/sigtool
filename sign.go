// sign.go -- Ed25519 keys and signature handling
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
//   - sign/verify of files and byte strings

package sigtool

import (
	"crypto"
	"crypto/rand"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"

	Ed "crypto/ed25519"
)

const _Sigtool_sign_prefix = "sigtool signed message"

// Sigtool signatures are always of the form
//   fingerprint.signature

// Sign a prehashed Message; return the sigtool signature of the form
//
//	fingerprint.signature
func (sk *PrivateKey) SignMessage(msg []byte) (string, error) {
	var hb [sha512.Size]byte

	h := sha512.New()
	h.Write([]byte(_Sigtool_sign_prefix))
	h.Write(msg)
	ck := h.Sum(hb[:0])[:]

	x := Ed.PrivateKey(sk.sk)

	sig, err := x.Sign(rand.Reader, ck, crypto.Hash(0))
	if err != nil {
		return "", fmt.Errorf("can't sign %x: %s", ck, err)
	}

	ss := tob64(sig)
	return fmt.Sprintf("%s.%s", sk.Fingerprint(), ss), nil
}

// Read and sign a file
//
// We calculate the signature differently here: We first calculate
// the SHA-512 checksum of the file and its size. We sign the
// checksum.
func (sk *PrivateKey) SignFile(fn string) (string, error) {
	ck, err := fileCksum(fn, func() hash.Hash {
		return sha3.New512()
	})
	if err != nil {
		return "", err
	}

	return sk.SignMessage(ck)
}

// Verify a signature 'sig' for a pre-calculated checksum 'ck' against public key 'pk'
// Return True if signature matches, False otherwise
func (pk *PublicKey) VerifyMessage(ck []byte, signature string) (bool, error) {
	fp, sig, err := parseSig(signature)
	if err != nil {
		return false, fmt.Errorf("sigtool: verify %s: %w", signature, err)
	}

	if fp != pk.Fingerprint() {
		return false, fmt.Errorf("sigtool: verify %s: wrong PK %s", signature, fp)
	}

	return pk.verifySig(ck, sig), nil
}

// Verify a signature 'sig' for file 'fn' against public key 'pk'
// Return True if signature matches, False otherwise
func (pk *PublicKey) VerifyFile(fn string, signature string) (bool, error) {
	fp, sig, err := parseSig(signature)
	if err != nil {
		return false, fmt.Errorf("sigtool: verify %s: %w", signature, err)
	}

	if fp != pk.Fingerprint() {
		return false, fmt.Errorf("sigtool: verify %s: wrong PK %s", signature, fp)
	}

	ck, err := fileCksum(fn, func() hash.Hash {
		return sha3.New512()
	})
	if err != nil {
		return false, err
	}

	return pk.verifySig(ck, sig), nil
}

// verify the signature 'sig' for the message 'msg'
func (pk *PublicKey) verifySig(msg, sig []byte) bool {
	var hb [sha512.Size]byte

	h := sha512.New()
	h.Write([]byte(_Sigtool_sign_prefix))
	h.Write(msg)
	ck := h.Sum(hb[:0])[:]

	x := Ed.PublicKey(pk.pk)
	return Ed.Verify(x, ck, sig)
}

func tob64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func fromb64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func b64len(n int) int {
	return base64.RawURLEncoding.EncodedLen(n)
}

// Return the length in bytes of an encoded signature
func sigLen() int {
	return b64len(_FpSize) + 1 + b64len(Ed.SignatureSize)
}

// take a string representation of a sigtool signature and return the
// fingerprint and decoded signature bytes
func parseSig(ss string) (string, []byte, error) {
	i := strings.IndexByte(ss, '.')
	if i < 0 {
		return "", nil, fmt.Errorf("invalid signature format")
	}

	fp, rest := ss[:i], ss[i+1:]

	// fp and rest must be base64 decodable
	_, err := fromb64(fp)
	if err != nil {
		return "", nil, fmt.Errorf("invalid fingerprint")
	}

	sig, err := fromb64(rest)
	if err != nil {
		return "", nil, fmt.Errorf("invalid signature")
	}

	return fp, sig, nil
}

// make a raandom looking signature
func randSig() string {
	fp := randBuf(_FpSize)
	sig := randBuf(Ed.SignatureSize)

	return fmt.Sprintf("%s.%s", tob64(fp), tob64(sig))
}

// make a null/empty sig
func nullSig() string {
	var zfp [_FpSize]byte
	var zsig [Ed.SignatureSize]byte

	return fmt.Sprintf("%s.%s", tob64(zfp[:]), tob64(zsig[:]))
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
