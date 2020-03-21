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
//   - key generation, and key I/O
//   - sign/verify of files and byte strings

package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	Ed "crypto/ed25519"
	"gopkg.in/yaml.v2"
)

// Sign a prehashed Message; return the signature as opaque bytes
// Signature is an YAML file:
//    Comment: source file path
//    Signature: Ed25519 signature
func (sk *PrivateKey) SignMessage(ck []byte, comment string) (*Signature, error) {
	h := sha512.New()
	h.Write([]byte("sigtool signed message"))
	h.Write(ck)
	ck = h.Sum(nil)[:]

	x := Ed.PrivateKey(sk.Sk)
	sig, err := x.Sign(rand.Reader, ck, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("can't sign %x: %s", ck, err)
	}

	ss := &Signature{
		Sig:    sig,
		pkhash: make([]byte, len(sk.pk.hash)),
	}

	copy(ss.pkhash, sk.pk.hash)
	return ss, nil
}

// Read and sign a file
//
// We calculate the signature differently here: We first calculate
// the SHA-512 checksum of the file and its size. We sign the
// checksum.
func (sk *PrivateKey) SignFile(fn string) (*Signature, error) {

	ck, err := fileCksum(fn, sha512.New())
	if err != nil {
		return nil, err
	}

	return sk.SignMessage(ck, fn)
}

// -- Signature Methods --

// Read serialized signature from file 'fn' and construct a
// Signature object
func ReadSignature(fn string) (*Signature, error) {
	yml, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	return MakeSignature(yml)
}

// Parse serialized signature from bytes 'b' and construct a
// Signature object
func MakeSignature(b []byte) (*Signature, error) {
	var ss signature
	err := yaml.Unmarshal(b, &ss)
	if err != nil {
		return nil, fmt.Errorf("can't parse YAML signature: %s", err)
	}

	b64 := base64.StdEncoding.DecodeString

	s, err := b64(ss.Signature)
	if err != nil {
		return nil, fmt.Errorf("can't decode Base64:Signature <%s>: %s", ss.Signature, err)
	}

	p, err := b64(ss.Pkhash)
	if err != nil {
		return nil, fmt.Errorf("can't decode Base64:Pkhash <%s>: %s", ss.Pkhash, err)
	}

	return &Signature{Sig: s, pkhash: p}, nil
}

// Serialize a signature suitable for storing in durable media
func (sig *Signature) Serialize(comment string) ([]byte, error) {

	sigs := base64.StdEncoding.EncodeToString(sig.Sig)
	pks := base64.StdEncoding.EncodeToString(sig.pkhash)
	ss := &signature{Comment: comment, Pkhash: pks, Signature: sigs}

	out, err := yaml.Marshal(ss)
	if err != nil {
		return nil, fmt.Errorf("can't marshal signature of %x to YAML: %s", sig.Sig, err)
	}

	return out, nil
}

// SerializeFile serializes the signature to an output file 'f'
func (sig *Signature) SerializeFile(fn, comment string) error {
	b, err := sig.Serialize(comment)
	if err == nil {
		err = writeFile(fn, b, 0644)
	}
	return err
}

// IsPKMatch returns true if public key 'pk' can potentially validate
// the signature. It does this by comparing the hash of 'pk' against
// 'Pkhash' of 'sig'.
func (sig *Signature) IsPKMatch(pk *PublicKey) bool {
	return subtle.ConstantTimeCompare(pk.hash, sig.pkhash) == 1
}

// Verify a signature 'sig' for file 'fn' against public key 'pk'
// Return True if signature matches, False otherwise
func (pk *PublicKey) VerifyFile(fn string, sig *Signature) (bool, error) {

	ck, err := fileCksum(fn, sha512.New())
	if err != nil {
		return false, err
	}

	return pk.VerifyMessage(ck, sig)
}

// Verify a signature 'sig' for a pre-calculated checksum 'ck' against public key 'pk'
// Return True if signature matches, False otherwise
func (pk *PublicKey) VerifyMessage(ck []byte, sig *Signature) (bool, error) {
	h := sha512.New()
	h.Write([]byte("sigtool signed message"))
	h.Write(ck)
	ck = h.Sum(nil)[:]

	x := Ed.PublicKey(pk.Pk)
	return Ed.Verify(x, ck, sig.Sig), nil
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
