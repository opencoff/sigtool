// wrap.go - wrap keys and sender as needed
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

package pb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

const (
	WrapReceiverNonce = "Receiver PK"
	WrapSenderNonce   = "Sender PK"
)

// Wrap sender's PK with the data encryption key
func WrapSenderPK(pk []byte, k, salt []byte) ([]byte, error) {
	aes, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("wrap: %s", err)
	}

	nonce := MakeNonce([]byte(WrapSenderNonce), salt)
	buf := make([]byte, ae.Overhead()+len(pk))
	out := ae.Seal(buf[:0], nonce[:ae.NonceSize()], pk, nil)
	return out, nil
}

// Given a wrapped PK of sender 's', unwrap it using the given key and salt
func (s *Sender) UnwrapPK(k, salt []byte) ([]byte, error) {
	aes, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("uwrap-sender: %s", err)
	}

	ae, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("unwrap-sender: %s", err)
	}

	nonce := MakeNonce([]byte(WrapSenderNonce), salt)
	want := 32 + ae.Overhead()
	if len(s.Pk) != want {
		return nil, fmt.Errorf("unwrap-sender: incorrect decrypt bytes (need %d, saw %d)", want, 32)
	}

	out := make([]byte, 32)
	pk, err := ae.Open(out[:0], nonce[:ae.NonceSize()], s.Pk, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap-sender: %s", err)
	}

	return pk, nil
}

func MakeNonce(v ...[]byte) []byte {
	h := sha256.New()
	for _, x := range v {
		h.Write(x)
	}
	return h.Sum(nil)[:]
}

func Clamp(k []byte) []byte {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}

func Randread(b []byte) []byte {
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(fmt.Sprintf("can't read %d bytes of random data: %s", len(b), err))
	}
	return b
}
