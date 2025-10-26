// keys_test.go -- Test harness for keys
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

package sigtool

import (
	"testing"
)

var goodPw = []byte("abc")
var badPw = []byte("def")
var nilPw []byte

// return a hardcoded password
func fixedPw() ([]byte, error) {
	return goodPw, nil
}

func wrongPw() ([]byte, error) {
	return badPw, nil
}
func emptyPw() ([]byte, error) {
	return nilPw, nil
}

func TestKeysMarshal(t *testing.T) {
	assert := newAsserter(t)

	sk, err := NewPrivateKey(t.Name())
	assert(err == nil, "NewPrivateKey() fail: %s", err)

	skb, err := sk.Marshal(fixedPw)
	assert(err == nil, "marshal sk: %s", err)
	assert(skb != nil, "marshal sk: nil bytes")

	sk2, err := ParsePrivateKey(skb, wrongPw)
	assert(err != nil, "unmarshal sk: wrong pw accepted")
	assert(sk2 == nil, "unmarshal sk: wrong pw worked")

	sk2, err = ParsePrivateKey(skb, fixedPw)
	assert(err == nil, "unmarshal sk: %s", err)
	assert(sk2 != nil, "unmarshal sk: nil sk2")

	assert(sk.Equal(sk2), "unmarshal: unequal keys")

	pk := sk.PublicKey()
	pkb, err := pk.Marshal()
	assert(err == nil, "marshal pk: %s", err)
	assert(pkb != nil, "marshal pk: nil bytes")

	pk2, err := ParsePublicKey(pkb)
	assert(err == nil, "unmarshal pk: %s", err)
	assert(pk2 != nil, "unmarshal pk: nil pk2")
	assert(pk.Equal(pk2), "unmarshal pk: unequal keys")
}

func Benchmark_Keygen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewPrivateKey("bench-key")
	}
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
