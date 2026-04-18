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
	"errors"
	"testing"

	"github.com/opencoff/sigtool/internal/pb"
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

// TestValidateArgonParams exercises every rejection branch of the KDF
// parameter gate. These parameters come from an attacker-supplied PEM, so
// validation is the first line of defence against DoS via crafted Argon
// params — fuzzing proved that a malformed Time=0 otherwise panics inside
// x/crypto/argon2.
func TestValidateArgonParams(t *testing.T) {
	assert := newAsserter(t)

	good := func() *pb.Argon {
		return &pb.Argon{
			Time: _Argon2id_time,
			Mem:  _Argon2id_mem,
			Proc: _Argon2id_proc,
			Salt: make([]byte, 32),
		}
	}

	// Baseline: the good params must validate.
	assert(validateArgonParams(good()) == nil, "good params should validate")

	// nil input
	assert(errors.Is(validateArgonParams(nil), ErrBadKDFParams), "nil accepted")

	cases := []struct {
		name   string
		mutate func(a *pb.Argon)
	}{
		{"time=0", func(a *pb.Argon) { a.Time = 0 }},
		{"time=too-big", func(a *pb.Argon) { a.Time = _Argon_maxTime + 1 }},
		{"mem=0", func(a *pb.Argon) { a.Mem = 0 }},
		{"mem=too-big", func(a *pb.Argon) { a.Mem = _Argon_maxMem + 1 }},
		{"proc=0", func(a *pb.Argon) { a.Proc = 0 }},
		{"proc=too-big", func(a *pb.Argon) { a.Proc = _Argon_maxProc + 1 }},
		{"salt=empty", func(a *pb.Argon) { a.Salt = nil }},
		{"salt=too-short", func(a *pb.Argon) { a.Salt = make([]byte, _Argon_minSalt-1) }},
		{"salt=too-long", func(a *pb.Argon) { a.Salt = make([]byte, _Argon_maxSalt+1) }},
	}

	for _, c := range cases {
		a := good()
		c.mutate(a)
		err := validateArgonParams(a)
		assert(errors.Is(err, ErrBadKDFParams), "%s: expected ErrBadKDFParams, got %v", c.name, err)
	}
}

func Benchmark_Keygen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewPrivateKey("bench-key")
	}
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
