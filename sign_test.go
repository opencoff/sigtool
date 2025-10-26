// sign_test.go -- Test harness for sign
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
	"crypto/sha512"
	"fmt"
	"os"
	"path"
	"testing"
)

// Return a temp dir in a temp-dir
func tempdir(t *testing.T) string {
	assert := newAsserter(t)

	var b [10]byte

	dn := os.TempDir()
	randRead(b[:])

	tmp := path.Join(dn, fmt.Sprintf("%x", b[:]))
	err := os.MkdirAll(tmp, 0755)
	assert(err == nil, fmt.Sprintf("mkdir -p %s: %s", tmp, err))

	//t.Logf("Tempdir is %s", tmp)
	return tmp
}

func TestSignRandBuf(t *testing.T) {
	assert := newAsserter(t)

	sk, err := NewPrivateKey(t.Name())
	assert(err == nil, "NewPrivateKey() fail: %s", err)

	var ck [sha512.Size]byte // simulates sha512 sum

	randRead(ck[:])

	sig, err := sk.SignMessage(ck[:])
	assert(err == nil, "sign: %s", err)

	pk := sk.PublicKey()

	ok, err := pk.VerifyMessage(ck[:], sig)
	assert(err == nil, "verify: %s", err)
	assert(ok, "verify: failed")

	// generate a random sig and see it fail
	sig = randSig()
	ok, err = pk.VerifyMessage(ck[:], sig)
	assert(err != nil, "verify: bad sig accepted")
	assert(!ok, "verify: bad sig worked")

	// corrupt the checksum and fail
	randRead(ck[:])
	ok, err = pk.VerifyMessage(ck[:], sig)
	assert(err != nil, "verify: bad cksum accepted")
	assert(!ok, "verify: bad cksum worked")

	// Now sign a file
	dn := t.TempDir()

	var buf [4096]byte

	zf := fmt.Sprintf("%s/file.dat", dn)
	fd, err := os.OpenFile(zf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	assert(err == nil, "file.dat creat file: %s", err)

	sz := int(randu32() & 0xfffff)
	filesz := int64(sz)

	for sz > 0 {
		want := min(sz, len(buf))
		b := randRead(buf[:want])
		n, err := fd.Write(b)
		assert(err == nil, fmt.Sprintf("file.dat write fail: %s", err))
		assert(n == want, fmt.Sprintf("file.dat i/o fail: exp %d saw %v", want, n))
		sz -= n
	}
	fd.Sync()
	fd.Close()

	sig, err = sk.SignFile(zf)
	assert(err == nil, "file.dat sign fail: %s", err)
	assert(sig != "", "file.dat sign nil")

	ok, err = pk.VerifyFile(zf, sig)
	assert(err == nil, "file.dat verify fail: %s", err)
	assert(ok, "file.dat verify false")

	// If we give a wrong file, verify must fail
	st, err := os.Stat(zf)
	assert(err == nil, "file.dat stat fail: %s", err)

	n := st.Size()
	assert(n == filesz, "file.dat size fail; exp %d, saw %d", filesz, n)

	os.Truncate(zf, n-1)

	st, err = os.Stat(zf)
	assert(err == nil, "file.dat stat2 fail: %s", err)
	assert(st.Size() == (n-1), "truncate fail")

	// Now verify this corrupt file
	ok, err = pk.VerifyFile(zf, sig)
	assert(err == nil, "file.dat corrupt i/o fail: %s", err)
	assert(!ok, "file.dat corrupt verify false")

	os.RemoveAll(dn)
}

func Benchmark_Sig(b *testing.B) {
	var sizes = [...]int{
		16,
		32,
		64,
		1024,
		4096,
		256 * 1024,
		1048576,
		4 * 1048576,
	}

	b.StopTimer()
	sk, _ := NewPrivateKey("bench-sig")
	pk := sk.PublicKey()
	var sig string
	for _, sz := range sizes {
		buf := randBuf(sz)
		s0 := fmt.Sprintf("%d byte sign", sz)
		s1 := fmt.Sprintf("%d byte verify", sz)

		b.ResetTimer()

		b.Run(s0, func(b *testing.B) {
			sig = benchSign(b, buf, sk)
		})

		b.Run(s1, func(b *testing.B) {
			benchVerify(b, buf, sig, pk)
		})
	}
}

func benchSign(b *testing.B, buf []byte, sk *PrivateKey) (sig string) {
	for i := 0; i < b.N; i++ {
		sig, _ = sk.SignMessage(buf)
	}
	return sig
}

func benchVerify(b *testing.B, buf []byte, sig string, pk *PublicKey) {
	for i := 0; i < b.N; i++ {
		pk.VerifyMessage(buf, sig)
	}
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
