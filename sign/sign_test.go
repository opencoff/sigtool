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

package sign

import (
	"fmt"
	"io/ioutil"
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

var fixedPw = []byte("abc")
var badPw = []byte("def")
var nilPw []byte

// return a hardcoded password
func hardcodedPw() ([]byte, error) {
	return fixedPw, nil
}

func wrongPw() ([]byte, error) {
	return badPw, nil
}
func emptyPw() ([]byte, error) {
	return nilPw, nil
}

// Return true if file exists, false otherwise
func fileExists(fn string) bool {
	st, err := os.Stat(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		return false
	}

	if st.Mode().IsRegular() {
		return true
	}
	return false
}

const badsk string = `
esk: q8AP3/6C5F0zB8CLiuJsidx2gJYmrnyOmuoazEbKL5Uh+Jn/Zgw85fTbYfhjcbt48CJejBzsgPYRYR7wWECFRA==
salt: uIdTQZotfnkaLkth9jsHvoQKMWdNZuE7dgVNADrRoeY=
algo: scrypt-sha256
verify: AOFLLC6h29+mvstWtMU1/zZFwHLBMMiI4mlW9DHpYdM=
Z: 65536
r: 8
p: 1
`

// #1. Create new key pair, and read them back.
func TestSignSimple(t *testing.T) {
	assert := newAsserter(t)

	sk, err := NewPrivateKey()
	assert(err == nil, "NewPrivateKey() fail")

	pk := sk.PublicKey()

	dn := t.TempDir()
	bn := fmt.Sprintf("%s/t0", dn)

	pkf := fmt.Sprintf("%s.pub", bn)
	skf := fmt.Sprintf("%s.key", bn)

	err = pk.Serialize(pkf, "", true)
	assert(err == nil, "can't serialize pk %s", pkf)

	// try to overwrite
	err = pk.Serialize(pkf, "", false)
	assert(err != nil, "pk %s overwritten!", pkf)

	err = sk.Serialize(skf, "", true, fixedPw)
	assert(err == nil, "can't serialize sk %s", skf)

	err = sk.Serialize(skf, "", false, nilPw)
	assert(err != nil, "sk %s overwritten!", skf)

	// We must find these two files
	assert(fileExists(pkf), "missing pkf %s", pkf)
	assert(fileExists(skf), "missing skf %s", skf)

	npk, err := ReadPublicKey(pkf)
	assert(err == nil, "ReadPK() fail")

	// send the public key as private key
	nsk, err := ReadPrivateKey(pkf, emptyPw)
	assert(err != nil, "bad SK ReadSK fail: %s", err)

	nsk, err = ReadPrivateKey(skf, emptyPw)
	assert(err != nil, "ReadSK() worked with empty pw")

	nsk, err = ReadPrivateKey(skf, wrongPw)
	assert(err != nil, "ReadSK() worked with wrong pw")

	badf := fmt.Sprintf("%s/badf.key", dn)
	err = ioutil.WriteFile(badf, []byte(badsk), 0600)
	assert(err == nil, "can't write badsk: %s", err)

	nsk, err = ReadPrivateKey(badf, hardcodedPw)
	assert(err != nil, "decoded bad SK")

	// Finally, with correct password it should work.
	nsk, err = ReadPrivateKey(skf, hardcodedPw)
	assert(err == nil, "ReadSK() correct pw fail: %s", err)

	// And, deserialized keys should be identical
	assert(byteEq(pk.Pk, npk.Pk), "pkbytes unequal")
	assert(byteEq(sk.Sk, nsk.Sk), "skbytes unequal")
}

// #2. Create new key pair, sign a rand buffer and verify
func TestSignRandBuf(t *testing.T) {
	assert := newAsserter(t)

	sk, err := NewPrivateKey()
	assert(err == nil, "NewPrivateKey() fail: %s", err)

	var ck [64]byte // simulates sha512 sum

	randRead(ck[:])

	pk := sk.PublicKey()

	ss, err := sk.SignMessage(ck[:], "")
	assert(err == nil, "sk.sign fail: %s", err)
	assert(ss != nil, "sig is null")

	// verify sig
	assert(ss.IsPKMatch(pk), "pk match fail")

	// Corrupt the pkhash and see
	randRead(ss.pkhash)
	assert(!ss.IsPKMatch(pk), "corrupt pk match fail")

	// Incorrect checksum == should fail verification
	ok := pk.VerifyMessage(ck[:16], ss)
	assert(!ok, "bad ck verify fail")

	// proper checksum == should work
	ok = pk.VerifyMessage(ck[:], ss)
	assert(ok, "verify fail")

	// Now sign a file
	dn := t.TempDir()

	var buf [8192]byte

	zf := fmt.Sprintf("%s/file.dat", dn)
	fd, err := os.OpenFile(zf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	assert(err == nil, "file.dat creat file: %s", err)

	for i := 0; i < 8; i++ {
		randRead(buf[:])
		n, err := fd.Write(buf[:])
		assert(err == nil, fmt.Sprintf("file.dat write fail: %s", err))
		assert(n == 8192, fmt.Sprintf("file.dat i/o fail: exp 8192 saw %v", n))
	}
	fd.Sync()
	fd.Close()

	sig, err := sk.SignFile(zf)
	assert(err == nil, "file.dat sign fail: %s", err)
	assert(sig != nil, "file.dat sign nil")

	ok, err = pk.VerifyFile(zf, sig)
	assert(err == nil, "file.dat verify fail: %s", err)
	assert(ok, "file.dat verify false")

	// Now, serialize the signature and read it back
	sf := fmt.Sprintf("%s/file.sig", dn)
	err = sig.Serialize(sf, "", true)
	assert(err == nil, "sig serialize fail: %s", err)

	// now try to overwrite it
	err = sig.Serialize(sf, "", false)
	assert(err != nil, "sig serialize overwrote?!")

	s2, err := ReadSignature(sf)
	assert(err == nil, "file.sig read fail: %s", err)
	assert(s2 != nil, "file.sig sig nil")

	assert(byteEq(s2.Sig, sig.Sig), "sig compare fail")

	// If we give a wrong file, verify must fail
	st, err := os.Stat(zf)
	assert(err == nil, "file.dat stat fail: %s", err)

	n := st.Size()
	assert(n == 8192*8, "file.dat size fail")

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

func Benchmark_Keygen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewPrivateKey()
	}
}

func Benchmark_Sig(b *testing.B) {
	var sizes = [...]uint{
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
	sk, _ := NewPrivateKey()
	pk := sk.PublicKey()
	var sig *Signature
	for _, sz := range sizes {
		buf := randbuf(sz)
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

func benchSign(b *testing.B, buf []byte, sk *PrivateKey) (sig *Signature) {
	for i := 0; i < b.N; i++ {
		sig, _ = sk.SignMessage(buf, "")
	}
	return sig
}

func benchVerify(b *testing.B, buf []byte, sig *Signature, pk *PublicKey) {
	for i := 0; i < b.N; i++ {
		pk.VerifyMessage(buf, sig)
	}
}

func randbuf(sz uint) []byte {
	b := make([]byte, sz)
	randRead(b)
	return b
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
