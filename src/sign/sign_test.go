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
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"testing"
	// module under test
	//"github.com/sign"
)

func newAsserter(t *testing.T) func(cond bool, msg string, args ...interface{}) {
	return func(cond bool, msg string, args ...interface{}) {
		if cond {
			return
		}

		_, file, line, ok := runtime.Caller(1)
		if !ok {
			file = "???"
			line = 0
		}

		s := fmt.Sprintf(msg, args...)
		t.Fatalf("%s: %d: Assertion failed: %s\n", file, line, s)
	}
}

// Return true if two byte arrays are equal
func byteEq(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

// Return a temp dir in a temp-dir
func tempdir(t *testing.T) string {
	assert := newAsserter(t)

	var b [10]byte

	dn := os.TempDir()
	rand.Read(b[:])

	tmp := path.Join(dn, fmt.Sprintf("%x", b[:]))
	err := os.MkdirAll(tmp, 0755)
	assert(err == nil, fmt.Sprintf("mkdir -p %s: %s", tmp, err))

	//t.Logf("Tempdir is %s", tmp)
	return tmp
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
func Test0(t *testing.T) {
	assert := newAsserter(t)

	kp, err := NewKeypair()
	assert(err == nil, "NewKeyPair() fail")

	dn := tempdir(t)
	bn := fmt.Sprintf("%s/t0", dn)

	err = kp.Serialize(bn, "", "abc")
	assert(err == nil, "keyPair.Serialize() fail")

	pkf := fmt.Sprintf("%s.pub", bn)
	skf := fmt.Sprintf("%s.key", bn)

	// We must find these two files
	assert(fileExists(pkf), "missing pkf")
	assert(fileExists(skf), "missing skf")

	// send wrong file and see what happens
	pk, err := ReadPublicKey(skf)
	assert(err != nil, "bad PK ReadPK fail")

	pk, err = ReadPublicKey(pkf)
	assert(err == nil, "ReadPK() fail")

	// -ditto- for Sk
	sk, err := ReadPrivateKey(pkf, "")
	assert(err != nil, "bad SK ReadSK fail")

	sk, err = ReadPrivateKey(skf, "")
	assert(err != nil, "ReadSK() empty pw fail")

	sk, err = ReadPrivateKey(skf, "abcdef")
	assert(err != nil, "ReadSK() wrong pw fail")

	badf := fmt.Sprintf("%s/badf.key", dn)
	err = ioutil.WriteFile(badf, []byte(badsk), 0600)
	assert(err == nil, "write badsk")

	sk, err = ReadPrivateKey(badf, "abc")
	assert(err != nil, "badsk read fail")

	// Finally, with correct password it should work.
	sk, err = ReadPrivateKey(skf, "abc")
	assert(err == nil, "ReadSK() correct pw fail")

	// And, deserialized keys should be identical
	assert(byteEq(pk.Pk, kp.Pub.Pk), "pkbytes unequal")
	assert(byteEq(sk.Sk, kp.Sec.Sk), "skbytes unequal")

	os.RemoveAll(dn)
}

// #2. Create new key pair, sign a rand buffer and verify
func Test1(t *testing.T) {
	assert := newAsserter(t)
	kp, err := NewKeypair()
	assert(err == nil, "NewKeyPair() fail")

	var ck [64]byte // simulates sha512 sum

	rand.Read(ck[:])

	pk := &kp.Pub
	sk := &kp.Sec

	ss, err := sk.SignMessage(ck[:], "")
	assert(err == nil, "sk.sign fail")
	assert(ss != nil, "sig is null")

	// verify sig
	assert(ss.IsPKMatch(pk), "pk match fail")

	// Corrupt the pkhash and see
	rand.Read(ss.pkhash[:])
	assert(!ss.IsPKMatch(pk), "corrupt pk match fail")

	// Incorrect checksum == should fail verification
	ok, err := pk.VerifyMessage(ck[:16], ss)
	assert(err == nil, "bad ck verify err fail")
	assert(!ok, "bad ck verify fail")

	// proper checksum == should work
	ok, err = pk.VerifyMessage(ck[:], ss)
	assert(err == nil, "verify err")
	assert(ok, "verify fail")

	// Now sign a file
	dn := tempdir(t)
	bn := fmt.Sprintf("%s/k", dn)

	pkf := fmt.Sprintf("%s.pub", bn)
	skf := fmt.Sprintf("%s.key", bn)

	err = kp.Serialize(bn, "", "")
	assert(err == nil, "keyPair.Serialize() fail")

	// Now read the private key and sign
	sk, err = ReadPrivateKey(skf, "")
	assert(err == nil, "readSK fail")

	pk, err = ReadPublicKey(pkf)
	assert(err == nil, "ReadPK fail")

	var buf [8192]byte

	zf := fmt.Sprintf("%s/file.dat", dn)
	fd, err := os.OpenFile(zf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	assert(err == nil, "file.dat creat file")

	for i := 0; i < 8; i++ {
		rand.Read(buf[:])
		n, err := fd.Write(buf[:])
		assert(err == nil, fmt.Sprintf("file.dat write fail: %s", err))
		assert(n == 8192, fmt.Sprintf("file.dat i/o fail: exp 8192 saw %v", n))
	}
	fd.Sync()
	fd.Close()

	sig, err := sk.SignFile(zf)
	assert(err == nil, "file.dat sign fail")
	assert(sig != nil, "file.dat sign nil")

	ok, err = pk.VerifyFile(zf, sig)
	assert(err == nil, "file.dat verify fail")
	assert(ok, "file.dat verify false")

	// Now, serialize the signature and read it back
	sf := fmt.Sprintf("%s/file.sig", dn)
	err = sig.SerializeFile(sf, "")
	assert(err == nil, "sig serialize fail")

	s2, err := ReadSignature(sf)
	assert(err == nil, "file.sig read fail")
	assert(s2 != nil, "file.sig sig nil")

	assert(byteEq(s2.Sig, sig.Sig), "sig compare fail")

	// If we give a wrong file, verify must fail
	st, err := os.Stat(zf)
	assert(err == nil, "file.dat stat fail")

	n := st.Size()
	assert(n == 8192*8, "file.dat size fail")

	os.Truncate(zf, n-1)

	st, err = os.Stat(zf)
	assert(err == nil, "file.dat stat2 fail")
	assert(st.Size() == (n-1), "truncate fail")

	// Now verify this corrupt file
	ok, err = pk.VerifyFile(zf, sig)
	assert(err == nil, "file.dat corrupt i/o fail")
	assert(!ok, "file.dat corrupt verify false")

	os.RemoveAll(dn)
}


func Benchmark_Keygen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewKeypair()
	}
}


func Benchmark_Sig(b *testing.B) {
	var sizes = [...]uint{
		16,
		32,
		64,
	}

	b.StopTimer()
	kp, _ := NewKeypair()
	var sig *Signature
	for _, sz := range sizes {
		buf := randbuf(sz)
		s0 := fmt.Sprintf("%d byte sign", sz)
		s1 := fmt.Sprintf("%d byte verify", sz)

		b.ResetTimer()

		b.Run(s0, func (b *testing.B) {
			sig = benchSign(b, buf, &kp.Sec)
		})

		b.Run(s1, func (b *testing.B) {
			benchVerify(b, buf, sig, &kp.Pub)
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
	rand.Read(b)
	return b
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
