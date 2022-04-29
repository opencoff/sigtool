// crypt_test.go -- Test harness for encrypt/decrypt bits
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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

type Buffer struct {
	bytes.Buffer
}

func (b *Buffer) Close() error {
	return nil
}

// one sender, one receiver no verification of sender
func TestEncryptSimple(t *testing.T) {
	assert := newAsserter(t)

	sk, err := NewPrivateKey()
	assert(err == nil, "SK gen failed: %s", err)

	pk := sk.PublicKey()

	var blkSize int = 1024
	var size int = (blkSize * 10)

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	ee, err := NewEncryptor(nil, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.AddRecipient(pk)
	assert(err == nil, "can't add recipient: %s", err)

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	err = ee.Encrypt(rd, &wr)
	assert(err == nil, "encrypt fail: %s", err)

	rd = bytes.NewBuffer(wr.Bytes())

	dd, err := NewDecryptor(rd)
	assert(err == nil, "decryptor create fail: %s", err)

	err = dd.SetPrivateKey(sk, nil)
	assert(err == nil, "decryptor can't add SK: %s", err)

	wr = Buffer{}
	err = dd.Decrypt(&wr)
	assert(err == nil, "decrypt fail: %s", err)

	b := wr.Bytes()
	assert(len(b) == len(buf), "decrypt length mismatch: exp %d, saw %d", len(buf), len(b))

	assert(byteEq(b, buf), "decrypt content mismatch")
}

// one sender, one receiver - small blocks
func TestEncryptSmallSizes(t *testing.T) {
	assert := newAsserter(t)

	sk, err := NewPrivateKey()
	assert(err == nil, "SK gen failed: %s", err)

	pk := sk.PublicKey()

	var blkSize int = 8
	var size int = (blkSize * 4)

	// cleartext
	bigbuf := make([]byte, size)
	for i := 0; i < len(bigbuf); i++ {
		bigbuf[i] = byte(i & 0xff)
	}

	// encrypt progressively larger bufs
	for i := 1; i < len(bigbuf); i++ {
		buf := bigbuf[:i]

		ee, err := NewEncryptor(nil, uint64(blkSize))
		assert(err == nil, "encryptor-%d create fail: %s", i, err)

		err = ee.AddRecipient(pk)
		assert(err == nil, "encryptor-%d: can't add recipient: %s", i, err)

		rd := bytes.NewBuffer(buf)
		wr := Buffer{}

		err = ee.Encrypt(rd, &wr)
		assert(err == nil, "encrypt-%d fail: %s", i, err)

		rd = bytes.NewBuffer(wr.Bytes())

		dd, err := NewDecryptor(rd)
		assert(err == nil, "decryptor-%d create fail: %s", i, err)

		err = dd.SetPrivateKey(sk, nil)
		assert(err == nil, "decryptor-%d can't add SK: %s", i, err)

		wr = Buffer{}
		err = dd.Decrypt(&wr)
		assert(err == nil, "decrypt-%d fail: %s", i, err)

		b := wr.Bytes()
		assert(len(b) == len(buf), "decrypt-%d length mismatch: exp %d, saw %d", i, len(buf), len(b))

		assert(byteEq(b, buf), "decrypt-%d content mismatch", i)
	}
}

// test corrupted header or corrupted input
func TestEncryptCorrupted(t *testing.T) {
	assert := newAsserter(t)

	sk, err := NewPrivateKey()
	assert(err == nil, "SK gen failed: %s", err)

	pk := sk.PublicKey()

	var blkSize int = 1024
	var size int = (blkSize * 23) + randmod(blkSize)

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	ee, err := NewEncryptor(nil, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.AddRecipient(pk)
	assert(err == nil, "can't add recipient: %s", err)

	rd := bytes.NewReader(buf)
	wr := Buffer{}

	err = ee.Encrypt(rd, &wr)
	assert(err == nil, "encrypt fail: %s", err)

	rb := wr.Bytes()
	n := len(rb)

	// corrupt the input
	for i := 0; i < n; i++ {
		j := randint() % n
		rb[j] = byte(randint() & 0xff)
	}

	rd = bytes.NewReader(rb)
	dd, err := NewDecryptor(rd)
	assert(err != nil, "decryptor works on bad input")
	assert(dd == nil, "decryptor not nil for bad input")
}

// one sender, one receiver with verification of sender
func TestEncryptSenderVerified(t *testing.T) {
	assert := newAsserter(t)

	sender, err := NewPrivateKey()
	assert(err == nil, "sender SK gen failed: %s", err)

	receiver, err := NewPrivateKey()
	assert(err == nil, "receiver SK gen failed: %s", err)

	var blkSize int = 1024
	var size int = (blkSize * 23) + randmod(blkSize)

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	ee, err := NewEncryptor(sender, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.AddRecipient(receiver.PublicKey())
	assert(err == nil, "can't add recipient: %s", err)

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	err = ee.Encrypt(rd, &wr)
	assert(err == nil, "encrypt fail: %s", err)

	rd = bytes.NewBuffer(wr.Bytes())

	dd, err := NewDecryptor(rd)
	assert(err == nil, "decryptor create fail: %s", err)

	randkey, err := NewPrivateKey()
	assert(err == nil, "rand SK gen failed: %s", err)

	// first send a wrong sender PK
	err = dd.SetPrivateKey(receiver, randkey.PublicKey())
	assert(err != nil, "decryptor failed to verify sender")

	// then the correct sender PK
	err = dd.SetPrivateKey(receiver, sender.PublicKey())
	assert(err == nil, "decryptor can't add SK: %s", err)

	wr = Buffer{}
	err = dd.Decrypt(&wr)
	assert(err == nil, "decrypt fail: %s", err)

	b := wr.Bytes()
	assert(len(b) == len(buf), "decrypt length mismatch: exp %d, saw %d", len(buf), len(b))

	assert(byteEq(b, buf), "decrypt content mismatch")
}

// one sender, multiple receivers, each decrypting the blob
func TestEncryptMultiReceiver(t *testing.T) {
	assert := newAsserter(t)

	sender, err := NewPrivateKey()
	assert(err == nil, "sender SK gen failed: %s", err)

	var blkSize int = 1024
	var size int = (blkSize * 23) + randmod(blkSize)

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	ee, err := NewEncryptor(sender, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	n := 4
	rx := make([]*PrivateKey, n)
	for i := 0; i < n; i++ {
		r, err := NewPrivateKey()
		assert(err == nil, "can't make receiver SK %d: %s", i, err)
		rx[i] = r

		err = ee.AddRecipient(r.PublicKey())
		assert(err == nil, "can't add recipient %d: %s", i, err)
	}

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	err = ee.Encrypt(rd, &wr)
	assert(err == nil, "encrypt fail: %s", err)

	encBytes := wr.Bytes()
	for i := 0; i < n; i++ {
		rd = bytes.NewBuffer(encBytes)

		dd, err := NewDecryptor(rd)
		assert(err == nil, "decryptor %d create fail: %s", i, err)

		err = dd.SetPrivateKey(rx[i], sender.PublicKey())
		assert(err == nil, "decryptor can't add SK %d: %s", i, err)

		wr = Buffer{}
		err = dd.Decrypt(&wr)
		assert(err == nil, "decrypt %d fail: %s", i, err)

		b := wr.Bytes()
		assert(len(b) == len(buf), "decrypt %d length mismatch: exp %d, saw %d", i, len(buf), len(b))

		assert(byteEq(b, buf), "decrypt %d content mismatch", i)
	}
}

// Test stream write and read
func TestStreamIO(t *testing.T) {
	assert := newAsserter(t)

	receiver, err := NewPrivateKey()
	assert(err == nil, "receiver keypair gen failed: %s", err)

	var blkSize int = 1024
	var size int = (blkSize * 10)

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	ee, err := NewEncryptor(nil, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.AddRecipient(receiver.PublicKey())
	assert(err == nil, "can't add recipient: %s", err)

	wr := Buffer{}
	wio, err := ee.NewStreamWriter(&wr)
	assert(err == nil, "can't start stream writer: %s", err)

	// chunksize for writing to stream
	csize := 19
	rbuf := buf
	for len(rbuf) > 0 {
		m := csize
		if len(rbuf) < m {
			m = len(rbuf)
		}

		n, err := wio.Write(rbuf[:m])
		assert(err == nil, "stream write failed: %s", err)
		assert(n == m, "stream write mismatch: exp %d, saw %d", m, n)

		rbuf = rbuf[m:]
	}
	err = wio.Close()
	assert(err == nil, "stream close failed: %s", err)

	_, err = wio.Write(buf[:csize])
	assert(err != nil, "stream write accepted I/O after close: %s", err)

	rd := bytes.NewBuffer(wr.Bytes())

	dd, err := NewDecryptor(rd)
	assert(err == nil, "decryptor create fail: %s", err)

	err = dd.SetPrivateKey(receiver, nil)
	assert(err == nil, "decryptor can't add SK: %s", err)

	rio, err := dd.NewStreamReader()
	assert(err == nil, "stream reader failed: %s", err)

	rbuf = make([]byte, csize)
	wr = Buffer{}
	n := 0
	for {
		m, err := rio.Read(rbuf)
		assert(err == nil || err == io.EOF, "streamread fail: %s", err)

		if m > 0 {
			wr.Write(rbuf[:m])
			n += m
		}
		if err == io.EOF || m == 0 {
			break
		}
	}

	b := wr.Bytes()
	assert(n == len(b), "streamread: bad buflen; exp %d, saw %d", n, len(b))
	assert(n == len(buf), "streamread: decrypt len mismatch; exp %d, saw %d", len(buf), n)

	assert(byteEq(b, buf), "decrypt content mismatch")

}

// Test stream write and read with small sizes
func TestSmallSizeStreamIO(t *testing.T) {
	assert := newAsserter(t)

	receiver, err := NewPrivateKey()
	assert(err == nil, "receiver SK gen failed: %s", err)

	var blkSize int = 8
	var size int = blkSize * 10

	// cleartext
	bigbuf := make([]byte, size)
	for i := 0; i < len(bigbuf); i++ {
		bigbuf[i] = byte(i & 0xff)
	}

	for i := 1; i < len(bigbuf); i++ {
		buf := bigbuf[:i]
		t.Logf("small-size-stream: size %d, chunksize %d\n", i, blkSize)

		ee, err := NewEncryptor(nil, uint64(blkSize))
		assert(err == nil, "encryptor create fail: %s", err)

		err = ee.AddRecipient(receiver.PublicKey())
		assert(err == nil, "can't add recipient: %s", err)

		wr := Buffer{}
		wio, err := ee.NewStreamWriter(&wr)
		assert(err == nil, "can't start stream writer: %s", err)

		// chunksize for writing to stream
		csize := blkSize - 1
		rbuf := buf
		for len(rbuf) > 0 {
			m := csize
			if len(rbuf) < m {
				m = len(rbuf)
			}

			n, err := wio.Write(rbuf[:m])
			assert(err == nil, "stream write failed: %s", err)
			assert(n == m, "stream write mismatch: exp %d, saw %d", m, n)

			rbuf = rbuf[m:]
		}
		err = wio.Close()
		assert(err == nil, "stream close failed: %s", err)

		_, err = wio.Write(buf[:csize])
		assert(err != nil, "stream write accepted I/O after close: %s", err)

		rd := bytes.NewBuffer(wr.Bytes())

		dd, err := NewDecryptor(rd)
		assert(err == nil, "decryptor create fail: %s", err)

		err = dd.SetPrivateKey(receiver, nil)
		assert(err == nil, "decryptor can't add SK: %s", err)

		rio, err := dd.NewStreamReader()
		assert(err == nil, "stream reader failed: %s", err)

		rbuf = make([]byte, csize)
		wr = Buffer{}
		n := 0
		for {
			m, err := rio.Read(rbuf)
			assert(err == nil || err == io.EOF, "streamread fail: %s", err)

			if m > 0 {
				wr.Write(rbuf[:m])
				n += m
			}
			if err == io.EOF || m == 0 {
				break
			}
		}

		b := wr.Bytes()
		assert(n == len(b), "streamread: bad buflen; exp %d, saw %d", n, len(b))
		assert(n == len(buf), "streamread: decrypt len mismatch; exp %d, saw %d", len(buf), n)

		assert(byteEq(b, buf), "decrypt content mismatch")
	}

}

func randint() int {
	var b [4]byte

	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		panic(fmt.Sprintf("can't read 4 rand bytes: %s", err))
	}

	u := binary.BigEndian.Uint32(b[:])

	return int(u & 0x7fffffff)
}

func randmod(m int) int {
	return randint() % m
}
