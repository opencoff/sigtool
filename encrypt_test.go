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

package sigtool

import (
	"bytes"
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

	sk, err := NewPrivateKey(t.Name())
	assert(err == nil, "SK gen failed: %s", err)

	pk := sk.PublicKey()

	var blkSize int = 512
	var size int = (blkSize * 10)

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	ee, err := NewEncryptor(nil, pk, rd, &wr, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.Encrypt()
	assert(err == nil, "encrypt fail: %s", err)

	rd = bytes.NewBuffer(wr.Bytes())

	wr = Buffer{}
	dd, err := NewDecryptor(sk, nil, rd, &wr)
	assert(err == nil, "decryptor create fail: %s", err)

	err = dd.Decrypt()
	assert(err == nil, "decrypt fail: %s", err)

	b := wr.Bytes()
	assert(len(b) == len(buf), "decrypt length mismatch: exp %d, saw %d", len(buf), len(b))

	assert(byteEq(b, buf), "decrypt content mismatch")
}

// one sender, one receiver - small blocks
func TestEncryptSmallSizes(t *testing.T) {
	assert := newAsserter(t)

	rx, err := NewPrivateKey(t.Name())
	assert(err == nil, "RX SK gen failed: %s", err)
	pk := rx.PublicKey()

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

		rd := bytes.NewBuffer(buf)
		wr := Buffer{}

		ee, err := NewEncryptor(nil, pk, rd, &wr, uint64(blkSize))
		assert(err == nil, "encryptor-%d create fail: %s", i, err)

		err = ee.Encrypt()
		assert(err == nil, "encrypt-%d fail: %s", i, err)

		rd = bytes.NewBuffer(wr.Bytes())
		wr = Buffer{}

		dd, err := NewDecryptor(rx, nil, rd, &wr)
		assert(err == nil, "decryptor-%d create fail: %s", i, err)

		err = dd.Decrypt()
		assert(err == nil, "decrypt-%d fail: %s", i, err)

		b := wr.Bytes()
		assert(len(b) == len(buf), "decrypt-%d length mismatch: exp %d, saw %d", i, len(buf), len(b))

		assert(byteEq(b, buf), "decrypt-%d content mismatch", i)
	}
}

// test corrupted header or corrupted input
func TestEncryptCorrupted(t *testing.T) {
	assert := newAsserter(t)

	sk, err := NewPrivateKey(t.Name())
	assert(err == nil, "SK gen failed: %s", err)

	pk := sk.PublicKey()

	var blkSize int = 1024
	var size int = (blkSize * 23) + randmod(blkSize)

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	rd := bytes.NewReader(buf)
	wr := Buffer{}

	ee, err := NewEncryptor(nil, pk, rd, &wr, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.Encrypt()
	assert(err == nil, "encrypt fail: %s", err)

	rb := wr.Bytes()
	n := len(rb)

	// corrupt the input
	for i := 0; i < n; i++ {
		j := randint() % n
		rb[j] = byte(randint() & 0xff)
	}

	rd = bytes.NewReader(rb)
	wr = Buffer{}
	dd, err := NewDecryptor(sk, nil, rd, &wr)
	assert(err != nil, "decryptor works on bad input")
	assert(dd == nil, "decryptor not nil for bad input")
}

// one sender, one receiver with verification of sender
func TestEncryptSenderVerified(t *testing.T) {
	assert := newAsserter(t)

	sender, err := NewPrivateKey(t.Name())
	assert(err == nil, "sender SK gen failed: %s", err)

	receiver, err := NewPrivateKey(t.Name())
	assert(err == nil, "receiver SK gen failed: %s", err)

	rxpk := receiver.PublicKey()

	var blkSize int = 1024
	var size int = (blkSize * 23) + randmod(blkSize)

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	ee, err := NewEncryptor(sender, rxpk, rd, &wr, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.Encrypt()
	assert(err == nil, "encrypt fail: %s", err)

	badrd := bytes.NewBuffer(wr.Bytes())
	rd = bytes.NewBuffer(wr.Bytes())
	wr = Buffer{}

	randkey, err := NewPrivateKey(t.Name())
	assert(err == nil, "rand SK gen failed: %s", err)

	// first set wrong keys
	dd, err := NewDecryptor(randkey, rxpk, badrd, &wr)
	assert(err != nil, "decryptor bad key worked")

	wr = Buffer{}
	dd, err = NewDecryptor(receiver, sender.PublicKey(), rd, &wr)
	assert(err == nil, "decryptor create fail: %s", err)

	err = dd.Decrypt()
	assert(err == nil, "decrypt fail: %s", err)

	b := wr.Bytes()
	assert(len(b) == len(buf), "decrypt length mismatch: exp %d, saw %d", len(buf), len(b))

	assert(byteEq(b, buf), "decrypt content mismatch")
}

// one sender, multiple receivers, each decrypting the blob
func TestEncryptMultiReceiver(t *testing.T) {
	assert := newAsserter(t)

	sender, err := NewPrivateKey(t.Name())
	assert(err == nil, "sender SK gen failed: %s", err)

	var blkSize int = 1024
	var size int = (blkSize * 23) + randmod(blkSize)

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	n := 4
	rx := make([]*PrivateKey, n)
	for i := 0; i < n; i++ {
		r, err := NewPrivateKey(t.Name())
		assert(err == nil, "can't make receiver SK %d: %s", i, err)
		rx[i] = r
	}

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	rx0 := rx[0].PublicKey()

	ee, err := NewEncryptor(sender, rx0, rd, &wr, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	for i := 1; i < n; i++ {
		r := rx[i]
		err = ee.AddRecipient(r.PublicKey())
		assert(err == nil, "can't add recipient %d: %s", i, err)
	}

	err = ee.Encrypt()
	assert(err == nil, "encrypt fail: %s", err)

	encBytes := wr.Bytes()
	senderPK := sender.PublicKey()
	for i := 0; i < n; i++ {
		rd = bytes.NewBuffer(encBytes)
		wr = Buffer{}

		dd, err := NewDecryptor(rx[i], senderPK, rd, &wr)
		assert(err == nil, "decryptor %d create fail: %s", i, err)

		err = dd.Decrypt()
		assert(err == nil, "decrypt %d fail: %s", i, err)

		b := wr.Bytes()
		assert(len(b) == len(buf), "decrypt %d length mismatch: exp %d, saw %d", i, len(buf), len(b))

		assert(byteEq(b, buf), "decrypt %d content mismatch", i)
	}
}

func randint() int {
	for {
		n := int(randu32())
		if n > 0 {
			return n
		}
	}
}

func randmod(m int) int {
	return randint() % m
}

// Test AuthenticatedSender() method
func TestAuthenticatedSenderTrue(t *testing.T) {
	assert := newAsserter(t)

	sender, err := NewPrivateKey("sender")
	assert(err == nil, "sender SK gen failed: %s", err)

	receiver, err := NewPrivateKey("receiver")
	assert(err == nil, "receiver SK gen failed: %s", err)

	rxpk := receiver.PublicKey()

	var blkSize int = 512
	var size int = blkSize * 5

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	// Encrypt WITH sender authentication
	ee, err := NewEncryptor(sender, rxpk, rd, &wr, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.Encrypt()
	assert(err == nil, "encrypt fail: %s", err)

	rd = bytes.NewBuffer(wr.Bytes())
	wr = Buffer{}

	// Decrypt and verify sender
	dd, err := NewDecryptor(receiver, sender.PublicKey(), rd, &wr)
	assert(err == nil, "decryptor create fail: %s", err)

	// IMPORTANT: Check AuthenticatedSender() BEFORE calling Decrypt()
	isAuth := dd.AuthenticatedSender()
	assert(isAuth, "AuthenticatedSender() should return true when sender is authenticated")

	err = dd.Decrypt()
	assert(err == nil, "decrypt fail: %s", err)

	b := wr.Bytes()
	assert(byteEq(b, buf), "decrypt content mismatch")
}

func TestAuthenticatedSenderFalse(t *testing.T) {
	assert := newAsserter(t)

	receiver, err := NewPrivateKey("receiver")
	assert(err == nil, "receiver SK gen failed: %s", err)

	rxpk := receiver.PublicKey()

	var blkSize int = 512
	var size int = blkSize * 5

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	// Encrypt WITHOUT sender authentication (nil sender)
	ee, err := NewEncryptor(nil, rxpk, rd, &wr, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.Encrypt()
	assert(err == nil, "encrypt fail: %s", err)

	rd = bytes.NewBuffer(wr.Bytes())
	wr = Buffer{}

	// Decrypt without expecting sender verification
	dd, err := NewDecryptor(receiver, nil, rd, &wr)
	assert(err == nil, "decryptor create fail: %s", err)

	// IMPORTANT: Check AuthenticatedSender() returns false when no sender auth
	isAuth := dd.AuthenticatedSender()
	assert(!isAuth, "AuthenticatedSender() should return false when sender is not authenticated")

	err = dd.Decrypt()
	assert(err == nil, "decrypt fail: %s", err)

	b := wr.Bytes()
	assert(byteEq(b, buf), "decrypt content mismatch")
}

func TestAuthenticatedSenderWrongKey(t *testing.T) {
	assert := newAsserter(t)

	sender, err := NewPrivateKey("sender")
	assert(err == nil, "sender SK gen failed: %s", err)

	receiver, err := NewPrivateKey("receiver")
	assert(err == nil, "receiver SK gen failed: %s", err)

	fakeSender, err := NewPrivateKey("fake-sender")
	assert(err == nil, "fake sender SK gen failed: %s", err)

	rxpk := receiver.PublicKey()

	var blkSize int = 512
	var size int = blkSize * 5

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	// Encrypt with REAL sender
	ee, err := NewEncryptor(sender, rxpk, rd, &wr, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.Encrypt()
	assert(err == nil, "encrypt fail: %s", err)

	rd = bytes.NewBuffer(wr.Bytes())
	wr = Buffer{}

	// Try to decrypt expecting WRONG sender - should fail
	dd, err := NewDecryptor(receiver, fakeSender.PublicKey(), rd, &wr)
	assert(err != nil, "decryptor should fail with wrong sender public key")
	assert(dd == nil, "decryptor should be nil when sender verification fails")
}

func TestAuthenticatedSenderMultiRecipient(t *testing.T) {
	assert := newAsserter(t)

	sender, err := NewPrivateKey("sender")
	assert(err == nil, "sender SK gen failed: %s", err)

	var blkSize int = 512
	var size int = blkSize * 3

	// cleartext
	buf := make([]byte, size)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	// Create 3 recipients
	n := 3
	rx := make([]*PrivateKey, n)
	for i := 0; i < n; i++ {
		r, err := NewPrivateKey(t.Name())
		assert(err == nil, "can't make receiver SK %d: %s", i, err)
		rx[i] = r
	}

	rd := bytes.NewBuffer(buf)
	wr := Buffer{}

	rx0 := rx[0].PublicKey()

	// Encrypt with sender authentication for multiple recipients
	ee, err := NewEncryptor(sender, rx0, rd, &wr, uint64(blkSize))
	assert(err == nil, "encryptor create fail: %s", err)

	for i := 1; i < n; i++ {
		err = ee.AddRecipient(rx[i].PublicKey())
		assert(err == nil, "can't add recipient %d: %s", i, err)
	}

	err = ee.Encrypt()
	assert(err == nil, "encrypt fail: %s", err)

	encBytes := wr.Bytes()
	senderPK := sender.PublicKey()

	// Each recipient should be able to decrypt and verify sender
	for i := 0; i < n; i++ {
		rd = bytes.NewBuffer(encBytes)
		wr = Buffer{}

		dd, err := NewDecryptor(rx[i], senderPK, rd, &wr)
		assert(err == nil, "decryptor %d create fail: %s", i, err)

		// Verify AuthenticatedSender() returns true for all recipients
		isAuth := dd.AuthenticatedSender()
		assert(isAuth, "recipient %d: AuthenticatedSender() should return true", i)

		err = dd.Decrypt()
		assert(err == nil, "decrypt %d fail: %s", i, err)

		b := wr.Bytes()
		assert(byteEq(b, buf), "decrypt %d content mismatch", i)
	}
}
