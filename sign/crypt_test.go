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
	"testing"
)


// one sender, one receiver no verification of sender
func TestSimple(t *testing.T) {
	assert := newAsserter(t)

	receiver, err := NewKeypair()
	assert(err == nil, "receiver keypair gen failed: %s", err)

	// cleartext
	buf := make([]byte, 64 * 1024)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	ee, err := NewEncryptor(nil, 4096)
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.AddRecipient(&receiver.Pub)
	assert(err == nil, "can't add recipient: %s", err)

	rd := bytes.NewBuffer(buf)
	wr := bytes.Buffer{}

	err = ee.Encrypt(rd, &wr)
	assert(err == nil, "encrypt fail: %s", err)

	rd = bytes.NewBuffer(wr.Bytes())

	dd, err := NewDecryptor(rd)
	assert(err == nil, "decryptor create fail: %s", err)

	err = dd.SetPrivateKey(&receiver.Sec, nil)
	assert(err == nil, "decryptor can't add SK: %s", err)

	wr = bytes.Buffer{}
	err = dd.Decrypt(&wr)
	assert(err == nil, "decrypt fail: %s", err)

	b := wr.Bytes()
	assert(len(b) == len(buf), "decrypt length mismatch: exp %d, saw %d", len(buf), len(b))

	assert(byteEq(b, buf), "decrypt content mismatch")
}

// one sender, one receiver with verification of sender
func TestSenderVerified(t *testing.T) {
	assert := newAsserter(t)

	sender, err := NewKeypair()
	assert(err == nil, "sender keypair gen failed: %s", err)

	receiver, err := NewKeypair()
	assert(err == nil, "receiver keypair gen failed: %s", err)

	// cleartext
	buf := make([]byte, 64 * 1024)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	ee, err := NewEncryptor(&sender.Sec, 4096)
	assert(err == nil, "encryptor create fail: %s", err)

	err = ee.AddRecipient(&receiver.Pub)
	assert(err == nil, "can't add recipient: %s", err)

	rd := bytes.NewBuffer(buf)
	wr := bytes.Buffer{}

	err = ee.Encrypt(rd, &wr)
	assert(err == nil, "encrypt fail: %s", err)

	rd = bytes.NewBuffer(wr.Bytes())

	dd, err := NewDecryptor(rd)
	assert(err == nil, "decryptor create fail: %s", err)

	err = dd.SetPrivateKey(&receiver.Sec, &sender.Pub)
	assert(err == nil, "decryptor can't add SK: %s", err)

	wr = bytes.Buffer{}
	err = dd.Decrypt(&wr)
	assert(err == nil, "decrypt fail: %s", err)

	b := wr.Bytes()
	assert(len(b) == len(buf), "decrypt length mismatch: exp %d, saw %d", len(buf), len(b))

	assert(byteEq(b, buf), "decrypt content mismatch")
}


// one sender, multiple receivers, each decrypting the blob
func TestMultiReceiver(t *testing.T) {
	assert := newAsserter(t)

	sender, err := NewKeypair()
	assert(err == nil, "sender keypair gen failed: %s", err)

	// cleartext
	buf := make([]byte, 64 * 1024)
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i & 0xff)
	}

	ee, err := NewEncryptor(&sender.Sec, 4096)
	assert(err == nil, "encryptor create fail: %s", err)


	n := 4
	rx := make([]*Keypair, n)
	for i := 0; i < n; i++ {
		r, err := NewKeypair()
		assert(err == nil, "can't make receiver key %d: %s", i, err)
		rx[i] = r

		err = ee.AddRecipient(&r.Pub)
		assert(err == nil, "can't add recipient %d: %s", i, err)
	}

	rd := bytes.NewBuffer(buf)
	wr := bytes.Buffer{}

	err = ee.Encrypt(rd, &wr)
	assert(err == nil, "encrypt fail: %s", err)

	encBytes := wr.Bytes()
	for i := 0; i < n; i++ {
		rd = bytes.NewBuffer(encBytes)

		dd, err := NewDecryptor(rd)
		assert(err == nil, "decryptor %d create fail: %s", i, err)

		err = dd.SetPrivateKey(&rx[i].Sec, &sender.Pub)
		assert(err == nil, "decryptor can't add SK %d: %s", i, err)

		wr = bytes.Buffer{}
		err = dd.Decrypt(&wr)
		assert(err == nil, "decrypt %d fail: %s", i, err)

		b := wr.Bytes()
		assert(len(b) == len(buf), "decrypt %d length mismatch: exp %d, saw %d", i, len(buf), len(b))

		assert(byteEq(b, buf), "decrypt %d content mismatch", i)
	}
}
