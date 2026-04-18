// encrypt_fuzz_test.go -- Fuzz tests for sigtool encrypt/decrypt
//
// (c) 2026 Sudhi Herle <sudhi@herle.net>
//
// Licensing Terms: GPLv2

package sigtool

import (
	"bytes"
	"testing"
)

// discardWriter is an io.WriteCloser that drops all bytes written to it.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (discardWriter) Close() error                { return nil }

// fuzzEncryptedSeed builds a fresh deterministic-ish (sender, receiver) pair
// and returns a ciphertext produced by encrypting a 1 KiB buffer. Fresh random
// keys per call are fine: fuzz seeds don't need to be reproducible across
// invocations.
func fuzzEncryptedSeed(t testing.TB) (sk *PrivateKey, senderPk *PublicKey, ciphertext []byte) {
	sender, err := NewPrivateKey("fuzz-sender")
	if err != nil {
		t.Fatalf("fuzz seed: sender key: %s", err)
	}
	receiver, err := NewPrivateKey("fuzz-receiver")
	if err != nil {
		t.Fatalf("fuzz seed: receiver key: %s", err)
	}

	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i & 0xff)
	}

	rd := bytes.NewReader(plaintext)
	wr := newBuffer("fuzz-wr")

	ee, err := NewEncryptor(sender, receiver.PublicKey(), rd, wr, 512)
	if err != nil {
		t.Fatalf("fuzz seed: new encryptor: %s", err)
	}
	if err := ee.Encrypt(); err != nil {
		t.Fatalf("fuzz seed: encrypt: %s", err)
	}

	return receiver, sender.PublicKey(), wr.Bytes()
}

func FuzzNewDecryptor(f *testing.F) {
	sk, senderPk, ct := fuzzEncryptedSeed(f)

	f.Add(ct)
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("garbage"))
	f.Add([]byte("SIGTOOL\x00\x00\x00\x00\x00"))
	// truncated prefix
	if len(ct) > 32 {
		f.Add(ct[:32])
		f.Add(ct[:len(ct)/2])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("NewDecryptor panicked on %d bytes: %v", len(data), r)
			}
		}()
		_, _ = NewDecryptor(sk, senderPk, bytes.NewReader(data), discardWriter{})
	})
}

func FuzzDecryptorRoundTrip(f *testing.F) {
	sk, senderPk, ct := fuzzEncryptedSeed(f)

	f.Add(ct)
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("garbage"))
	if len(ct) > 32 {
		f.Add(ct[:len(ct)-1])
		f.Add(ct[:len(ct)/2])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Decrypt panicked on %d bytes: %v", len(data), r)
			}
		}()
		dd, err := NewDecryptor(sk, senderPk, bytes.NewReader(data), discardWriter{})
		if err != nil {
			return
		}
		_ = dd.Decrypt()
	})
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
