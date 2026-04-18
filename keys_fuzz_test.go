// keys_fuzz_test.go -- Fuzz tests for sigtool key parsing
//
// (c) 2026 Sudhi Herle <sudhi@herle.net>
//
// Licensing Terms: GPLv2

package sigtool

import (
	"encoding/base64"
	"strings"
	"testing"
)

func FuzzParsePrivateKey(f *testing.F) {
	getpw := func() ([]byte, error) { return []byte("test"), nil }

	// Valid sigtool PEM seed: generate one fresh.
	if sk, err := NewPrivateKey("fuzz-seed"); err == nil {
		if b, err := sk.Marshal(getpw); err == nil {
			f.Add(b)
		}
	}

	// SSH private-key PEM fixture
	f.Add([]byte(sshPrivateKeyUnencrypted))

	// Empty/nil
	f.Add([]byte(nil))
	f.Add([]byte{})

	// Truncated PEM prefix
	f.Add([]byte("-----BEGIN SIGTOOL PRIVATE KEY-----\n"))

	// PEM with unknown Type
	f.Add([]byte("-----BEGIN UNKNOWN KEY-----\nAAAA\n-----END UNKNOWN KEY-----\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParsePrivateKey panicked on %d bytes: %v", len(data), r)
			}
		}()
		_, _ = ParsePrivateKey(data, getpw)
	})
}

func FuzzParsePublicKey(f *testing.F) {
	// Valid sigtool PEM: marshal a PublicKey from NewPrivateKey
	if sk, err := NewPrivateKey("fuzz-seed"); err == nil {
		if b, err := sk.PublicKey().Marshal(); err == nil {
			f.Add(b)
		}
	}

	// SSH public key (full authorized_keys-style line)
	f.Add([]byte(sshPublicKeyUnencrypted))

	// Bare base64 wire-encoded ssh key - extract the middle field
	parts := strings.Fields(sshPublicKeyUnencrypted)
	if len(parts) >= 2 {
		f.Add([]byte(parts[1]))
		// also try decoded wire bytes
		if raw, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
			f.Add(raw)
		}
	}

	// Empty and random short bytes
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("AAA"))
	f.Add([]byte("-----BEGIN SIGTOOL PUBLIC KEY-----\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParsePublicKey panicked on %d bytes: %v", len(data), r)
			}
		}()
		_, _ = ParsePublicKey(data)
	})
}

func FuzzParseAuthorizedKeys(f *testing.F) {
	f.Add([]byte(authorizedKeysMultiple))
	f.Add([]byte(authorizedKeysMixed))
	f.Add([]byte(authorizedKeysWithOptions))
	f.Add([]byte(authorizedKeysEmpty))
	f.Add([]byte(authorizedKeysCommentsOnly))
	f.Add([]byte(authorizedKeysWeirdSpacing))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseAuthorizedKeys panicked on %d bytes: %v", len(data), r)
			}
		}()
		_, _ = ParseAuthorizedKeys(data)
	})
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
