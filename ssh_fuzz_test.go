// ssh_fuzz_test.go -- Fuzz tests for SSH key parsing
//
// (c) 2026 Sudhi Herle <sudhi@herle.net>
//
// Licensing Terms: GPLv2

package sigtool

import (
	"testing"
)

func FuzzParseOpenSSHPrivateKey(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte(opensshv1Magic[:1]))
	f.Add([]byte(opensshv1Magic[:5]))
	f.Add([]byte(opensshv1Magic[:len(opensshv1Magic)-1]))
	f.Add([]byte(opensshv1Magic))
	f.Add([]byte(sshPrivateKeyUnencrypted))

	getpw := func() ([]byte, error) { return []byte("test"), nil }

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseSSHPrivateKey panicked on %d bytes: %v", len(data), r)
			}
		}()
		_, _ = parseSSHPrivateKey(data, getpw)
	})
}
