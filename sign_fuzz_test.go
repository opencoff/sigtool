// sign_fuzz_test.go -- Fuzz tests for sigtool signature parsing
//
// (c) 2026 Sudhi Herle <sudhi@herle.net>
//
// Licensing Terms: GPLv2

package sigtool

import (
	"testing"
)

func FuzzParseSig(f *testing.F) {
	// Real sigtool signature
	if sk, err := NewPrivateKey("fuzz-sign"); err == nil {
		if sig, err := sk.SignMessage([]byte("hello")); err == nil {
			f.Add(sig)
		}
	}

	// Pathological short inputs
	f.Add("")
	f.Add(".")
	f.Add("xxx")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseSig panicked on %d bytes: %v", len(s), r)
			}
		}()
		_, _, _ = parseSig(s)
	})
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
