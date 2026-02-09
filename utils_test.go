// utils_test.go -- Test harness utilities for sign
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
	"crypto/subtle"
	"fmt"
	"os"
	"runtime"
	"testing"
)

// benchSizes is the shared set of file sizes for all benchmarks.
// Capped at 64MB for go test benchmarks.
var benchSizes = []struct {
	name string
	size int
}{
	{"0B", 0},
	{"64B", 64},
	{"4KB", 4 * 1024},
	{"64KB", 64 * 1024},
	{"256KB", 256 * 1024},
	{"1MB", 1024 * 1024},
	{"16MB", 16 * 1024 * 1024},
	{"64MB", 64 * 1024 * 1024},
}

// chunkSizeForFileSize returns an appropriate encryption chunk size
// proportional to the file size.
func chunkSizeForFileSize(fileSize int) uint64 {
	switch {
	case fileSize == 0:
		return uint64(_chunkSize) // 128KB default
	case fileSize <= 64*1024: // <= 64KB
		return uint64(fileSize)
	case fileSize <= 1024*1024: // <= 1MB
		return 128 * 1024 // 128KB default
	case fileSize <= 16*1024*1024: // <= 16MB
		return 1024 * 1024 // 1MB
	default: // > 16MB
		return 4 * 1024 * 1024 // 4MB
	}
}

// createTempFile creates a temp file of the given size filled with
// random data. It writes in 1MB chunks to avoid huge allocations.
// Uses b.TempDir() for automatic cleanup.
func createTempFile(b *testing.B, size int) string {
	b.Helper()

	dn := b.TempDir()
	fn := fmt.Sprintf("%s/bench-%d.dat", dn, size)

	fd, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		b.Fatalf("create temp file: %s", err)
	}
	defer fd.Close()

	const chunkWrite = 1024 * 1024 // 1MB write chunks
	var buf [chunkWrite]byte

	remaining := size
	for remaining > 0 {
		want := min(remaining, chunkWrite)
		randRead(buf[:want])
		n, err := fd.Write(buf[:want])
		if err != nil {
			b.Fatalf("write temp file: %s", err)
		}
		remaining -= n
	}
	fd.Sync()

	return fn
}

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
