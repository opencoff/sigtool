// iomisc.go -- misc i/o functions
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
	"encoding/binary"
	"fmt"
	"github.com/opencoff/go-mmap"
	"hash"
	"os"
)

// Generate file checksum out of hash function h
func fileCksum(fn string, f func() hash.Hash) ([]byte, error) {
	fd, err := os.Open(fn)
	if err != nil {
		return nil, fmt.Errorf("can't open %s: %s", fn, err)
	}

	defer fd.Close()

	h := f()

	sz, err := mmap.Reader(fd, func(b []byte) error {
		h.Write(b)
		return nil
	})
	if err != nil {
		return nil, err
	}

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(sz))

	h.Write(b[:])

	return h.Sum(nil)[:], nil
}
