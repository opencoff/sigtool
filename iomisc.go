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
	"github.com/opencoff/go-fio"
	"github.com/opencoff/go-mmap"
	"hash"
	"os"
)

// Simple function to reliably write data to a file.
// Does MORE than ioutil.WriteFile() - in that it doesn't trash the
// existing file with an incomplete write.
func writeFile(fn string, b []byte, ovwrite bool, mode uint32) error {
	var opts uint32
	if ovwrite {
		opts |= fio.OPT_OVERWRITE
	}
	sf, err := fio.NewSafeFile(fn, opts, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(mode))
	if err != nil {
		return err
	}
	defer sf.Abort()
	if _, err = sf.Write(b); err != nil {
		return err
	}

	return sf.Close()
}

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
