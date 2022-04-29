// safefile.go - safe file creation and unwinding on error
//
// (c) 2021 Sudhi Herle <sudhi@herle.net>
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
	"fmt"
	"io"
	"os"
)

// SafeFile is an io.WriteCloser which uses a temporary file that
// will be atomically renamed when there are no errors and
// caller invokes Close(). Callers are advised to call
// Abort() in the appropriate error handling (defer) context
// so that the temporary file is properly deleted.
type SafeFile struct {
	*os.File

	// error for writes recorded once
	err  error
	name string // actual filename

	closed bool // set if the file is closed properly
}

var _ io.WriteCloser = &SafeFile{}

// NewSafeFile creates a new temporary file that would either be
// aborted or safely renamed to the correct name.
// 'nm' is the name of the final file; if 'ovwrite' is true,
// then the file is overwritten if it exists.
func NewSafeFile(nm string, ovwrite bool, flag int, perm os.FileMode) (*SafeFile, error) {
	if _, err := os.Stat(nm); err == nil && !ovwrite {
		return nil, fmt.Errorf("safefile: won't overwrite existing %s", nm)
	}

	// forcibly unlink the old file - so previous artifacts don't exist
	os.Remove(nm)

	tmp := fmt.Sprintf("%s.tmp.%d.%x", nm, os.Getpid(), randu32())
	fd, err := os.OpenFile(tmp, flag, perm)
	if err != nil {
		return nil, err
	}

	sf := &SafeFile{
		File: fd,
		name: nm,
	}
	return sf, nil
}

// Attempt to write everything in 'b' and don't proceed if there was
// a previous error or the file was already closed.
func (sf *SafeFile) Write(b []byte) (int, error) {
	if sf.err != nil {
		return 0, sf.err
	}

	if sf.closed {
		return 0, fmt.Errorf("safefile: %s is closed", sf.Name())
	}

	var z, nw int
	n := len(b)
	for n > 0 {
		if nw, sf.err = sf.File.Write(b); sf.err != nil {
			return z, sf.err
		}
		z += nw
		n -= nw
		b = b[nw:]
	}
	return z, nil
}

// Abort the file write and remove any temporary artifacts
func (sf *SafeFile) Abort() {
	// if we've successfully closed, nothing to do!
	if sf.closed {
		return
	}

	sf.closed = true
	sf.File.Close()
	os.Remove(sf.Name())
}

// Close flushes all file data & metadata to disk, closes the file and atomically renames
// the temp file to the actual file - ONLY if there were no intervening errors.
func (sf *SafeFile) Close() error {
	if sf.err != nil {
		sf.Abort()
		return sf.err
	}

	// mark this file as closed!
	sf.closed = true

	if sf.err = sf.Sync(); sf.err != nil {
		return sf.err
	}

	if sf.err = sf.File.Close(); sf.err != nil {
		return sf.err
	}

	if sf.err = os.Rename(sf.Name(), sf.name); sf.err != nil {
		return sf.err
	}

	return nil
}
