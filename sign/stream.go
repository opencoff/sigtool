// stream.go - Streaming io.Reader, io.Writer interface to encryption/decryption
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
//

package sign

import (
	"io"
)

// encWriter buffers partial writes until a full chunk is accumulated.
// It's methods implement the io.WriteCloser interface.
type encWriter struct {
	buf []byte
	n   int // # of bytes written
	wr  io.WriteCloser
	e   *Encryptor
	blk uint32
	err error
}

var _ io.WriteCloser = &encWriter{}

// NewStreamWriter begins stream encryption to an underlying destination writer 'wr'.
// It returns an io.WriteCloser.
func (e *Encryptor) NewStreamWriter(wr io.WriteCloser) (io.WriteCloser, error) {
	if !e.started {
		err := e.start(wr)
		if err != nil {
			return nil, err
		}
	}

	w := &encWriter{
		buf: make([]byte, e.ChunkSize),
		wr:  wr,
		e:   e,
	}

	e.stream = true
	return w, nil
}

// Write implements the io.Writer interface
func (w *encWriter) Write(b []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	n := len(b)
	if n == 0 {
		return 0, nil
	}

	max := int(w.e.ChunkSize)
	for len(b) > 0 {
		buf := w.buf[w.n:]
		z := copy(buf, b)
		b = b[z:]
		w.n += z

		// We only flush if we have more data remaining in the input buffer.
		// This way, we don't flush a potentially last block here; that happens
		// when the caller eventually closes the stream.
		if w.n == max && len(b) > 0 {
			w.err = w.e.encrypt(w.buf, w.wr, w.blk, false)
			if w.err != nil {
				return 0, w.err
			}

			w.n = 0
			w.blk += 1
		}
	}
	return n, nil
}

// Close implements the io.Close interface
func (w *encWriter) Close() error {
	if w.err != nil {
		return w.err
	}

	err := w.e.encrypt(w.buf[:w.n], w.wr, w.blk, true)
	if err != nil {
		w.err = err
		return err
	}

	w.n = 0
	w.err = ErrClosed
	return w.wr.Close()
}

// encReader buffers partial reads and it's methods implement the io.Reader interface.
type encReader struct {
	buf    []byte
	unread []byte
	d      *Decryptor
	blk    uint32
}

var _ io.Reader = &encReader{}

// NewStreamReader returns an io.Reader to read from the decrypted stream
func (d *Decryptor) NewStreamReader() (io.Reader, error) {
	if d.key == nil {
		return nil, ErrNoKey
	}

	if d.eof {
		return nil, io.EOF
	}

	d.stream = true
	return &encReader{
		buf: make([]byte, d.ChunkSize),
		d:   d,
	}, nil
}

// Read implements io.Reader interface
func (r *encReader) Read(b []byte) (int, error) {
	if r.d.eof && len(r.unread) == 0 {
		return 0, io.EOF
	}

	if len(r.unread) > 0 {
		n := copy(b, r.unread)
		r.unread = r.unread[n:]
		return n, nil
	}

	buf, eof, err := r.d.decrypt(r.blk)
	if err != nil {
		return 0, err
	}

	r.blk += 1

	n := copy(b, buf)
	buf = buf[n:]

	copy(r.buf, buf)
	r.unread = r.buf[:len(buf)]

	if eof {
		r.d.eof = true
	}

	return n, nil
}
