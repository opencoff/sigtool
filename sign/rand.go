// rand.go - utility functions to generate random quantities
//
// (c) 2018 Sudhi Herle <sudhi@herle.net>
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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

func randu32() uint32 {
	var b [4]byte

	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		panic(fmt.Sprintf("can't read 4 rand bytes: %s", err))
	}

	return binary.LittleEndian.Uint32(b[:])
}

func randRead(b []byte) []byte {
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(fmt.Sprintf("can't read %d bytes of random data: %s", len(b), err))
	}
	return b
}

func randBuf(sz int) []byte {
	b := make([]byte, sz)
	return randRead(b)
}
