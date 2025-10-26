// encdec.go  - handy wrappers for encoding/decoding basic types
//
// (c) 2024- Sudhi Herle <sudhi@herle.net>
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
)

func enc32[T ~int32 | ~uint32 | int](b []byte, n T) []byte {
	be := binary.BigEndian

	be.PutUint32(b, uint32(n))
	return b[4:]
}

func dec32[T ~int | ~int32 | ~uint | ~uint32](b []byte) ([]byte, T) {
	be := binary.BigEndian
	n := be.Uint32(b[:4])
	return b[4:], T(n)
}

func dec64[T ~int | ~int64 | ~uint | ~uint64](b []byte) ([]byte, T) {
	be := binary.BigEndian
	n := be.Uint64(b[:8])
	return b[8:], T(n)
}

func enc64[T ~int64 | ~uint64](b []byte, n T) []byte {
	be := binary.BigEndian
	be.PutUint64(b, uint64(n))
	return b[8:]
}
