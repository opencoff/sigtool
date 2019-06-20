[![GoDoc](https://godoc.org/github.com/opencoff/sigtool/sign?status.svg)](https://godoc.org/github.com/opencoff/sigtool/sign)

# sigtool/sign - Ed25519 signature calculation and verification

This is a small library that makes it easier to create and serialize Ed25519 keys, and sign,
verify files using those keys. The library uses mmap(2) to read and process very large files.

The companion program [sigtool](https://github.com/opencoff/sigtool) uses this library.
## License
GPL v2.0
