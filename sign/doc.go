// doc.go -- Documentation for sign & encrypt
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

// Package sign implements Ed25519 signing, verification on files.
// It builds upon golang.org/x/crypto/ed25519 by adding methods
// for serializing and deserializing Ed25519 private & public keys.
//
// It can sign and verify very large files - it prehashes the files
// with SHA-512 and then signs the SHA-512 checksum. The keys and signatures
// are YAML files and so, human readable.
//
// It can encrypt files for multiple recipients - each of whom is identified
// by their Ed25519 public key. The encryption by default generates ephmeral
// Curve25519 keys and creates pair-wise shared secret for each recipient of
// the encrypted file. The caller can optionally use a specific secret key
// during the encryption process - this has the benefit of also authenticating
// the sender (and the receiver can verify the sender if they possess the
// corresponding public key).
//
// The sign, verify, encrypt, decrypt operations can use OpenSSH Ed25519 keys
// *or* the keys generated by sigtool. This means, you can send encrypted
// files to any recipient identified by their comment in `~/.ssh/authorized_keys`.
package sign