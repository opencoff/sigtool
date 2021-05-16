// ssh.go - support for reading ssh private and public keys
//
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is a bastardization of github.com/ScaleFT/sshkeys and
// golang.org/x/crypto/ssh/keys.go
//
// It is licensed under the terms of the original go source code
// OR the Apache 2.0 license (terms of sshkeys).
//
// Changes from that version:
//   - don't use password but call a func() to get the password as needed
//   - narrowly scope the key support for ONLY ed25519 keys
//   - support reading multiple public keys from authorized_keys

package sign

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/dchest/bcrypt_pbkdf"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

const keySizeAES256 = 32

// ParseEncryptedRawPrivateKey returns a private key from an
// encrypted ed25519 private key.
func parseSSHPrivateKey(data []byte, getpw func() ([]byte, error)) (*PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrNoPEMFound
	}

	if x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("ssh: no support for legacy PEM encrypted keys")
	}

	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		return parseOpenSSHPrivateKey(block.Bytes, getpw)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func parseSSHPublicKey(in []byte) (*PublicKey, error) {
	v := bytes.Split(in, []byte(" \t"))
	if len(v) != 3 {
		return nil, ErrBadPublicKey
	}

	return parseEncPubKey(v[1], string(v[2]))
}

// parse a wire encoded public key
func parseEncPubKey(in []byte, comm string) (*PublicKey, error) {
	in, err := base64.StdEncoding.DecodeString(string(in))
	if err != nil {
		return nil, err
	}

	algo, in, ok := parseString(in)
	if !ok {
		return nil, ErrKeyTooShort

	}
	if string(algo) != ssh.KeyAlgoED25519 {
		return nil, nil
	}

	var w struct {
		KeyBytes []byte
		Rest     []byte `ssh:"rest"`
	}

	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, err
	}

	if len(w.Rest) > 0 {
		return nil, ErrBadTrailers
	}

	pk, err := PublicKeyFromBytes(w.KeyBytes)
	if err == nil {
		pk.Comment = strings.TrimSpace(comm)
	}
	return pk, err
}

func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if uint32(len(in)) < length {
		return
	}
	out = in[:length]
	rest = in[length:]
	ok = true
	return
}

// parseAuthorizedKey parses a public key in OpenSSH binary format and decodes it.
// removed.
func parseAuthorizedKey(in []byte) (*PublicKey, error) {
	in = bytes.TrimSpace(in)
	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		i = len(in)
	}

	pk, err := parseEncPubKey(in[:i], string(in[i:]))
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// ParseAuthorizedKeys parses a public key from an authorized_keys
// file used in OpenSSH according to the sshd(8) manual page.
func ParseAuthorizedKeys(in []byte) ([]*PublicKey, error) {
	var pka []*PublicKey
	var rest []byte

	for len(in) > 0 {
		end := bytes.IndexByte(in, '\n')
		if end != -1 {
			rest = in[end+1:]
			in = in[:end]
		} else {
			rest = nil
		}

		end = bytes.IndexByte(in, '\r')
		if end != -1 {
			in = in[:end]
		}

		in = bytes.TrimSpace(in)
		if len(in) == 0 || in[0] == '#' {
			in = rest
			continue
		}

		i := bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		if pk, err := parseAuthorizedKey(in[i:]); err == nil {
			if pk != nil {
				pka = append(pka, pk)
			}
			in = rest
			continue
		}

		// No key type recognised. Maybe there's an options field at
		// the beginning.
		var b byte
		inQuote := false
		var candidateOptions []string
		optionStart := 0
		for i, b = range in {
			isEnd := !inQuote && (b == ' ' || b == '\t')
			if (b == ',' && !inQuote) || isEnd {
				if i-optionStart > 0 {
					candidateOptions = append(candidateOptions, string(in[optionStart:i]))
				}
				optionStart = i + 1
			}
			if isEnd {
				break
			}
			if b == '"' && (i == 0 || (i > 0 && in[i-1] != '\\')) {
				inQuote = !inQuote
			}
		}
		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i == len(in) {
			// Invalid line: unmatched quote
			in = rest
			continue
		}

		in = in[i:]
		i = bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		if pk, err := parseAuthorizedKey(in[i:]); err == nil {
			if pk != nil {
				pka = append(pka, pk)
			}
		}

		in = rest
		continue
	}

	return pka, nil
}

const opensshv1Magic = "openssh-key-v1"

type opensshHeader struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       string
	PrivKeyBlock string
}

type opensshKey struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

type opensshED25519 struct {
	Pub     []byte
	Priv    []byte
	Comment string
	Pad     []byte `ssh:"rest"`
}

func parseOpenSSHPrivateKey(data []byte, getpw func() ([]byte, error)) (*PrivateKey, error) {
	magic := append([]byte(opensshv1Magic), 0)
	if !bytes.Equal(magic, data[0:len(magic)]) {
		return nil, ErrBadFormat
	}
	remaining := data[len(magic):]

	w := opensshHeader{}

	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return nil, err
	}

	if w.NumKeys != 1 {
		return nil, fmt.Errorf("ssh: NumKeys must be 1: %d", w.NumKeys)
	}

	var privateKeyBytes []byte
	var encrypted bool

	switch {
	// OpenSSH supports bcrypt KDF w/ AES256-CBC or AES256-CTR mode
	case w.KdfName == "bcrypt" && w.CipherName == "aes256-cbc":
		pw, err := getpw()
		if err != nil {
			return nil, err
		}
		iv, block, err := extractBcryptIvBlock(pw, &w)
		if err != nil {
			return nil, err
		}

		cbc := cipher.NewCBCDecrypter(block, iv)
		privateKeyBytes = []byte(w.PrivKeyBlock)
		cbc.CryptBlocks(privateKeyBytes, privateKeyBytes)

		encrypted = true

	case w.KdfName == "bcrypt" && w.CipherName == "aes256-ctr":
		pw, err := getpw()
		if err != nil {
			return nil, err
		}
		iv, block, err := extractBcryptIvBlock(pw, &w)
		if err != nil {
			return nil, err
		}

		stream := cipher.NewCTR(block, iv)
		privateKeyBytes = []byte(w.PrivKeyBlock)
		stream.XORKeyStream(privateKeyBytes, privateKeyBytes)

		encrypted = true

	case w.KdfName == "none" && w.CipherName == "none":
		privateKeyBytes = []byte(w.PrivKeyBlock)

	default:
		return nil, fmt.Errorf("ssh: unknown Cipher/KDF: %s:%s", w.CipherName, w.KdfName)
	}

	pk1 := opensshKey{}

	if err := ssh.Unmarshal(privateKeyBytes, &pk1); err != nil {
		if encrypted {
			return nil, ErrIncorrectPassword
		}
		return nil, err
	}

	if pk1.Check1 != pk1.Check2 {
		return nil, ErrIncorrectPassword
	}

	// we only handle ed25519 and rsa keys currently
	switch pk1.Keytype {
	case ssh.KeyAlgoED25519:
		key := opensshED25519{}

		err := ssh.Unmarshal(pk1.Rest, &key)
		if err != nil {
			return nil, err
		}

		if len(key.Priv) != ed25519.PrivateKeySize {
			return nil, ErrBadLength
		}

		for i, b := range key.Pad {
			if int(b) != i+1 {
				return nil, ErrBadPadding
			}
		}

		pk, err := PrivateKeyFromBytes(key.Priv)
		return pk, err
	default:
		return nil, fmt.Errorf("ssh: unhandled key type: %v", pk1.Keytype)
	}
}

func extractBcryptIvBlock(passphrase []byte, w *opensshHeader) ([]byte, cipher.Block, error) {
	cipherKeylen := keySizeAES256
	cipherIvLen := aes.BlockSize

	var opts struct {
		Salt   []byte
		Rounds uint32
	}

	if err := ssh.Unmarshal([]byte(w.KdfOpts), &opts); err != nil {
		return nil, nil, err
	}
	kdfdata, err := bcrypt_pbkdf.Key(passphrase, opts.Salt, int(opts.Rounds), cipherKeylen+cipherIvLen)
	if err != nil {
		return nil, nil, err
	}

	iv := kdfdata[cipherKeylen : cipherIvLen+cipherKeylen]
	aeskey := kdfdata[0:cipherKeylen]
	block, err := aes.NewCipher(aeskey)

	if err != nil {
		return nil, nil, err
	}

	return iv, block, nil
}
