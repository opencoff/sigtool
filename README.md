[![GoDoc](https://godoc.org/github.com/opencoff/go-sign?status.svg)](https://godoc.org/github.com/opencoff/go-sign)

# README for sigtool


## What is this?
`sigtool` is an opinionated tool to generate, sign and verify Ed25519
signatures on files.  In many ways, it is like like OpenBSD's signify_
-- except written in Golang and definitely easier to use.

It can sign and verify very large files - it prehashes the files
with SHA-512 and then signs the SHA-512 checksum.

All the artifacts produced by this tool are standard YAML files -
thus, human readable.

## How do I build it?
With Go 1.5 and later:

    git clone https://github.com/opencoff/sigtool
    cd sigtool
    make

The binary will be in `./sigtool`.

## How do I use it?
Broadly, the tool can:

- generate new key pairs (public key and private key)
- sign a file
- verify a file against its signature

### Generate Key pair
To start with, you generate a new key pair (a public key used for
verification and a private key used for signing). e.g.,

    sigtool gen /tmp/testkey

The tool then generates */tmp/testkey.pub* and */tmp/testkey.key*.  The secret
key (".key") can optionally be encrypted with a user supplied pass
phrase - which the user has to enter via interactive prompt:

    sigtool gen -p /tmp/testkey

### Sign a file
Signing a file requires the user to provide a previously generated
Ed25519 private key.  The signature (YAML) is written to STDOUT.
e.g.,  to sign `archive.tar.gz` with private key `/tmp/testkey.key`:

    sigtool sign /tmp/testkey.key archive.tar.gz

If *testkey.key* was encrypted with a user pass phrase:

    sigtool sign -p /tmp/testkey.key archive.tar.gz


The signature can also be written directly to a user supplied output
file.

    sigtool sign -p -o archive.sig /tmp/testkey.key archive.tar.gz


### Verify a signature against a file
Verifying a signature of a file requires the user to supply three
pieces of information:

- the Ed25519 public key to be used for verification
- the Ed25519 signature
- the file whose signature must be verified

e.g., to verify the signature of *archive.tar.gz* against
*testkey.pub* using the signature *archive.sig*

    sigtool verify /tmp/testkey.pub archive.sig archive.tar.gz

## How is the private key protected?
The Ed25519 private key is encrypted using a key derived from the
user supplied pass phrase. This pass phrase is used to derive an
encryption key using the Scrypt key derivation algorithm. The
resulting derived key is XOR'd with the Ed25519 private key before
being committed to disk. To protect the integrity of the process,
the essential parameters used for deriving the key, and the derived
key are hashed via SHA256 and stored along with the encrypted key.

As an additional security measure, the user supplied pass phrase is
hashed with SHA512.

## Understanding the Code
`src/sign` is a library to generate, verify and store Ed25519 keys
and signatures.  It uses the extended library (golang.org/x/crypto)
for the underlying operations.

The generated keys and signatures are proper YAML files and human
readable.

The signature file contains a hash of the public key - so that at
verification time, the right private key may be used (in situations
where there are lots of keys).

Signatures on large files are calculated efficiently by reading them
in memory mapped mode (```mmap(2)```) and hashing the file contents
using SHA-512. The Ed25519 signature is calculated on the file-hash.

## Example of Keys, Signature

### Ed25519 Public Key
A serialized Ed25519 public key looks like so:

    pk: uxpDh+gqXojAmxA/6vxZHzA+Uk+8wogUwvEhPBlWgvo=

### Ed25519 Private Key
And, a serialized Ed25519 private key looks like so:

    esk: t3vfqHbgUiA733KKPymFjWT8DdnBEkiMfsDHolPUdQWpvVn/F1Z4J6KYV3M5rGO9xgKxh5RAmqt+6LKgOiJAMQ==
    salt: pPHKG55UJYtJ5wU0G9hBvNQJ0DvT0a7T4Fmj4aPB84s=
    algo: scrypt-sha256
    verify: JvjRjJMKhJhBmZngC3Pvq7x3KCLKt7gar1AAz7HB4qM=
    Z: 131072
    r: 16
    p: 1

The Ed25519 private key is encrypted using Scrypt password hashing
mechanism. A user supplied passphrase to protect the private key
is first pre-hashed using SHA-512 before being used in
```scrypt()```. In pseudo code, this operation looks like below:

    passphrase = get_user_passphrase()
    hpass      = SHA512(passphrase)
    salt       = randombytes(32)
    xorkey     = Scrypt(hpass, salt, N, r, p)
    verify     = SHA256(salt, xorkey)
    esk        = ed25519_private_key ^ xorkey

Where, ```N```, ```r```, ```p``` are Scrypt parameters. In our
implementation:

    N = 131072
    r = 16
    p = 1

```verify```  is used during the decryption of the Ed25519 private
key - *before* actually doing the "xor" operation. This check
ensures that the supplied passphrase yields the same value as
```verify```.

### Ed25519 Signature
A generated signature looks like below after serialization:

    comment: inpfile=/tmp/file.txt
    pkhash: 36z9tCwTIVNwwDlExrB0SQ==
    signature: ow2oBP+buDbEvlNakOrsxgB5Yc/7PYyPVZCkfyu7oahw8BakF4Qf32uswPaKGZ8RVz4uXboYHdZtfrEjCgP/Cg==

Here, ```pkhash`` is a SHA256 of the public key needed to verify
this signature.

## Licensing Terms
The tool and code is licensed under the terms of the
GNU Public License v2.0 (strictly v2.0). If you need a commercial
license or a different license, please get in touch with me.

See the file ``LICENSE.md`` for the full terms of the license.

## Author
Sudhi Herle <sw@herle.net>

.. _signify: https://www.openbsd.org/papers/bsdcan-signify.html
