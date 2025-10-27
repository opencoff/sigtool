[![GoDoc](https://godoc.org/github.com/opencoff/sigtool/cmd/sigtool?status.svg)](https://godoc.org/github.com/opencoff/sigtool/cmd/sigtool)

# README for sigtool CLI


## What is this?
`sigtool` is a companion CLI for the [sigtool](https://github.com/opencoff/sigtool)
library.

## How do I build it?
You need two things:

1. Protobuf compiler:

   On Debian based systems: `apt install protobuf-compiler`

   Consult your OS's package manager to install protobuf tools;
   these are typically named 'protobuf' or 'protoc'.

2. go 1.24+ toolchain

Next, build sigtool:

    git clone https://github.com/opencoff/sigtool
    cd sigtool
    ./cmd/sigtool/build -s

The binary will be in `./bin/$HOSTOS-$ARCH/sigtool`.
where `$HOSTOS` is the host OS where you are building (e.g., openbsd)
and `$ARCH` is the CPU architecture (e.g., amd64).

The shell script `build` is a helper that adds version numbers and
enables easy cross-platform builds.

## How do I use it?
Broadly, the tool can:

- generate new key pairs (public key and private key)
- sign a file
- verify a file against its signature
- encrypt a file
- decrypt a file

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

If *testkey.key* was encrypted without a user pass phrase:

    sigtool sign --no-password /tmp/testkey.key archive.tar.gz


The signature can also be written directly to a user supplied output
file.

    sigtool sign -o archive.sig /tmp/testkey.key archive.tar.gz


### Verify a signature against a file
Verifying a signature of a file requires the user to supply three
pieces of information:

- the Ed25519 public key to be used for verification
- the Ed25519 signature
- the file whose signature must be verified

e.g., to verify the signature of *archive.tar.gz* against
*testkey.pub* using the signature *archive.sig*

    sigtool verify /tmp/testkey.pub archive.sig archive.tar.gz


You can also pass a public key as a string (instead of a file):

    sigtool verify iF84Dymq/bAEnUMK6DRIHWAQDRD8FwDDDfsgFfzdjWM= archive.sig archive.tar.gz

Note that signing and verifying can also work with OpenSSH ed25519
keys.

### Encrypt a file by authenticating the sender
If the sender wishes to prove to the recipient that they  encrypted
a file:

    sigtool encrypt -s sender.key to.pub -o archive.tar.gz.enc archive.tar.gz


This will create an encrypted file *archive.tar.gz.enc* such that the
recipient in possession of *to.key* can decrypt it. Furthermore, if
the recipient has *sender.pub*, they can verify that the sender is indeed
who they expect.

### Decrypt a file and verify the sender
If the receiver has the public key of the sender, they can verify that
they indeed sent the file by cryptographically checking the output:

    sigtool decrypt -o archive.tar.gz -v sender.pub to.key archive.tar.gz.enc

Note that the verification is optional and if the `-v` option is not
used, then decryption will proceed without verifying the sender.

### Encrypt a file *without* authenticating the sender
`sigtool` can generate ephemeral keys for encrypting a file such that
the receiver doesn't need to authenticate the sender:

    sigtool encrypt to.pub -o archive.tar.gz.enc archive.tar.gz

This will create an encrypted file *archive.tar.gz.enc* such that the
recipient in possession of *to.key* can decrypt it.

### Encrypt a file to an OpenSSH recipient *without* authenticating the sender
Suppose you want to send an encrypted file where the recipient's
public key is in `~/.ssh/authorized_keys`. Such a recipient is identified
by their OpenSSH key comment (typically `name@domain`):

    sigtool encrypt user@domain -o archive.tar.gz.enc archive.tar.gz

If you have their public key in file "name-domain.pub", you can do:

    sigtool encrypt name-domain.pub -o archive.tar.gz.enc archive.tar.gz

This will create an encrypted file *archive.tar.gz.enc* such that the
recipient can decrypt using their private key.


### Tests
The core library has its own set of tests (`go test`); the CLI tool
has a simple shell script `tests.sh` that tests all the commands of the tool.

## Licensing Terms
The tool and code is licensed under the terms of the
GNU Public License v2.0 (strictly v2.0). If you need a commercial
license or a different license, please get in touch with me.

See the file ``LICENSE.md`` for the full terms of the license.

## Author
Sudhi Herle <sw@herle.net>
