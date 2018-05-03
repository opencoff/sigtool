==================
README for sigtool
==================


What is this?
=============
This is a tool to generate, sign and verify Ed25519 signatures. In
many ways, it is like like OpenBSD's signify_ -- except written in Golang
and designed to be easier to use.

It can sign and verify very large files - it prehashes the files
with SHA-512 and then signs the SHA-512 checksum.

All the artifacts produced by this tool are standard YAML files -
thus, human readable.

How do I build it?
==================
With Go 1.5 and later::

    mkdir sigtool
    cd sigtool
    env GOPATH=`pwd` go get -u github.com/opencoff/sigtool

The binary will be in ``bin/sigtool``.

How do I use it?
================
Broadly, the tool can:

- generate new key pairs (public key and private key)
- sign a file
- verify a file against its signature

Generate Key pair
-----------------
To start with, you generate a new key pair (a public key used for
verification and a private key used for signing). e.g., ::

    sigtool gen /tmp/testkey

The tool then generates */tmp/testkey.pub* and */tmp/testkey.key*.  The secret
key (".key") can optionally be encrypted with a user supplied pass
phrase - which the user has to enter via interactive prompt::

    sigtool gen -p /tmp/testkey

Sign a file
-----------
Signing a file requires the user to provide a previously generated
Ed25519 private key.  The signature (YAML) is written to STDOUT.
e.g.,  to sign ``archive.tar.gz`` with private key ``/tmp/testkey.key`` ::

    sigtool sign /tmp/testkey.key archive.tar.gz

If *testkey.key* was encrypted with a user pass phrase::

    sigtool sign -p /tmp/testkey.key archive.tar.gz


The signature can also be written directly to a user supplied output
file.::

    sigtool sign -p -o archive.sig /tmp/testkey.key archive.tar.gz


Verify a signature against a file
---------------------------------
Verifying a signature of a file requires the user to supply three
pieces of information:

- the Ed25519 public key to be used for verification
- the Ed25519 signature
- the file whose signature must be verified

e.g., to verify the signature of *archive.tar.gz* against
*testkey.pub* using the signature *archive.sig*::

    sigtool verify /tmp/testkey.pub archive.sig archive.tar.gz

How is the private key protected?
=================================
The Ed25519 private key is encrypted using a key derived from the
user supplied pass phrase. This pass phrase is used to derive an
encryption key using the Scrypt key derivation algorithm. The
resulting derived key is XOR'd with the Ed25519 private key before
being committed to disk. To protect the integrity of the process,
the essential parameters used for deriving the key, and the derived
key are hashed via SHA256 and stored along with the encrypted key.

As an additional security measure, the user supplied pass phrase is
hashed with SHA512.

In Pseudo-code::

    passwd = get_user_password()
    hpass  = SHA512(passwd)
    salt   = randombytes(32)
    xorkey = Scrypt(hpass, salt, N, r, p)

    cksum  = SHA256(salt, xorkey)
    enckey = ed25519_private_key ^ xorkey

And, ``cksum``, ``enckey`` are the entities stored as on-disk
private key.

The Scrypt parameters used by the ``sign`` library are:

- N: 131072
- r: 16
- p: 1

Understanding the Code
======================
The tool uses a companion library that manages the keys and
signatures. It is part of a growing set of Golang libraries that are
useful in multiple projects. You can find them on github_.

The core code is in the ``sign`` library. This library is
can be reused in any of your projects.

.. _github: https://github.com/opencoff/go-sign/

Licensing Terms
===============
The tool is licensed under the terms of the GNU Public License v2.0
(strictly v2.0). If you need a commercial license or a different
license, please get in touch with me.

See the file ``LICENSE.md`` for the full terms of the license.

Author
======
Sudhi Herle <sw@herle.net>

.. _signify: https://www.openbsd.org/papers/bsdcan-signify.html
