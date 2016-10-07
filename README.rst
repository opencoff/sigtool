==================
README for sigtool
==================


What is this?
=============
This is a tool like OpenBSD's signify_ -- except written in Golang
and designed to be easier to use.

How do I build it?
==================
With Go 1.5 and later::

    mkdir sigtool
    cd sigtool
    env GOPATH=`pwd` go get -u github.com/opencoff/sigtool

The binary will be in ``bin/sigtool``.

How do I use it?
================
``signify --help``


Understanding the Code
======================
The tool uses a companion library that manages the keys and
signatures. It is part of a growing set of Golang libraries that are
useful in multiple projects. You can find them on github_.

The core code is in the ``sign`` library. This library is
self-documenting and can be reused in any of your projects.

.. _github: https://github.com/opencoff/go-libs/

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
