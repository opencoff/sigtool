// decrypt.go -- Decrypt command handling
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

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/opencoff/go-fio"
	flag "github.com/opencoff/pflag"
	"github.com/opencoff/sigtool"
)

type nullWriter struct{}

func (w *nullWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *nullWriter) Close() error {
	return nil
}

var _ io.WriteCloser = &nullWriter{}

func decrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	fs.Usage = func() {
		decryptUsage(fs)
	}

	var envpw string
	var outfile string
	var pubkey string
	var nopw, test, force bool

	fs.StringVarP(&outfile, "outfile", "o", "", "Write the output to file `F`")
	fs.BoolVarP(&nopw, "no-password", "", false, "Don't ask for passphrase to decrypt the private key")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use passphrase from environment variable `E`")
	fs.StringVarP(&pubkey, "verify-sender", "v", "", "Verify that the sender matches public key in `F`")
	fs.BoolVarP(&test, "test", "t", false, "Test the encrypted file against the given key without writing to output")
	fs.BoolVarP(&force, "overwrite", "", false, "Overwrite the output file if it exists")

	err := fs.Parse(args)
	if err != nil {
		Die("%s", err)
	}

	args = fs.Args()
	if len(args) < 1 {
		Die("Insufficient args. Try '%s --help'", os.Args[0])
	}

	var infd io.Reader = os.Stdin
	var outfd io.WriteCloser = os.Stdout
	var inf *os.File
	var infile string
	var pk *sigtool.PublicKey
	var sk *sigtool.PrivateKey

	// Read the private key first
	skfile := args[0]
	getpw := maybeGetPw(nopw, envpw, false)
	sk, err = sigtool.ReadPrivateKey(skfile, getpw)
	if err != nil {
		Die("%s", err)
	}

	if len(pubkey) > 0 {
		pk, err = sigtool.ReadPublicKey(pubkey)
		if err != nil {
			Die("%s", err)
		}
	}

	if len(args) > 1 {
		infile = args[1]
		if infile != "-" {
			inf := mustOpen(infile, os.O_RDONLY)
			defer inf.Close()

			infd = inf
		}
	}

	if test {
		outfd = &nullWriter{}
	} else if len(outfile) > 0 && outfile != "-" {
		var mode os.FileMode = 0600 // conservative mode

		if inf != nil {
			var same bool
			if same, mode = sameFile(inf, outfile); same {
				Die("won't create output file: same as input file!")
			}
		}

		var opts uint32
		if force {
			opts |= fio.OPT_OVERWRITE
		}
		sf, err := fio.NewSafeFile(outfile, opts, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			Die("%s", err)
		}

		AtExit(sf.Abort)
		defer sf.Abort()
		outfd = sf
	}

	d, err := sigtool.NewDecryptor(sk, pk, infd, outfd)
	if err != nil {
		Die("%s", err)
	}

	if pk == nil && d.AuthenticatedSender() {
		var fn string = infile
		if len(fn) == 0 || fn == "-" {
			fn = "<stdin>"
		}
		Warn("%s: Missing sender Public Key; can't authenticate sender ..", fn)
	}

	if err = d.Decrypt(); err != nil {
		Die("%s", err)
	}

	outfd.Close()

	if test {
		Warn("Enc file OK")
	}

}

func decryptUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s decrypt: Decrypt a file.

Usage: %s decrypt [options] key [infile]

Where KEY is the private key to be used for decryption and INFILE is
the encrypted input file. If INFILE is not provided, %s reads
from STDIN. Unless '-o' is used, %s writes the decrypted output to STDOUT.

Options:
`, Z, Z, Z, Z)

	fs.PrintDefaults()
	os.Exit(0)
}
