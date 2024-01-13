// crypt.go -- Encrypt/decrypt command handling
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
	"io/ioutil"
	"os"
	"strings"

	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
	"github.com/opencoff/sigtool/sign"
)

// sigtool encrypt [-i|--identity my.key] to.pub [to.pub] [ssh.pub] inputfile|- [-o output]

func encrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	fs.Usage = func() {
		encryptUsage(fs)
	}

	var outfile string
	var keyfile string
	var szstr string = "128k"
	var envpw string
	var nopw, force bool
	var blksize uint64

	fs.StringVarP(&outfile, "outfile", "o", "", "Write the output to file `F`")
	fs.StringVarP(&keyfile, "sign", "s", "", "Sign using private key `S`")
	fs.BoolVarP(&nopw, "no-password", "", false, "Don't ask for passphrase to decrypt the private key")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use passphrase from environment variable `E`")
	fs.StringVarP(&szstr, "block-size", "B", szstr, "Use `S` as the encryption block size")
	fs.BoolVarP(&force, "overwrite", "", false, "Overwrite the output file if it exists")

	err := fs.Parse(args)
	if err != nil {
		Die("%s", err)
	}

	if blksize, err = utils.ParseSize(szstr); err != nil {
		Die("%s", err)
	}

	var pws, infile string
	var sk *sign.PrivateKey

	if len(keyfile) > 0 {
		sk, err = sign.ReadPrivateKey(keyfile, func() ([]byte, error) {
			if nopw {
				return nil, nil
			}
			if len(envpw) > 0 {
				pws = os.Getenv(envpw)
			} else {
				pws, err = utils.Askpass("Enter passphrase for private key", false)
				if err != nil {
					Die("%s", err)
				}
			}
			return []byte(pws), nil
		})
		if err != nil {
			Die("%s", err)
		}
	}

	args = fs.Args()
	if len(args) < 2 {
		Die("Insufficient args. Try '%s --help'", os.Args[0])
	}

	var infd io.Reader = os.Stdin
	var outfd io.WriteCloser = os.Stdout
	var inf *os.File

	if len(args) > 1 {
		infile = args[len(args)-1]
		if infile != "-" {
			inf := mustOpen(infile, os.O_RDONLY)
			defer inf.Close()

			infd = inf
		}
	}

	// Lets try to read the authorized files
	home, err := os.UserHomeDir()
	if err != nil {
		Die("can't find homedir for this user")
	}

	authkeys := fmt.Sprintf("%s/.ssh/authorized_keys", home)
	authdata, err := ioutil.ReadFile(authkeys)
	if err != nil {
		if !os.IsNotExist(err) {
			Die("can't open %s: %s", authkeys, err)
		}
	}

	pka, err := sign.ParseAuthorizedKeys(authdata)
	keymap := make(map[string]*sign.PublicKey)

	for _, pk := range pka {
		keymap[pk.Comment] = pk
	}

	if len(outfile) > 0 && outfile != "-" {
		var mode os.FileMode = 0600 // conservative output mode

		if inf != nil {
			var err error
			var ist, ost os.FileInfo

			if ost, err = os.Stat(outfile); err != nil {
				Die("can't stat %s: %s", outfile, err)
			}

			if ist, err = inf.Stat(); err != nil {
				Die("can't stat %s: %s", infile, err)
			}

			if os.SameFile(ist, ost) {
				Die("won't create output file: same as input file!")
			}
			mode = ist.Mode()
		}

		sf, err := utils.NewSafeFile(outfile, force, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			Die("%s", err)
		}

		AtExit(sf.Abort)
		defer sf.Abort()
		outfd = sf
	}

	en, err := sign.NewEncryptor(sk, blksize)
	if err != nil {
		Die("%s", err)
	}

	errs := 0
	for i := 0; i < len(args)-1; i++ {
		var err error
		var pk *sign.PublicKey

		fn := args[i]
		if strings.Index(fn, "@") > 0 {
			var ok bool
			pk, ok = keymap[fn]
			if !ok {
				Warn("can't find user %s in %s", fn, authkeys)
				errs += 1
				continue
			}
		} else {
			pk, err = sign.ReadPublicKey(fn)
			if err != nil {
				Warn("%s", err)
				errs += 1
				continue
			}
		}

		err = en.AddRecipient(pk)
		if err != nil {
			Die("%s", err)
		}
	}

	if errs > 0 {
		Die("Too many errors!")
	}

	err = en.Encrypt(infd, outfd)
	if err != nil {
		Die("%s", err)
	}
	outfd.Close()
}

type nullWriter struct{}

func (w *nullWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *nullWriter) Close() error {
	return nil
}

var _ io.WriteCloser = &nullWriter{}

// sigtool decrypt a.key [file] [-o output]
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

	keyfile := args[0]
	sk, err := sign.ReadPrivateKey(keyfile, func() ([]byte, error) {
		var pws string
		if nopw {
			return nil, nil
		}

		if len(envpw) > 0 {
			pws = os.Getenv(envpw)
		} else {
			pws, err = utils.Askpass("Enter passphrase for private key", false)
			if err != nil {
				Die("%s", err)
			}
		}
		return []byte(pws), nil
	})
	if err != nil {
		Die("%s", err)
	}

	var pk *sign.PublicKey

	if len(pubkey) > 0 {
		pk, err = sign.ReadPublicKey(pubkey)
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
			var ist, ost os.FileInfo
			var err error

			if ost, err = os.Stat(outfile); err != nil {
				Die("can't stat %s: %s", outfile, err)
			}
			if ist, err = inf.Stat(); err != nil {
				Die("can't stat %s: %s", infile, err)
			}
			if os.SameFile(ist, ost) {
				Die("won't create output file: same as input file!")
			}
			mode = ist.Mode()
		}

		sf, err := utils.NewSafeFile(outfile, force, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			Die("%s", err)
		}

		AtExit(sf.Abort)
		defer sf.Abort()
		outfd = sf
	}

	d, err := sign.NewDecryptor(infd)
	if err != nil {
		Die("%s", err)
	}

	err = d.SetPrivateKey(sk, pk)
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

	if err = d.Decrypt(outfd); err != nil {
		Die("%s", err)
	}

	outfd.Close()

	if test {
		Warn("Enc file OK")
	}

}

func encryptUsage(fs *flag.FlagSet) {
	fmt.Printf(`%s encrypt: Encrypt a file to one or more recipients.

Usage: %s encrypt [options] to [to ...] infile|-

Where TO is the public key of the recipient; it can be one of:

- a file referring to an SSH or sigtool public key.
- string of the form 'a@b' - in which case the user's default
  ssh/authorized_keys is consulted to find the comment matching
  'a@b' - in which case the user's ssh authorized_keys file is consulted to
  find the comment matching the string.

INFILE is an input file to be encrypted. If the input file is '-' then %s
reads from STDIN. Unless '-o' is used, %s writes the encrypted output to STDOUT.

Options:
`, Z, Z, Z, Z)

	fs.PrintDefaults()
	os.Exit(0)
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

func mustOpen(fn string, flag int) *os.File {
	fdk, err := os.OpenFile(fn, flag, 0600)
	if err != nil {
		Die("can't open file %s: %s", fn, err)
	}
	return fdk
}
