// encrypt.go -- Encrypt command handling
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

	"github.com/opencoff/go-fio"
	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
	"github.com/opencoff/sigtool"
)

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

	args = fs.Args()
	if len(args) < 2 {
		Die("Insufficient args. Try '%s --help'", os.Args[0])
	}

	if blksize, err = utils.ParseSize(szstr); err != nil {
		Die("%s", err)
	}

	var sk *sigtool.PrivateKey

	if len(keyfile) > 0 {
		getpw := maybeGetPw(nopw, envpw, false)
		sk, err = sigtool.ReadPrivateKey(keyfile, getpw)
		if err != nil {
			Die("%s", err)
		}
	}

	var infd io.Reader = os.Stdin
	var outfd io.WriteCloser = os.Stdout
	var inf *os.File
	var infile string

	// The last argument is the input file and everything in between
	// is a recipient PK. The last argument must be an input file OR
	// an explicit "-".
	if len(args) > 1 {
		n := len(args)
		infile, args = args[n-1], args[:n-1]
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

	pka, err := sigtool.ParseAuthorizedKeys(authdata)
	keymap := make(map[string]*sigtool.PublicKey)

	for _, pk := range pka {
		keymap[pk.Comment] = pk
	}

	if len(outfile) > 0 && outfile != "-" {
		var mode os.FileMode = 0600 // conservative output mode

		// make sure infile and outfile are not the same underlying file.
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

	// Now find a PK for each recipient
	errs := 0
	var rxpk []*sigtool.PublicKey
	for i := 0; i < len(args); i++ {
		var err error
		var pk *sigtool.PublicKey

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
			pk, err = sigtool.ReadPublicKey(fn)
			if err != nil {
				Warn("%s", err)
				errs += 1
				continue
			}
		}

		rxpk = append(rxpk, pk)
	}

	if len(rxpk) == 0 {
		Die("No usable recipient public key")
	}

	en, err := sigtool.NewEncryptor(sk, rxpk[0], infd, outfd, blksize)
	if err != nil {
		Die("%s", err)
	}

	for i := 1; i < len(rxpk); i++ {
		err = en.AddRecipient(rxpk[i])
		if err != nil {
			Warn("%s", err)
			errs += 1
		}
	}

	if errs > 0 {
		Die("Too many errors!")
	}

	err = en.Encrypt()
	if err != nil {
		Die("%s", err)
	}
	outfd.Close()
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

func mustOpen(fn string, flag int) *os.File {
	fdk, err := os.OpenFile(fn, flag, 0600)
	if err != nil {
		Die("can't open file %s: %s", fn, err)
	}
	return fdk
}

// Return true if the file 'infd' and outfn are the same underlying file
func sameFile(infd *os.File, outfn string) (bool, os.FileMode) {
	var ist, ost os.FileInfo
	var err error

	if ost, err = os.Stat(outfn); err != nil {
		Die("can't stat %s: %s", outfn, err)
	}
	if ist, err = infd.Stat(); err != nil {
		Die("can't stat %s: %s", infd.Name(), err)
	}

	if os.SameFile(ist, ost) {
		return true, 0
	}

	return false, ist.Mode()
}
