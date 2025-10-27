// gen.go -- generate keys
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
	"os"
	"path"

	"github.com/opencoff/go-fio"
	flag "github.com/opencoff/pflag"
	"github.com/opencoff/sigtool"
)

// Run the generate command
func gen(args []string) {
	var nopw, help, force bool
	var comment string
	var envpw string

	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	fs.BoolVarP(&help, "help", "h", false, "Show this help and exit")
	fs.BoolVarP(&nopw, "no-password", "", false, "Don't ask for a password for the private key")
	fs.StringVarP(&comment, "comment", "c", "", "Use `C` as the text comment for the keys")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use passphrase from environment variable `E`")
	fs.BoolVarP(&force, "overwrite", "", false, "Overwrite the output file if it exists")

	fs.Parse(args)

	if help {
		fs.SetOutput(os.Stdout)
		fmt.Printf(`%s generate|gen|g [options] file-prefix

Generate a new Ed25519 public+private key pair and write public key to
FILE-PREFIX.pub and private key to FILE-PREFIX.key.

Options:
`, Z)
		fs.PrintDefaults()
		os.Exit(0)
	}

	args = fs.Args()
	if len(args) < 1 {
		Die("Insufficient arguments to 'generate'. Try '%s generate -h' ..", Z)
	}

	bn := args[0]

	pkn := fmt.Sprintf("%s.pub", path.Clean(bn))
	skn := fmt.Sprintf("%s.key", path.Clean(bn))

	if !force {
		if exists(pkn) || exists(skn) {
			Die("Public/Private key files (%s, %s) exist. won't overwrite!", skn, pkn)
		}
	}

	getpw := maybeGetPw(nopw, envpw, true)
	sk, err := sigtool.NewPrivateKey(comment)
	if err != nil {
		Die("%s", err)
	}

	pk := sk.PublicKey()

	skb, err := sk.Marshal(getpw)
	if err != nil {
		Die("%s", err)
	}

	pkb, err := pk.Marshal()
	if err != nil {
		Die("%s", err)
	}

	// Now write the files out
	writeFile(skn, skb, force, 0600)
	writeFile(pkn, pkb, force, 0644)
}

func writeFile(fn string, buf []byte, force bool, perm os.FileMode) {
	var opts uint32

	if force {
		opts |= fio.OPT_OVERWRITE
	}
	sf, err := fio.NewSafeFile(fn, opts, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		Die("%s: %s", fn, err)
	}

	AtExit(sf.Abort)
	defer sf.Abort()

	if err = writeAll(sf, buf); err != nil {
		Die("%s: %s", fn, err)
	}

	sf.Close()
}
