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

	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
	"github.com/opencoff/sigtool/sign"
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

	var err error
	var pw []byte

	if !nopw {
		var pws string
		if len(envpw) > 0 {
			pws = os.Getenv(envpw)
		} else {
			pws, err = utils.Askpass("Enter passphrase for private key", true)
			if err != nil {
				Die("%s", err)
			}
		}

		pw = []byte(pws)
	}

	sk, err := sign.NewPrivateKey()
	if err != nil {
		Die("%s", err)
	}

	if err = sk.Serialize(skn, comment, force, pw); err != nil {
		Die("%s", err)
	}

	pk := sk.PublicKey()
	if err = pk.Serialize(pkn, comment, force); err != nil {
		Die("%s", err)
	}
}
