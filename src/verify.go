// verify.go -- Verify signatures
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

	flag "github.com/opencoff/pflag"
	"github.com/opencoff/sigtool/sign"
)

func verify(args []string) {
	var help, quiet bool

	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.BoolVarP(&help, "help", "h", false, "Show this help and exit")
	fs.BoolVarP(&quiet, "quiet", "q", false, "Don't show any output; exit with status code only")

	fs.Parse(args)

	if help {
		fs.SetOutput(os.Stdout)
		fmt.Printf(`%s verify|v [options] pubkey sig file

Verify an Ed25519 signature in SIG of FILE using a public key PUBKEY.
The pubkey can be one of:
  - a file: either OpenSSH ed25519 pubkey or a sigtool pubkey
  - a string: the raw OpenSSH or sigtool pubkey

%s will first parse it as a string before trying to parse it as a file.

Options:
`, Z, Z)
		fs.PrintDefaults()
		os.Exit(0)
	}

	args = fs.Args()
	if len(args) < 3 {
		Die("Insufficient arguments to 'verify'. Try '%s verify -h' ..", Z)
	}

	pn := args[0]
	sn := args[1]
	fn := args[2]

	// We first try to read the public key as a base64/openssh string
	pk, err := sign.MakePublicKeyFromString(pn)
	if err != nil {
		pk, err = sign.ReadPublicKey(pn)
		if err != nil {
			Die("%s", err)
		}
	}

	sig, err := sign.ReadSignature(sn)
	if err != nil {
		Die("Can't read signature '%s': %s", sn, err)
	}

	if !sig.IsPKMatch(pk) {
		Die("Wrong public key '%s' for verifying '%s'", pn, sn)
	}

	ok, err := pk.VerifyFile(fn, sig)
	if err != nil {
		Die("%s", err)
	}

	exit := 0
	if !ok {
		exit = 1
	}

	if !quiet {
		if ok {
			fmt.Printf("%s: Signature %s verified\n", fn, sn)
		} else {
			fmt.Printf("%s: Signature %s verification failure\n", fn, sn)
		}
	}

	os.Exit(exit)
}
