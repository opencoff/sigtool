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
	"github.com/opencoff/sigtool"
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
  - a string: the raw OpenSSH pubkey

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

	pk, err := readPK(pn)
	if err != nil {
		Die("%s: %s", pn, err)
	}

	sig, err := os.ReadFile(sn)
	if err != nil {
		Die("%s: %s", sn, err)
	}

	ok, err := pk.VerifyFile(fn, string(sig))
	if err != nil {
		Die("%s: %s", sn, err)
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

// read and parse a PK; a PK can be:
// - a string containing the openssh PK
// - a file containing the openssh PK
// - a file containing native sigtool PK
func readPK(fn string) (*sigtool.PublicKey, error) {
	// first see if we can read the file
	pkb, err := os.ReadFile(fn)
	if err != nil {
		// we couldn't; let's treat it as a string
		pkb = []byte(fn)
	}

	// Now parse the public key
	pk, err := sigtool.ParsePublicKey(pkb)
	if err != nil {
		return nil, err
	}
	return pk, nil
}
