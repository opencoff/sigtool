// sign.go -- 'sign' command implementation
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
	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
	"github.com/opencoff/sigtool/sign"
)

// Run the 'sign' command.
func signify(args []string) {
	var nopw, help, force bool
	var output string
	var envpw string

	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	fs.BoolVarP(&help, "help", "h", false, "Show this help and exit")
	fs.BoolVarP(&nopw, "no-password", "", false, "Don't ask for a password for the private key")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use passphrase from environment variable `E`")
	fs.StringVarP(&output, "output", "o", "", "Write signature to file `F`")
	fs.BoolVarP(&force, "overwrite", "", false, "Overwrite previous signature file if it exists")

	fs.Parse(args)

	if help {
		fs.SetOutput(os.Stdout)
		fmt.Printf(`%s sign|s [options] privkey file

Sign FILE with a Ed25519 private key PRIVKEY and write signature to FILE.sig

Options:
`, Z)
		fs.PrintDefaults()
		os.Exit(0)
	}

	args = fs.Args()
	if len(args) < 2 {
		Die("Insufficient arguments to 'sign'. Try '%s sign -h' ..", Z)
	}

	kn := args[0]
	fn := args[1]
	outf := fmt.Sprintf("%s.sig", fn)

	var err error

	if len(output) > 0 {
		outf = output
	}

	var fd io.WriteCloser = os.Stdout

	if outf != "-" {
		var opts uint32
		if force {
			opts |= fio.OPT_OVERWRITE
		}
		sf, err := fio.NewSafeFile(outf, opts, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			Die("can't create sig file: %s", err)
		}

		// we unlink and remove temp on any error
		AtExit(sf.Abort)
		defer sf.Abort()
		fd = sf
	}

	sk, err := sign.ReadPrivateKey(kn, func() ([]byte, error) {
		if nopw {
			return nil, nil
		}

		var pws string
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

	sig, err := sk.SignFile(fn)
	if err != nil {
		Die("%s", err)
	}

	sigbytes, err := sig.MarshalBinary(fmt.Sprintf("input=%s", fn))
	fd.Write(sigbytes)
	fd.Close()
}
