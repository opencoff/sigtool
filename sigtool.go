// sigtool.go -- Tool to generate, manage Ed25519 keys and
// signatures.
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
	"path"
	"strings"

	"github.com/opencoff/go-utils"
	flag "github.com/opencoff/pflag"
	"github.com/opencoff/sigtool/sign"
)

var Z string = path.Base(os.Args[0])

func main() {

	var ver, help, debug bool

	mf := flag.NewFlagSet(Z, flag.ExitOnError)
	mf.SetInterspersed(false)
	mf.BoolVarP(&ver, "version", "v", false, "Show version info and exit")
	mf.BoolVarP(&help, "help", "h", false, "Show help info exit")
	mf.BoolVarP(&debug, "debug", "", false, "Enable debug mode")
	mf.Parse(os.Args[1:])

	if ver {
		fmt.Printf("%s - %s [%s; %s]\n", Z, ProductVersion, RepoVersion, Buildtime)
		os.Exit(0)
	}

	if help {
		usage(0)
	}

	args := mf.Args()
	if len(args) < 1 {
		Die("Insufficient arguments. Try '%s -h'", Z)
	}

	cmds := map[string]func(args []string){
		"generate": gen,
		"sign":     signify,
		"verify":   verify,
		"encrypt":  encrypt,
		"decrypt":  decrypt,

		"help": func(_ []string) {
			usage(0)
		},
	}

	words := make([]string, 0, len(cmds))
	for k := range cmds {
		words = append(words, k)
	}

	ab := utils.Abbrev(words)
	canon, ok := ab[strings.ToLower(args[0])]
	if !ok {
		Die("Unknown command %s", args[0])
	}

	cmd := cmds[canon]
	if cmd == nil {
		Die("can't map command %s", canon)
	}

	if debug {
		sign.Debug(1)
	}

	cmd(args[1:])

	// always call Exit so that at-exit handlers are called.
	Exit(0)
}

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
		sf, err := utils.NewSafeFile(outf, force, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
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

// Verify signature on a given file
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

Options:
`, Z)
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

	sig, err := sign.ReadSignature(sn)
	if err != nil {
		Die("Can't read signature '%s': %s", sn, err)
	}

	pk, err := sign.ReadPublicKey(pn)
	if err != nil {
		Die("%s", err)
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

func usage(c int) {
	x := fmt.Sprintf(`%s is a tool to generate, sign and verify files with Ed25519 signatures.

Usage: %s [global-options] command [options] arg [args..]

Global options:
  -h, --help       Show help and exit
  -v, --version    Show version info and exit
  --debug	   Enable debug (DANGEROUS)

Commands:
  generate, g      Generate a new Ed25519 keypair
  sign, s          Sign a file with a private key
  verify, v        Verify a signature against a file and a public key
  encrypt, e       Encrypt an input file to one or more recipients
  decrypt, d       Decrypt a file with a private key
`, Z, Z)

	os.Stdout.Write([]byte(x))
	os.Exit(c)
}

// Return true if $bn.key or $bn.pub exist; false otherwise
func exists(nm string) bool {
	if _, err := os.Stat(nm); err == nil {
		return true
	}

	return false
}

// This will be filled in by "build"
var RepoVersion string = "UNDEFINED"
var Buildtime string = "UNDEFINED"
var ProductVersion string = "UNDEFINED"

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
