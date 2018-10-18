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

	flag "github.com/ogier/pflag"
	"github.com/opencoff/go-utils"

	// My signing library
	"sign"
)

// This will be filled in by "build"
var Version string = "1.1"

var Z string = path.Base(os.Args[0])

func main() {

	var ver, help bool

	mf := flag.NewFlagSet(Z, flag.ExitOnError)
	mf.SetInterspersed(false)
	mf.BoolVarP(&ver, "version", "v", false, "Show version info and exit")
	mf.BoolVarP(&help, "help", "h", false, "Show help info exit")
	mf.Parse(os.Args[1:])

	if ver {
		fmt.Printf("%s: %s\n", Z, Version)
		os.Exit(0)
	}

	if help {
		usage(0)
	}

	args := mf.Args()
	if len(args) < 1 {
		warn("Insufficient arguments. Try '%s -h'", Z)
		os.Exit(1)
	}

	switch args[0] {
	case "gen", "generate", "g":
		gen(args[1:])

	case "sign", "s":
		signify(args[1:])

	case "verify", "v":
		verify(args[1:])

	case "help", "":
		usage(0)

	default:
		die("Unknown command %s", args[0])
	}
}

// Run the generate command
func gen(args []string) {

	var pw, help, force bool
	var comment string
	var envpw string

	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	fs.BoolVarP(&help, "help", "h", false, "Show this help and exit")
	fs.BoolVarP(&pw, "password", "p", false, "Ask for passphrase to encrypt the private key [False]")
	fs.StringVarP(&comment, "comment", "c", "", "Use 'C' as the text comment for the keys []")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use passphrase from environment variable 'E' []")
	fs.BoolVarP(&force, "force", "F", false, "Overwrite the output file if it exists [False]")

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
		die("Insufficient arguments to 'generate'. Try '%s generate -h' ..", Z)
	}

	bn := args[0]

	if exists(bn) && !force {
		die("Public/Private key files (%s.key, %s.pub) exist. Won't overwrite!", bn, bn)
	}

	var pws string
	var err error

	if len(envpw) > 0 {
		pws = os.Getenv(envpw)
	} else if pw {
		pws, err = utils.Askpass("Enter passphrase for private key", true)
		if err != nil {
			die("%s", err)
		}
	}

	kp, err := sign.NewKeypair()
	if err != nil {
		die("%s", err)
	}

	err = kp.Serialize(bn, comment, pws)
	if err != nil {
		die("%s", err)
	}
}

// Run the 'sign' command.
func signify(args []string) {
	var pw, help bool
	var output string
	var envpw string

	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	fs.BoolVarP(&help, "help", "h", false, "Show this help and exit")
	fs.BoolVarP(&pw, "password", "p", false, "Ask for passphrase to decrypt the private key [False]")
	fs.StringVarP(&envpw, "env-password", "E", "", "Use passphrase from environment variable 'E' []")
	fs.StringVarP(&output, "output", "o", "", "Write signature to file F")

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
		die("Insufficient arguments to 'sign'. Try '%s sign -h' ..", Z)
	}

	kn := args[0]
	fn := args[1]
	outf := fmt.Sprintf("%s.sig", fn)

	var pws string
	var err error

	if len(envpw) > 0 {
		pws = os.Getenv(envpw)
	} else if pw {
		pws, err = utils.Askpass("Enter passphrase for private key", false)
		if err != nil {
			die("%s", err)
		}
	}

	if len(output) > 0 {
		outf = output
	}

	pk, err := sign.ReadPrivateKey(kn, pws)
	if err != nil {
		die("%s", err)
	}

	sig, err := pk.SignFile(fn)
	if err != nil {
		die("%s", err)
	}

	sigo, err := sig.Serialize(fmt.Sprintf("input=%s", fn))

	var fd io.Writer = os.Stdout

	if outf != "-" {
		fdx, err := os.OpenFile(outf, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			die("can't create output file %s: %s", outf, err)
		}
		defer fdx.Close()
		fd = fdx
	}

	fd.Write(sigo)
}

// Verify signature on a given file
func verify(args []string) {
	var help, quiet bool

	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.BoolVarP(&help, "help", "h", false, "Show this help and exit")
	fs.BoolVarP(&quiet, "quiet", "q", false, "Don't show any output; exit with status code only [False]")

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
		die("Insufficient arguments to 'verify'. Try '%s verify -h' ..", Z)
	}

	pn := args[0]
	sn := args[1]
	fn := args[2]

	sig, err := sign.ReadSignature(sn)
	if err != nil {
		die("Can't read signature '%s': %s", sn, err)
	}

	pk, err := sign.ReadPublicKey(pn)
	if err != nil {
		die("%s", err)
	}

	if !sig.IsPKMatch(pk) {
		die("Wrong public key '%s' for verifying '%s'", pn, sn)
	}

	ok, err := pk.VerifyFile(fn, sig)
	if err != nil {
		die("%s", err)
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
  -v, --version    Show version info and exit.

Commands:
  generate, g      Generate a new Ed25519 keypair
  sign, s          Sign a file with a private key
  verify, v        Verify a signature against a file and a public key
`, Z, Z)

	os.Stdout.Write([]byte(x))
	os.Exit(c)
}

// Return true if $bn.key or $bn.pub exist; false otherwise
func exists(bn string) bool {
	pk := bn + ".pub"
	sk := bn + ".key"

	if _, err := os.Stat(pk); err == nil {
		return true
	}
	if _, err := os.Stat(sk); err == nil {
		return true
	}

	return false
}

// die with error
func die(f string, v ...interface{}) {
	warn(f, v...)
	os.Exit(1)
}

func warn(f string, v ...interface{}) {
	z := fmt.Sprintf("%s: %s", os.Args[0], f)
	s := fmt.Sprintf(z, v...)
	if n := len(s); s[n-1] != '\n' {
		s += "\n"
	}

	os.Stderr.WriteString(s)
	os.Stderr.Sync()
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
