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

	"github.com/opencoff/go-options"
	"github.com/opencoff/go-sign"
	"github.com/opencoff/go-utils"
)

// This will be filled in by "build"
var Version string = "1.0"

var Z string = path.Base(os.Args[0])

// die with error
func die(f string, v ...interface{}) {
	z := fmt.Sprintf("%s: %s", Z, f)
	s := fmt.Sprintf(z, v...)
	if n := len(s); s[n-1] != '\n' {
		s += "\n"
	}

	os.Stderr.WriteString(s)
	os.Exit(1)
}

// Option parsing spec for the main program
var Maindesc = fmt.Sprintf(`
Usage: %s [options] command [options ..] [args ..]

%s is a tool to generate, sign and verify files with Ed25519 signatures.
--
#      Options
help   -h,--help        Show this help message and exit
ver    -v,--version     Show version info and exit
--
--
#      Commands
gen    generate,gen      Generate a new Ed25519 keypair
sign   sign, s           Sign a file with a private key
verify verify, v         Verify a signature against a file and public key
--`, Z, Z)

// Option parsing spec for key gen
var Gendesc = fmt.Sprintf(`
Usage: %s generate [options] path-prefix

Generate a new Ed25519 public/private key pair. The public key is written
to PATH-PREFIX.pub and private key to PATH-PREFIX.key.
--
#        Options
help     -h,--help         Show this help message and exit
pw       -p,--passwd       Ask for a passphrase to encrypt the private key
comment= -c=,--comment=    Use 'C' as the text comment for the keys []
envpw=   -e=E,--env-pass=E Use passphrase from environment var E []
force    -F,--force        Overwrite the output file if it exists [false]
--
--
*
--`, Z)

// Option parsing spec for signing a file
var Signdesc = fmt.Sprintf(`
Usage: %s sign [options] privkey file

Sign FILE with an Ed25519 PRIVKEY and write the signature to STDOUT.
--
#        Options
help     -h,--help         Show this help message and exit
pw       -p,--passwd       Ask for a passphrase to decrypt the private key
envpw=   -e=E,--env-pass=E Use passphrase from environment var E []
output=- -o=F,--output=F   Write signature to file F [STDOUT]
--
--
*
--`, Z)

// Option parsing spec for signature verification
var Verifydesc = fmt.Sprintf(`
Usage: %s verify [options] pubkey sig file

Verify signature SIG of FILE using Ed25519 public key in PUBKEY.
--
#        Options
help     -h,--help        Show this help message and exit
quiet    -q,--quiet       Don't show any output, exit with status code
--
--
*
--`, Z)

// Run the generate command
func gen(s *options.Spec, opt *options.Options) {
	if opt.GetBool("help") {
		s.PrintUsageAndExit()
	}

	if len(opt.Args) < 1 {
		s.PrintUsageWithError(fmt.Errorf("Missing path-prefix."))
	}

	bn := opt.Args[0]

	if exists(bn) && !opt.GetBool("force") {
		die("%s: Public/Private key files (%s.key, %s.pub) exist. Won't overwrite!", Z, bn, bn)
	}

	var pw string
	var comm string
	var err error

	if pwenv, ok := opt.Get("envpw"); ok {
		pw = os.Getenv(pwenv)
	} else if opt.GetBool("pw") {
		pw, err = utils.Askpass("Enter passphrase for private key", true)
		if err != nil {
			die("%s: %s", Z, err)
		}
	}

	comm, _ = opt.Get("comment")

	kp, err := sign.NewKeypair()
	if err != nil {
		die("%s: %s", Z, err)
	}

	err = kp.Serialize(bn, comm, pw)
	if err != nil {
		die("%s: %s", Z, err)
	}
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

// Run the 'sign' command.
func signify(s *options.Spec, opt *options.Options) {
	if opt.GetBool("help") {
		s.PrintUsageAndExit()
	}

	if len(opt.Args) < 2 {
		s.PrintUsageWithError(fmt.Errorf("Missing arguments (key? file?)"))
	}

	var pw string
	var err error
	var fd io.Writer = os.Stdout

	if pwenv, ok := opt.Get("envpw"); ok {
		pw = os.Getenv(pwenv)
	} else if opt.GetBool("pw") {
		pw, err = utils.Askpass("Enter passphrase for private key", false)
		if err != nil {
			die("%s: %s", Z, err)
		}
	}

	if outf, ok := opt.Get("output"); ok {
		if outf != "-" {
			fdx, err := os.OpenFile(outf, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				die("%s: Can't create output file %s: %s", Z, outf, err)
			}
			defer fdx.Close()

			fd = fdx
		}
	}

	kn := opt.Args[0]
	fn := opt.Args[1]

	pk, err := sign.ReadPrivateKey(kn, pw)
	if err != nil {
		die("%s: %s", Z, err)
	}

	sig, err := pk.SignFile(fn)
	if err != nil {
		die("%s: %s", Z, err)
	}

	sigo, err := sig.Serialize(fmt.Sprintf("inpfile=%s", fn))

	fd.Write(sigo)
}

// Verify signature on a given file
func verify(s *options.Spec, opt *options.Options) {
	if opt.GetBool("help") {
		s.PrintUsageAndExit()
	}

	if len(opt.Args) < 3 {
		s.PrintUsageWithError(fmt.Errorf("Missing arguments (key? file? pubkey?)"))
	}

	pn := opt.Args[0]
	sn := opt.Args[1]
	fn := opt.Args[2]

	sig, err := sign.ReadSignature(sn)
	if err != nil {
		die("%s: Can't read signature '%s': %s", Z, sn, err)
	}

	pk, err := sign.ReadPublicKey(pn)
	if err != nil {
		die("%s: %s", Z, err)
	}

	if !sig.IsPKMatch(pk) {
		die("Wrong public key '%s' for verifying '%s'", pn, sn)
	}

	ok, err := pk.VerifyFile(fn, sig)
	if err != nil {
		die("%s: %s", Z, err)
	}

	exit := 0
	if !ok {
		exit = 1
	}

	if !opt.GetBool("quiet") {
		if ok {
			fmt.Printf("%s: Signature %s verified\n", fn, sn)
		} else {
			fmt.Printf("%s: Signature %s verification failure\n", fn, sn)
		}
	}

	os.Exit(exit)
}

func main() {

	var env = []string{}

	spec := options.MustParse(Maindesc)
	gspec := options.MustParse(Gendesc)
	sspec := options.MustParse(Signdesc)
	vspec := options.MustParse(Verifydesc)

	opts, err := spec.Interpret(os.Args, env)
	if err != nil {
		die("%s", err)
	}

	if opts.GetBool("help") {
		spec.PrintUsageAndExit()
	}
	if opts.GetBool("ver") {
		fmt.Printf("%s: %s\n", Z, Version)
		os.Exit(0)
	}

	switch opts.Command {
	case "gen":
		o, err := gspec.Interpret(opts.Args, env)
		if err != nil {
			die("%s", err)
		}
		gen(gspec, o)

	case "sign":
		ox, err := sspec.Interpret(opts.Args, env)
		if err != nil {
			die("%s", err)
		}
		signify(sspec, ox)

	case "verify":
		ox, err := vspec.Interpret(opts.Args, env)
		if err != nil {
			die("%s", err)
		}
		verify(vspec, ox)

	default:
		die("%s: Forgot to add code for command %s", Z, opts.Command)
	}

}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
