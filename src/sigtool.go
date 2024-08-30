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
		fmt.Printf("%s - %s [%s]\n", Z, ProductVersion, RepoVersion)
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

// Verify signature on a given file

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
var ProductVersion string = "UNDEFINED"

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
