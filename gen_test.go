// gen_test.go - scaffolding to generate protobuf code as needed
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
//

package sigtool

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

const _Script = "./gen-proto.sh"

// XXX This only works on Unix-like platforms.
//
// TODO Add support for windows. Gah.
func TestMain(m *testing.M) {
	cmd := exec.Command(_Script)
	cmd.Dir = "."
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n%s: %s\n", _Script, err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestEmpty(t *testing.T) {
}
