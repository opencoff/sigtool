// die.go -- die() and warn()
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
)

var atExit []func()

// Die prints an error message to stderr
// and exits the program after calling all the registered
// at-exit functions.
func Die(f string, v ...interface{}) {
	Warn(f, v...)
	Exit(1)
}

// Warn prints an error message to stderr
func Warn(f string, v ...interface{}) {
	z := fmt.Sprintf("%s: %s", os.Args[0], f)
	s := fmt.Sprintf(z, v...)
	if n := len(s); s[n-1] != '\n' {
		s += "\n"
	}

	os.Stderr.WriteString(s)
	os.Stderr.Sync()
}

// AtExit registers a function to be called before the program exits.
func AtExit(f func()) {
	atExit = append(atExit, f)
}

// Exit invokes the registered atexit handlers and exits with the
// given code.
func Exit(v int) {
	for _, f := range atExit {
		f()
	}
	os.Exit(v)
}
