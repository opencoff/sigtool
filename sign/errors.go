// errors.go - list of all exportable errors in this module
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

package sign

import (
	"errors"
)

var (
	ErrClosed         = errors.New("encrypt: stream already closed")
	ErrNoKey          = errors.New("decrypt: No private key set for decryption")
	ErrEncStarted     = errors.New("encrypt: can't add new recipient after encryption has started")
	ErrDecStarted     = errors.New("decrypt: can't add new recipient after decryption has started")
	ErrEncIsStream    = errors.New("encrypt: can't use Encrypt() after using streaming I/O")
	ErrNotSigTool     = errors.New("decrypt: Not a sigtool encrypted file?")
	ErrHeaderTooBig   = errors.New("decrypt: header too large (max 1048576)")
	ErrHeaderTooSmall = errors.New("decrypt: header too small (min 32)")
	ErrBadHeader      = errors.New("decrypt: header corrupted")
	ErrNoWrappedKeys  = errors.New("decrypt: No wrapped keys in encrypted file")
	ErrBadKey         = errors.New("decrypt: wrong key")
	ErrBadSender      = errors.New("unwrap: sender verification failed")

	ErrIncorrectPassword = errors.New("ssh: invalid passphrase")
	ErrNoPEMFound        = errors.New("ssh: no PEM block found")
	ErrBadPublicKey      = errors.New("ssh: malformed public key")
	ErrKeyTooShort       = errors.New("ssh: public key too short")
	ErrBadTrailers       = errors.New("ssh: trailing junk in public key")
	ErrBadFormat         = errors.New("ssh: invalid openssh private key format")
	ErrBadLength         = errors.New("ssh: private key unexpected length")
	ErrBadPadding        = errors.New("ssh: padding not as expected")
)
