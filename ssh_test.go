// ssh_test.go -- Test harness for SSH key support
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

package sigtool

import (
	"strings"
	"testing"
)

// Test fixture: OpenSSH Ed25519 private key (unencrypted)
const sshPrivateKeyUnencrypted = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBqxKnVGIJRIwnYJVJQ7dS7xKxBHxKqJxJxqxBRxKq0IwAAAJgQxJxQEMSc
UAAAAAATZW4yNTUxOQAAACBqxKnVGIJRIwnYJVJQ7dS7xKxBHxKqJxJxqxBRxKq0IwAAAE
DXeF8V8qxJKxQ1YJRxQxJVJxKqxBRxKxBJxKqxQRVGoWrEqdUYglEjCdglUlDt1LvErEEf
EqonEnGrEFHEqrQjAAAAE3Rlc3QtdW5lbmNyeXB0ZWQta2V5AQIDBA==
-----END OPENSSH PRIVATE KEY-----
`

// Test fixture: OpenSSH Ed25519 public key (for the unencrypted private key above)
const sshPublicKeyUnencrypted = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrEqdUYglEjCdglUlDt1LvErEEfEqonEnGrEFHEqrQj test-unencrypted-key`

// Multiple keys in authorized_keys format
const authorizedKeysMultiple = `# This is a comment
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrEqdUYglEjCdglUlDt1LvErEEfEqonEnGrEFHEqrQj first-key

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHaBcDefGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp second-key
# Another comment
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPqRsTuvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf third-key
`

// authorized_keys with mixed key types
const authorizedKeysMixed = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... rsa-key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrEqdUYglEjCdglUlDt1LvErEEfEqonEnGrEFHEqrQj ed25519-key
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY... ecdsa-key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHaBcDefGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp another-ed25519
`

// authorized_keys with options
const authorizedKeysWithOptions = `restrict,command="/usr/bin/foo" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrEqdUYglEjCdglUlDt1LvErEEfEqonEnGrEFHEqrQj restricted-key
from="192.168.1.0/24",no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHaBcDefGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp limited-key
`

// Empty and comment-only authorized_keys
const authorizedKeysEmpty = ``
const authorizedKeysCommentsOnly = `# Just comments
# Nothing but comments
   # More comments with leading spaces
`

// authorized_keys with blank lines and weird spacing
const authorizedKeysWeirdSpacing = `

# Comment

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrEqdUYglEjCdglUlDt1LvErEEfEqonEnGrEFHEqrQj   key-with-spaces


ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHaBcDefGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp	key-with-tab

`

func TestSSHPublicKeyParsing(t *testing.T) {
	assert := newAsserter(t)

	// Test parsing a single SSH public key
	pk, err := parseSSHPublicKey([]byte(sshPublicKeyUnencrypted))
	assert(err == nil, "parseSSHPublicKey failed: %s", err)
	assert(pk != nil, "parseSSHPublicKey returned nil")
	assert(pk.Comment == "test-unencrypted-key", "comment mismatch: got %q", pk.Comment)

	// Verify the fingerprint is generated
	fp := pk.Fingerprint()
	assert(fp != "", "fingerprint is empty")
	assert(len(fp) > 0, "fingerprint length is 0")
}

func TestSSHPublicKeyErrors(t *testing.T) {
	assert := newAsserter(t)

	// Malformed public key - missing parts
	_, err := parseSSHPublicKey([]byte("ssh-ed25519"))
	assert(err != nil, "malformed key should error")

	// Malformed public key - only 2 parts
	_, err = parseSSHPublicKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"))
	assert(err != nil, "incomplete key should error")

	// Invalid base64
	_, err = parseSSHPublicKey([]byte("ssh-ed25519 !!!invalid-base64!!! comment"))
	assert(err != nil, "invalid base64 should error")

	// Non-Ed25519 key type (RSA) - should return nil, not error
	rsakey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 rsa-comment"
	pk, err := parseSSHPublicKey([]byte(rsakey))
	assert(pk == nil, "RSA key should return nil pk")
	// Note: parseSSHPublicKey returns nil for non-Ed25519, not an error
}

func TestParseAuthorizedKeys(t *testing.T) {
	assert := newAsserter(t)

	// Test single key
	pks, err := ParseAuthorizedKeys([]byte(sshPublicKeyUnencrypted))
	assert(err == nil, "ParseAuthorizedKeys single failed: %s", err)
	assert(len(pks) == 1, "expected 1 key, got %d", len(pks))
	assert(pks[0].Comment == "test-unencrypted-key", "comment mismatch")

	// Test multiple keys
	pks, err = ParseAuthorizedKeys([]byte(authorizedKeysMultiple))
	assert(err == nil, "ParseAuthorizedKeys multiple failed: %s", err)
	assert(len(pks) == 3, "expected 3 keys, got %d", len(pks))
	assert(pks[0].Comment == "first-key", "first key comment mismatch: %q", pks[0].Comment)
	assert(pks[1].Comment == "second-key", "second key comment mismatch: %q", pks[1].Comment)
	assert(pks[2].Comment == "third-key", "third key comment mismatch: %q", pks[2].Comment)

	// Each key should have a fingerprint
	for i, pk := range pks {
		fp := pk.Fingerprint()
		assert(fp != "", "key %d fingerprint is empty", i)
	}
}

func TestParseAuthorizedKeysMixedTypes(t *testing.T) {
	assert := newAsserter(t)

	// Test with mixed key types - should only return Ed25519 keys
	pks, err := ParseAuthorizedKeys([]byte(authorizedKeysMixed))
	assert(err == nil, "ParseAuthorizedKeys mixed failed: %s", err)
	assert(len(pks) == 2, "expected 2 Ed25519 keys, got %d", len(pks))

	// Verify they are the Ed25519 keys
	assert(pks[0].Comment == "ed25519-key", "first ed25519 key comment mismatch")
	assert(pks[1].Comment == "another-ed25519", "second ed25519 key comment mismatch")
}

func TestParseAuthorizedKeysWithOptions(t *testing.T) {
	assert := newAsserter(t)

	// Keys with SSH options should still parse
	pks, err := ParseAuthorizedKeys([]byte(authorizedKeysWithOptions))
	assert(err == nil, "ParseAuthorizedKeys with options failed: %s", err)
	assert(len(pks) == 2, "expected 2 keys, got %d", len(pks))
	assert(pks[0].Comment == "restricted-key", "first key comment mismatch")
	assert(pks[1].Comment == "limited-key", "second key comment mismatch")
}

func TestParseAuthorizedKeysEmpty(t *testing.T) {
	assert := newAsserter(t)

	// Empty file
	pks, err := ParseAuthorizedKeys([]byte(authorizedKeysEmpty))
	assert(err == nil, "ParseAuthorizedKeys empty failed: %s", err)
	assert(len(pks) == 0, "expected 0 keys for empty file, got %d", len(pks))

	// Comments only
	pks, err = ParseAuthorizedKeys([]byte(authorizedKeysCommentsOnly))
	assert(err == nil, "ParseAuthorizedKeys comments-only failed: %s", err)
	assert(len(pks) == 0, "expected 0 keys for comments-only, got %d", len(pks))
}

func TestParseAuthorizedKeysWeirdSpacing(t *testing.T) {
	assert := newAsserter(t)

	// Test with various spacing and blank lines
	pks, err := ParseAuthorizedKeys([]byte(authorizedKeysWeirdSpacing))
	assert(err == nil, "ParseAuthorizedKeys spacing failed: %s", err)
	assert(len(pks) == 2, "expected 2 keys, got %d", len(pks))

	// Comments should be trimmed
	assert(strings.TrimSpace(pks[0].Comment) == "key-with-spaces", "first key comment mismatch: %q", pks[0].Comment)
	assert(strings.TrimSpace(pks[1].Comment) == "key-with-tab", "second key comment mismatch: %q", pks[1].Comment)
}

func TestParseAuthorizedKeysLineEndings(t *testing.T) {
	assert := newAsserter(t)

	// Test with Windows line endings (\r\n)
	windowsKeys := strings.ReplaceAll(authorizedKeysMultiple, "\n", "\r\n")
	pks, err := ParseAuthorizedKeys([]byte(windowsKeys))
	assert(err == nil, "ParseAuthorizedKeys windows line endings failed: %s", err)
	assert(len(pks) == 3, "expected 3 keys with windows endings, got %d", len(pks))
}

func TestParseAuthorizedKeysVerifySignatures(t *testing.T) {
	assert := newAsserter(t)

	// Parse a public key from authorized_keys format
	pks, err := ParseAuthorizedKeys([]byte(sshPublicKeyUnencrypted))
	assert(err == nil, "ParseAuthorizedKeys failed: %s", err)
	assert(len(pks) == 1, "expected 1 key, got %d", len(pks))

	// Verify we got a valid public key
	assert(pks[0] != nil, "parsed public key is nil")
	assert(pks[0].Comment == "test-unencrypted-key", "comment mismatch: got %q", pks[0].Comment)

	// Create a sigtool private key and verify they're compatible
	sk, err := NewPrivateKey("test-sig-compatibility")
	assert(err == nil, "NewPrivateKey failed: %s", err)

	// Sign a message with the sigtool key
	msg := []byte("test message for signature verification")
	sig, err := sk.SignMessage(msg)
	assert(err == nil, "SignMessage failed: %s", err)

	// Verify with sigtool public key (should work)
	sigPk := sk.PublicKey()
	ok, err := sigPk.VerifyMessage(msg, sig)
	assert(err == nil, "VerifyMessage failed: %s", err)
	assert(ok, "signature verification failed")

	// Note: We can't easily test cross-verification with the SSH key
	// without actually having a matching SSH private key to sign with.
	// This would require either:
	// 1. Real ssh-keygen generated keys
	// 2. Or implementing SSH signature format (different from sigtool)
}

// vim: noexpandtab:ts=8:sw=8:tw=92:
