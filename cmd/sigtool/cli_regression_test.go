package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/opencoff/sigtool"
)

func TestEnvPasswordUnsetFails(t *testing.T) {
	const envName = "SIGTOOL_TEST_MISSING_PASSWORD"
	if err := os.Unsetenv(envName); err != nil {
		t.Fatalf("unset env: %s", err)
	}

	getpw := maybeGetPw(false, envName, false)
	pw, err := getpw()
	if err == nil {
		t.Fatalf("unset --env-password %s returned passphrase %q", envName, string(pw))
	}
}

func TestEncryptRejectsSameInputAndOutput(t *testing.T) {
	dn := t.TempDir()
	infile := filepath.Join(dn, "plain.txt")
	pubfile := filepath.Join(dn, "recipient.pub")

	if err := os.WriteFile(infile, []byte("plaintext"), 0600); err != nil {
		t.Fatalf("write input: %s", err)
	}
	writeRecipientPublicKey(t, pubfile)

	cmd := helperCommand(t, "encrypt", "--overwrite", "-o", infile, pubfile, infile)
	err := cmd.Run()
	if err == nil {
		t.Fatal("encrypt succeeded with identical input and output file")
	}
}

func TestDecryptRejectsSameInputAndOutput(t *testing.T) {
	dn := t.TempDir()
	encfile := filepath.Join(dn, "cipher.sigtool")
	keyfile := filepath.Join(dn, "recipient.key")

	sk, err := sigtool.NewPrivateKey(t.Name())
	if err != nil {
		t.Fatalf("new private key: %s", err)
	}
	writePrivateKey(t, keyfile, sk)

	var encrypted bytes.Buffer
	enc, err := sigtool.NewEncryptor(nil, sk.PublicKey(), bytes.NewReader([]byte("plaintext")), nopWriteCloser{&encrypted}, 0)
	if err != nil {
		t.Fatalf("new encryptor: %s", err)
	}
	if err := enc.Encrypt(); err != nil {
		t.Fatalf("encrypt fixture: %s", err)
	}
	if err := os.WriteFile(encfile, encrypted.Bytes(), 0600); err != nil {
		t.Fatalf("write encrypted input: %s", err)
	}

	cmd := helperCommand(t, "decrypt", "--no-password", "--overwrite", "-o", encfile, keyfile, encfile)
	err = cmd.Run()
	if err == nil {
		t.Fatal("decrypt succeeded with identical input and output file")
	}
}

func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("SIGTOOL_CLI_HELPER") != "1" {
		return
	}

	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(2)
	}

	switch args[1] {
	case "encrypt":
		encrypt(args[2:])
	case "decrypt":
		decrypt(args[2:])
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

type nopWriteCloser struct {
	*bytes.Buffer
}

func (w nopWriteCloser) Close() error {
	return nil
}

func helperCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()

	all := append([]string{"-test.run=TestCLIHelperProcess", "--"}, args...)
	cmd := exec.Command(os.Args[0], all...)
	cmd.Env = append(os.Environ(), "SIGTOOL_CLI_HELPER=1")
	return cmd
}

func writeRecipientPublicKey(t *testing.T, fn string) {
	t.Helper()

	sk, err := sigtool.NewPrivateKey(t.Name())
	if err != nil {
		t.Fatalf("new private key: %s", err)
	}
	b, err := sk.PublicKey().Marshal()
	if err != nil {
		t.Fatalf("marshal public key: %s", err)
	}
	if err := os.WriteFile(fn, b, 0644); err != nil {
		t.Fatalf("write public key: %s", err)
	}
}

func writePrivateKey(t *testing.T, fn string, sk *sigtool.PrivateKey) {
	t.Helper()

	b, err := sk.Marshal(func() ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatalf("marshal private key: %s", err)
	}
	if err := os.WriteFile(fn, b, 0600); err != nil {
		t.Fatalf("write private key: %s", err)
	}
}
