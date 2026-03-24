package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hyperscale-stack/enigma/document"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
	"github.com/stretchr/testify/assert"
)

func TestMainUsageExitCode(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "ENIGMA_INSPECT_HELPER=1")
	err := cmd.Run()
	assert.Error(t, err)
	if exitErr, ok := err.(*exec.ExitError); ok {
		assert.Equal(t, 2, exitErr.ExitCode())
	}
}

func TestMainSuccess(t *testing.T) {
	tmp := t.TempDir()
	plain := filepath.Join(tmp, "plain.txt")
	enc := filepath.Join(tmp, "plain.enc")
	assert.NoError(t, os.WriteFile(plain, []byte("inspect-cli"), 0o600))
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "cli")
	assert.NoError(t, err)
	assert.NoError(t, document.EncryptFile(context.Background(), plain, enc, document.WithRecipient(r)))

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", enc)
	cmd.Env = append(os.Environ(), "ENIGMA_INSPECT_HELPER=1")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)
	assert.True(t, strings.Contains(string(out), "\"Version\""))
}

func TestMainInspectFailureExitCode(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", "/does/not/exist.enc")
	cmd.Env = append(os.Environ(), "ENIGMA_INSPECT_HELPER=1")
	err := cmd.Run()
	assert.Error(t, err)
	if exitErr, ok := err.(*exec.ExitError); ok {
		assert.Equal(t, 1, exitErr.ExitCode())
	}
}

func TestMainEncodeFailureExitCode(t *testing.T) {
	tmp := t.TempDir()
	plain := filepath.Join(tmp, "plain.txt")
	enc := filepath.Join(tmp, "plain.enc")
	assert.NoError(t, os.WriteFile(plain, []byte("inspect-cli"), 0o600))
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "cli-encode-fail")
	assert.NoError(t, err)
	assert.NoError(t, document.EncryptFile(context.Background(), plain, enc, document.WithRecipient(r)))

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", enc)
	cmd.Env = append(os.Environ(), "ENIGMA_INSPECT_HELPER=1", "ENIGMA_INSPECT_CLOSE_STDOUT=1")
	err = cmd.Run()
	assert.Error(t, err)
	if exitErr, ok := err.(*exec.ExitError); ok {
		assert.Equal(t, 1, exitErr.ExitCode())
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("ENIGMA_INSPECT_HELPER") != "1" {
		return
	}

	if os.Getenv("ENIGMA_INSPECT_CLOSE_STDOUT") == "1" {
		_ = os.Stdout.Close()
	}

	args := []string{os.Args[0]}
	for i, a := range os.Args {
		if a == "--" {
			args = append(args, os.Args[i+1:]...)
			break
		}
	}
	os.Args = args
	main()
}
