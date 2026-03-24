package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/hyperscale-stack/enigma/document"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

func main() {
	tmpDir, err := os.MkdirTemp("", "enigma-example-doc")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	plainPath := filepath.Join(tmpDir, "plain.txt")
	encPath := filepath.Join(tmpDir, "plain.txt.enc")
	decPath := filepath.Join(tmpDir, "plain.dec.txt")

	if err := os.WriteFile(plainPath, []byte("example document payload"), 0o600); err != nil {
		panic(err)
	}
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "example-local-key")
	if err != nil {
		panic(err)
	}
	if err := document.EncryptFile(context.Background(), plainPath, encPath, document.WithRecipient(r)); err != nil {
		panic(err)
	}
	if err := document.DecryptFile(context.Background(), encPath, decPath, document.WithRecipient(r)); err != nil {
		panic(err)
	}
	out, err := os.ReadFile(decPath)
	if err != nil {
		panic(err)
	}
	_, _ = os.Stdout.Write(append(out, '\n'))
}
