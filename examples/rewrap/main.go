package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/hyperscale-stack/enigma/document"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

func main() {
	rOld, err := localmlkem.Generate(localmlkem.MLKEM768, "old-key")
	if err != nil {
		panic(err)
	}
	rNew, err := localmlkem.Generate(localmlkem.MLKEM768, "new-key")
	if err != nil {
		panic(err)
	}

	tmpDir, err := os.MkdirTemp("", "enigma-example-rewrap")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	plainPath := filepath.Join(tmpDir, "plain.txt")
	srcPath := filepath.Join(tmpDir, "payload.enc")
	dstPath := filepath.Join(tmpDir, "payload.rewrapped.enc")
	decPath := filepath.Join(tmpDir, "plain.dec.txt")

	if err := os.WriteFile(plainPath, []byte("rewrap payload"), 0o600); err != nil {
		panic(err)
	}
	if err := document.EncryptFile(context.Background(), plainPath, srcPath, document.WithRecipient(rOld)); err != nil {
		panic(err)
	}
	if err := document.Rewrap(context.Background(), srcPath, dstPath,
		document.WithRecipient(rOld),
		document.WithNewRecipient(rNew),
		document.WithReplaceRecipients(),
	); err != nil {
		panic(err)
	}
	if err := document.DecryptFile(context.Background(), dstPath, decPath, document.WithRecipient(rNew)); err != nil {
		panic(err)
	}
	out, err := os.ReadFile(decPath)
	if err != nil {
		panic(err)
	}
	_, _ = os.Stdout.Write(append(out, '\n'))
}
