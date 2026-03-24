package main

import (
	"bytes"
	"context"
	"io"
	"os"

	"github.com/hyperscale-stack/enigma/document"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

func main() {
	r1, err := localmlkem.Generate(localmlkem.MLKEM768, "team-a")
	if err != nil {
		panic(err)
	}
	r2, err := localmlkem.Generate(localmlkem.MLKEM768, "team-b")
	if err != nil {
		panic(err)
	}

	var encrypted bytes.Buffer
	w, err := document.NewEncryptWriter(context.Background(), &encrypted, document.WithRecipient(r1), document.WithRecipient(r2))
	if err != nil {
		panic(err)
	}
	if _, err := w.Write([]byte("shared payload")); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}

	rd, err := document.NewDecryptReader(context.Background(), bytes.NewReader(encrypted.Bytes()), document.WithRecipient(r2))
	if err != nil {
		panic(err)
	}
	out, err := io.ReadAll(rd)
	if err != nil {
		panic(err)
	}
	_, _ = os.Stdout.Write(append(out, '\n'))
}
