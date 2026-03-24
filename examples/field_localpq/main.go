package main

import (
	"context"
	"os"

	"github.com/hyperscale-stack/enigma/field"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

func main() {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "example-field-key")
	if err != nil {
		panic(err)
	}
	ciphertext, err := field.EncryptValue(context.Background(), []byte("sensitive-value"), field.WithRecipient(r))
	if err != nil {
		panic(err)
	}
	plaintext, err := field.DecryptValue(context.Background(), ciphertext, field.WithRecipient(r))
	if err != nil {
		panic(err)
	}
	_, _ = os.Stdout.Write(append(plaintext, '\n'))
}
