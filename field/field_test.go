package field

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

func TestEncryptDecryptValueRoundTrip(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "field-key")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	plaintext := []byte("database-secret-value")
	ciphertext, err := EncryptValue(context.Background(), plaintext, WithRecipient(r))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	out, err := DecryptValue(context.Background(), ciphertext, WithRecipient(r))
	if err != nil {
		t.Fatalf("DecryptValue: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestDecryptWrongRecipientFails(t *testing.T) {
	r1, err := localmlkem.Generate(localmlkem.MLKEM768, "field-key-1")
	if err != nil {
		t.Fatalf("Generate r1: %v", err)
	}
	r2, err := localmlkem.Generate(localmlkem.MLKEM768, "field-key-2")
	if err != nil {
		t.Fatalf("Generate r2: %v", err)
	}
	ciphertext, err := EncryptValue(context.Background(), []byte("value"), WithRecipient(r1))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	_, err = DecryptValue(context.Background(), ciphertext, WithRecipient(r2))
	if err == nil {
		t.Fatalf("expected unwrap failure")
	}
	if !errors.Is(err, enigma.ErrUnwrapFailed) {
		t.Fatalf("expected ErrUnwrapFailed, got %v", err)
	}
}

func TestMalformedValueBlob(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "field-key")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ciphertext, err := EncryptValue(context.Background(), []byte("value"), WithRecipient(r))
	if err != nil {
		t.Fatalf("EncryptValue: %v", err)
	}
	ciphertext[4] = 99
	_, err = DecryptValue(context.Background(), ciphertext, WithRecipient(r))
	if err == nil {
		t.Fatalf("expected unsupported version")
	}
	if !errors.Is(err, enigma.ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}
