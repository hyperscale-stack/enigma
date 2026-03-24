package localmlkem

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
)

func TestWrapUnwrapRoundTrip768(t *testing.T) {
	r, err := Generate(MLKEM768, "key-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	dek := []byte("01234567890123456789012345678901")
	wk, err := r.WrapKey(context.Background(), dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	out, err := r.UnwrapKey(context.Background(), wk)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if string(out) != string(dek) {
		t.Fatalf("dek mismatch")
	}
}

func TestWrapUnwrapWrongKey(t *testing.T) {
	r1, err := Generate(MLKEM768, "key-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r2, err := Generate(MLKEM768, "key-2")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	dek := []byte("01234567890123456789012345678901")
	wk, err := r1.WrapKey(context.Background(), dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	_, err = r2.UnwrapKey(context.Background(), wk)
	if err == nil {
		t.Fatalf("expected unwrap error")
	}
	if !errors.Is(err, enigma.ErrRecipientNotFound) && !errors.Is(err, enigma.ErrUnwrapFailed) {
		t.Fatalf("expected recipient/unwrap error, got: %v", err)
	}
}
