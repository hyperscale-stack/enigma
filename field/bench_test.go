package field

import (
	"bytes"
	"context"
	"testing"

	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

func BenchmarkEncryptDecryptValue(b *testing.B) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "field-bench")
	if err != nil {
		b.Fatalf("Generate: %v", err)
	}
	payload := bytes.Repeat([]byte("x"), 256)

	b.Run("encrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := EncryptValue(context.Background(), payload, WithRecipient(r)); err != nil {
				b.Fatalf("EncryptValue: %v", err)
			}
		}
	})

	blob, err := EncryptValue(context.Background(), payload, WithRecipient(r))
	if err != nil {
		b.Fatalf("EncryptValue setup: %v", err)
	}

	b.Run("decrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := DecryptValue(context.Background(), blob, WithRecipient(r)); err != nil {
				b.Fatalf("DecryptValue: %v", err)
			}
		}
	})
}
