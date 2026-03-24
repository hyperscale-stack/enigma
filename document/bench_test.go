package document

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

func BenchmarkEncryptDecrypt(b *testing.B) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "bench")
	if err != nil {
		b.Fatalf("Generate: %v", err)
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<14)
	b.Run("encrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var out bytes.Buffer
			w, err := NewEncryptWriter(context.Background(), &out, WithRecipient(r), WithChunkSize(4096))
			if err != nil {
				b.Fatalf("NewEncryptWriter: %v", err)
			}
			if _, err := w.Write(payload); err != nil {
				b.Fatalf("Write: %v", err)
			}
			if err := w.Close(); err != nil {
				b.Fatalf("Close: %v", err)
			}
		}
	})

	var encrypted bytes.Buffer
	w, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r), WithChunkSize(4096))
	if err != nil {
		b.Fatalf("NewEncryptWriter: %v", err)
	}
	_, _ = w.Write(payload)
	_ = w.Close()
	cipherBlob := encrypted.Bytes()

	b.Run("decrypt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			rd, err := NewDecryptReader(context.Background(), bytes.NewReader(cipherBlob), WithRecipient(r))
			if err != nil {
				b.Fatalf("NewDecryptReader: %v", err)
			}
			if _, err := io.Copy(io.Discard, rd); err != nil {
				b.Fatalf("Copy: %v", err)
			}
		}
	})
}
