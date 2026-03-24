package document

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/container"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

func TestDocumentRoundTripSmall(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "key-a")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	plaintext := []byte("hello encrypted document")
	var encrypted bytes.Buffer
	w, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r))
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rd, err := NewDecryptReader(context.Background(), bytes.NewReader(encrypted.Bytes()), WithRecipient(r))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	out, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := rd.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestDocumentRoundTripLargeStreaming(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "key-a")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	plaintext := bytes.Repeat([]byte("0123456789abcdef"), 1<<15)
	var encrypted bytes.Buffer
	w, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r), WithChunkSize(4096))
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	for i := 0; i < len(plaintext); i += 777 {
		end := i + 777
		if end > len(plaintext) {
			end = len(plaintext)
		}
		if _, err := w.Write(plaintext[i:end]); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rd, err := NewDecryptReader(context.Background(), bytes.NewReader(encrypted.Bytes()), WithRecipient(r))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	out, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestMultiRecipientDecrypt(t *testing.T) {
	r1, err := localmlkem.Generate(localmlkem.MLKEM768, "key-a")
	if err != nil {
		t.Fatalf("Generate r1: %v", err)
	}
	r2, err := localmlkem.Generate(localmlkem.MLKEM768, "key-b")
	if err != nil {
		t.Fatalf("Generate r2: %v", err)
	}
	plaintext := []byte("secret")
	var encrypted bytes.Buffer
	w, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r1), WithRecipient(r2))
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rd, err := NewDecryptReader(context.Background(), bytes.NewReader(encrypted.Bytes()), WithRecipient(r2))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	out, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestWrongRecipientFails(t *testing.T) {
	r1, err := localmlkem.Generate(localmlkem.MLKEM768, "key-a")
	if err != nil {
		t.Fatalf("Generate r1: %v", err)
	}
	r2, err := localmlkem.Generate(localmlkem.MLKEM768, "key-b")
	if err != nil {
		t.Fatalf("Generate r2: %v", err)
	}
	var encrypted bytes.Buffer
	w, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r1))
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := w.Write([]byte("secret")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = NewDecryptReader(context.Background(), bytes.NewReader(encrypted.Bytes()), WithRecipient(r2))
	if err == nil {
		t.Fatalf("expected unwrap failure")
	}
	if !errors.Is(err, enigma.ErrUnwrapFailed) {
		t.Fatalf("expected ErrUnwrapFailed, got %v", err)
	}
}

func TestCorruptedHeaderFails(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "key-a")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var encrypted bytes.Buffer
	w, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r))
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	_, _ = w.Write([]byte("secret"))
	_ = w.Close()

	blob := encrypted.Bytes()
	h, offset, err := container.ReadHeader(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	tagStart := int(offset) - len(h.HeaderAuthTag)
	blob[tagStart] ^= 0x01
	_, err = NewDecryptReader(context.Background(), bytes.NewReader(blob), WithRecipient(r))
	if err == nil {
		t.Fatalf("expected integrity error")
	}
	if !errors.Is(err, enigma.ErrIntegrity) {
		t.Fatalf("expected ErrIntegrity, got %v", err)
	}
}

func TestCorruptedChunkFails(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "key-a")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var encrypted bytes.Buffer
	w, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r), WithChunkSize(2048))
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	_, _ = w.Write(bytes.Repeat([]byte("a"), 5000))
	_ = w.Close()

	env, err := container.Parse(encrypted.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	env.Chunks[0].Ciphertext[0] ^= 0x01
	mutated, err := container.Serialize(*env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	rd, err := NewDecryptReader(context.Background(), bytes.NewReader(mutated), WithRecipient(r))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	_, err = io.ReadAll(rd)
	if err == nil {
		t.Fatalf("expected decrypt error")
	}
	if !errors.Is(err, enigma.ErrDecryptFailed) {
		t.Fatalf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestRewrapKeepsChunkStream(t *testing.T) {
	rOld, err := localmlkem.Generate(localmlkem.MLKEM768, "old")
	if err != nil {
		t.Fatalf("Generate old: %v", err)
	}
	rNew, err := localmlkem.Generate(localmlkem.MLKEM768, "new")
	if err != nil {
		t.Fatalf("Generate new: %v", err)
	}
	plain := bytes.Repeat([]byte("rewrap-data"), 128)
	tmp := t.TempDir()
	plainPath := filepath.Join(tmp, "plain.txt")
	srcEnc := filepath.Join(tmp, "src.enc")
	dstEnc := filepath.Join(tmp, "dst.enc")
	outPlain := filepath.Join(tmp, "out.txt")
	if err := os.WriteFile(plainPath, plain, 0o600); err != nil {
		t.Fatalf("WriteFile plain: %v", err)
	}
	if err := EncryptFile(context.Background(), plainPath, srcEnc, WithRecipient(rOld), WithChunkSize(4096)); err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	if err := Rewrap(context.Background(), srcEnc, dstEnc, WithRecipient(rOld), WithNewRecipient(rNew), WithReplaceRecipients()); err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	oldBlob, err := os.ReadFile(srcEnc)
	if err != nil {
		t.Fatalf("Read old: %v", err)
	}
	newBlob, err := os.ReadFile(dstEnc)
	if err != nil {
		t.Fatalf("Read new: %v", err)
	}
	_, oldOff, err := container.ReadHeader(bytes.NewReader(oldBlob))
	if err != nil {
		t.Fatalf("Read old header: %v", err)
	}
	_, newOff, err := container.ReadHeader(bytes.NewReader(newBlob))
	if err != nil {
		t.Fatalf("Read new header: %v", err)
	}
	if !bytes.Equal(oldBlob[oldOff:], newBlob[newOff:]) {
		t.Fatalf("chunk stream changed during rewrap")
	}

	if err := DecryptFile(context.Background(), dstEnc, outPlain, WithRecipient(rNew)); err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}
	out, err := os.ReadFile(outPlain)
	if err != nil {
		t.Fatalf("Read output: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("rewrapped decryption mismatch")
	}
}
