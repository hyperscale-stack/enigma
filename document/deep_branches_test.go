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
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
	"github.com/stretchr/testify/assert"
)

type cloudRecipientStub2 struct{}

func (cloudRecipientStub2) WrapKey(_ context.Context, _ []byte) (*recipient.WrappedKey, error) {
	return &recipient.WrappedKey{RecipientType: recipient.TypeAWSKMS, Ciphertext: []byte{1}}, nil
}

func (cloudRecipientStub2) UnwrapKey(_ context.Context, _ *recipient.WrappedKey) ([]byte, error) {
	return nil, errors.New("no unwrap")
}

func (cloudRecipientStub2) Descriptor() recipient.Descriptor {
	return recipient.Descriptor{Type: recipient.TypeAWSKMS, Capability: recipient.CapabilityCloudClassical}
}

type badNonceAEAD struct{}

func (badNonceAEAD) NonceSize() int {
	return 0
}

func (badNonceAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return append(dst, plaintext...)
}

func (badNonceAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

func TestNewEncryptWriterValidationBranches(t *testing.T) {
	_, err := NewEncryptWriter(context.Background(), io.Discard, WithRecipient(cloudRecipientStub2{}), WithDefaultProfile(enigma.ProfileLocalPQ))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrCapabilityMismatch))

	_, err = NewEncryptWriter(context.Background(), io.Discard, WithRecipient(cloudRecipientStub2{}), WithChunkSize(1023))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestEncryptWriterCloseAndFlushChunkErrorPath(t *testing.T) {
	w := &EncryptWriter{
		w:            io.Discard,
		aead:         badNonceAEAD{},
		nonceSalt:    []byte{1},
		nonceContext: []byte{2},
		immutableRaw: []byte{3},
		chunkSize:    4,
		buf:          []byte("x"),
	}
	err := w.Close()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestUnwrapWithRecipientsNoMatchingType(t *testing.T) {
	rec := cloudRecipientStub2{}
	entries := []container.RecipientEntry{{RecipientType: recipient.TypeLocalMLKEM, Ciphertext: []byte{1}}}
	_, err := unwrapWithRecipients(context.Background(), []recipient.Recipient{rec}, entries)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnwrapFailed))
}

func TestRewrapNoUnwrapRecipientsBranch(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "rewrap-branch")
	assert.NoError(t, err)

	tmp := t.TempDir()
	src := filepath.Join(tmp, "plain.txt")
	enc := filepath.Join(tmp, "plain.enc")
	assert.NoError(t, os.WriteFile(src, []byte("payload"), 0o600))
	assert.NoError(t, EncryptFile(context.Background(), src, enc, WithRecipient(r)))

	err = Rewrap(context.Background(), enc, filepath.Join(tmp, "out.enc"), WithRemoveRecipientKeyRef("rewrap-branch"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNoRecipients))
}

func TestDecryptFileCopyErrorRemovesOutput(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "copy-fail")
	assert.NoError(t, err)

	tmp := t.TempDir()
	plain := filepath.Join(tmp, "plain.txt")
	enc := filepath.Join(tmp, "ok.enc")
	bad := filepath.Join(tmp, "bad.enc")
	out := filepath.Join(tmp, "out.txt")
	assert.NoError(t, os.WriteFile(plain, bytes.Repeat([]byte("x"), 128), 0o600))
	assert.NoError(t, EncryptFile(context.Background(), plain, enc, WithRecipient(r)))

	blob, err := os.ReadFile(enc)
	assert.NoError(t, err)
	env, err := container.Parse(blob)
	assert.NoError(t, err)
	env.Chunks[0].Ciphertext[0] ^= 0x01
	mut, err := container.Serialize(*env)
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(bad, mut, 0o600))

	err = DecryptFile(context.Background(), bad, out, WithRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrDecryptFailed))
	_, statErr := os.Stat(out)
	assert.Error(t, statErr)
	assert.True(t, os.IsNotExist(statErr))
}
