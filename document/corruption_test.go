package document

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/container"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
	"github.com/stretchr/testify/assert"
)

type failingWrapRecipient struct{}

func (f failingWrapRecipient) WrapKey(_ context.Context, _ []byte) (*recipient.WrappedKey, error) {
	return nil, errors.New("wrap fail")
}

func (f failingWrapRecipient) UnwrapKey(_ context.Context, _ *recipient.WrappedKey) ([]byte, error) {
	return nil, errors.New("unwrap fail")
}

func (f failingWrapRecipient) Descriptor() recipient.Descriptor {
	return recipient.Descriptor{Type: recipient.TypeLocalMLKEM, Capability: recipient.CapabilityLocalPQ}
}

func TestNewEncryptWriterWrapFailure(t *testing.T) {
	_, err := NewEncryptWriter(context.Background(), io.Discard, WithRecipient(failingWrapRecipient{}))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrWrapFailed))
}

func TestDecryptChunkIndexMismatchAndLengthMismatch(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "corrupt")
	assert.NoError(t, err)

	var encrypted bytes.Buffer
	w, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r), WithChunkSize(1024))
	assert.NoError(t, err)
	_, err = w.Write(bytes.Repeat([]byte("z"), 4096))
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	env, err := container.Parse(encrypted.Bytes())
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(env.Chunks), 2)

	idxCorrupt := *env
	idxCorrupt.Chunks = append([]container.ChunkFrame(nil), env.Chunks...)
	idxCorrupt.Chunks[1].Index = 999
	blob, err := container.Serialize(idxCorrupt)
	assert.NoError(t, err)
	rd, err := NewDecryptReader(context.Background(), bytes.NewReader(blob), WithRecipient(r))
	assert.NoError(t, err)
	_, err = io.ReadAll(rd)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	lenCorrupt := *env
	lenCorrupt.Chunks = append([]container.ChunkFrame(nil), env.Chunks...)
	lenCorrupt.Chunks[0].PlaintextLen++
	blob, err = container.Serialize(lenCorrupt)
	assert.NoError(t, err)
	rd, err = NewDecryptReader(context.Background(), bytes.NewReader(blob), WithRecipient(r))
	assert.NoError(t, err)
	_, err = io.ReadAll(rd)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer) || errors.Is(err, enigma.ErrDecryptFailed))
}

func TestRewrapIntegrityAndEmptyRecipientsBranches(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "rw")
	assert.NoError(t, err)

	tmp := t.TempDir()
	src := tmp + "/src.txt"
	enc := tmp + "/src.enc"
	assert.NoError(t, os.WriteFile(src, []byte("rewrap-branch"), 0o600))
	assert.NoError(t, EncryptFile(context.Background(), src, enc, WithRecipient(r)))

	blob, err := os.ReadFile(enc)
	assert.NoError(t, err)
	h, off, err := container.ReadHeader(bytes.NewReader(blob))
	assert.NoError(t, err)
	tagStart := int(off) - len(h.HeaderAuthTag)
	blob[tagStart] ^= 0x01
	corrupt := tmp + "/corrupt.enc"
	assert.NoError(t, os.WriteFile(corrupt, blob, 0o600))

	err = Rewrap(context.Background(), corrupt, tmp+"/out.enc", WithRecipient(r), WithNewRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrIntegrity))

	err = Rewrap(context.Background(), enc, tmp+"/empty.enc", WithRecipient(r), WithRemoveRecipientKeyRef("rw"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNoRecipients))
}
