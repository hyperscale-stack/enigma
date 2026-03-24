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
	"github.com/stretchr/testify/assert"
)

func TestDecryptReaderMissingFinalChunkAndInvalidFooter(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "doc-max")
	assert.NoError(t, err)

	var enc bytes.Buffer
	ew, err := NewEncryptWriter(context.Background(), &enc, WithRecipient(r), WithChunkSize(1024))
	assert.NoError(t, err)
	_, err = ew.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.NoError(t, ew.Close())

	env, err := container.Parse(enc.Bytes())
	assert.NoError(t, err)
	assert.Len(t, env.Chunks, 1)

	var noFinal bytes.Buffer
	_, err = container.WriteHeader(&noFinal, env.Header)
	assert.NoError(t, err)
	frame := env.Chunks[0]
	frame.Final = false
	assert.NoError(t, container.WriteChunkFrame(&noFinal, frame))

	rd, err := NewDecryptReader(context.Background(), bytes.NewReader(noFinal.Bytes()), WithRecipient(r))
	assert.NoError(t, err)
	_, err = io.ReadAll(rd)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer) || errors.Is(err, enigma.ErrDecryptFailed))

	truncatedFooter := enc.Bytes()[:len(enc.Bytes())-1]
	rd, err = NewDecryptReader(context.Background(), bytes.NewReader(truncatedFooter), WithRecipient(r))
	assert.NoError(t, err)
	_, err = io.ReadAll(rd)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}

func TestReaderWriterAdditionalBranches(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "doc-branches")
	assert.NoError(t, err)

	var encrypted bytes.Buffer
	ew, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r))
	assert.NoError(t, err)
	_, err = ew.Write(nil)
	assert.NoError(t, err)
	assert.NoError(t, ew.Close())
	assert.NoError(t, ew.Close())

	rd, err := NewDecryptReader(context.Background(), bytes.NewReader(encrypted.Bytes()), WithRecipient(r))
	assert.NoError(t, err)
	n, err := rd.Read(nil)
	assert.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.NoError(t, rd.Close())
	assert.NoError(t, rd.Close())
}

func TestInspectReaderAndRewrapBranches(t *testing.T) {
	rOld, err := localmlkem.Generate(localmlkem.MLKEM768, "old-ref")
	assert.NoError(t, err)
	rNew, err := localmlkem.Generate(localmlkem.MLKEM768, "new-ref")
	assert.NoError(t, err)

	tmp := t.TempDir()
	src := filepath.Join(tmp, "in.txt")
	srcEnc := filepath.Join(tmp, "in.enc")
	dstEnc := filepath.Join(tmp, "out.enc")
	assert.NoError(t, os.WriteFile(src, []byte("rewrap-value"), 0o600))
	assert.NoError(t, EncryptFile(context.Background(), src, srcEnc, WithRecipient(rOld)))

	_, err = InspectReader(context.Background(), bytes.NewReader([]byte("bad")))
	assert.Error(t, err)

	err = Rewrap(context.Background(), srcEnc, dstEnc, WithNewRecipient(rNew))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnwrapFailed))

	err = Rewrap(context.Background(), srcEnc, dstEnc,
		WithRecipient(rOld),
		WithNewRecipient(rNew),
		WithRemoveRecipientKeyRef("does-not-exist"),
	)
	assert.NoError(t, err)

	err = RewrapFile(context.Background(), filepath.Join(tmp, "missing.enc"), WithRecipient(rOld))
	assert.Error(t, err)
}

func TestEncryptFileAndDecryptFileCopyFailureBranches(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "copy-err")
	assert.NoError(t, err)

	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "srcdir")
	assert.NoError(t, os.Mkdir(srcDir, 0o700))
	encOut := filepath.Join(tmp, "out.enc")
	err = EncryptFile(context.Background(), srcDir, encOut, WithRecipient(r))
	assert.Error(t, err)

	plainPath := filepath.Join(tmp, "plain.txt")
	encPath := filepath.Join(tmp, "good.enc")
	badPath := filepath.Join(tmp, "bad.enc")
	decPath := filepath.Join(tmp, "out.txt")
	assert.NoError(t, os.WriteFile(plainPath, []byte("hello world"), 0o600))
	assert.NoError(t, EncryptFile(context.Background(), plainPath, encPath, WithRecipient(r)))

	blob, err := os.ReadFile(encPath)
	assert.NoError(t, err)
	env, err := container.Parse(blob)
	assert.NoError(t, err)
	assert.NotEmpty(t, env.Chunks)
	env.Chunks[0].Ciphertext[0] ^= 0x01
	mut, err := container.Serialize(*env)
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(badPath, mut, 0o600))

	err = DecryptFile(context.Background(), badPath, decPath, WithRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrDecryptFailed))
}
