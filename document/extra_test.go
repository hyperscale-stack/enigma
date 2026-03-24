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
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
	"github.com/stretchr/testify/assert"
)

func TestNewEncryptorAndMethodEncryptFile(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "enc-method")
	assert.NoError(t, err)

	e, err := NewEncryptor(WithRecipient(r))
	assert.NoError(t, err)
	assert.NotNil(t, e)

	tmp := t.TempDir()
	src := filepath.Join(tmp, "in.txt")
	dst := filepath.Join(tmp, "out.enc")
	assert.NoError(t, os.WriteFile(src, []byte("payload"), 0o600))
	assert.NoError(t, e.EncryptFile(context.Background(), src, dst))
}

func TestNewEncryptorAndDecryptReaderValidationErrors(t *testing.T) {
	_, err := NewEncryptor()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNoRecipients))

	_, err = NewDecryptReader(context.Background(), bytes.NewReader(nil))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNoRecipients))
}

func TestInspectAndInspectReader(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "inspect")
	assert.NoError(t, err)

	tmp := t.TempDir()
	src := filepath.Join(tmp, "in.txt")
	dst := filepath.Join(tmp, "out.enc")
	assert.NoError(t, os.WriteFile(src, []byte("inspect me"), 0o600))
	assert.NoError(t, EncryptFile(context.Background(), src, dst, WithRecipient(r), WithMetadata(map[string]string{"x": "y"})))

	info, err := Inspect(context.Background(), dst)
	assert.NoError(t, err)
	assert.Equal(t, enigma.ContainerVersion, int(info.Version))
	assert.Equal(t, "y", info.Metadata["x"])
	assert.GreaterOrEqual(t, len(info.Recipients), 1)

	f, err := os.Open(dst)
	assert.NoError(t, err)
	defer f.Close()
	info2, err := InspectReader(context.Background(), f)
	assert.NoError(t, err)
	assert.Equal(t, info.Suite, info2.Suite)
}

func TestRewrapFile(t *testing.T) {
	rOld, err := localmlkem.Generate(localmlkem.MLKEM768, "r-old")
	assert.NoError(t, err)
	rNew, err := localmlkem.Generate(localmlkem.MLKEM768, "r-new")
	assert.NoError(t, err)

	tmp := t.TempDir()
	src := filepath.Join(tmp, "in.txt")
	enc := filepath.Join(tmp, "in.enc")
	dec := filepath.Join(tmp, "out.txt")
	assert.NoError(t, os.WriteFile(src, []byte("rewrap-file"), 0o600))
	assert.NoError(t, EncryptFile(context.Background(), src, enc, WithRecipient(rOld)))

	assert.NoError(t, RewrapFile(context.Background(), enc,
		WithRecipient(rOld),
		WithNewRecipient(rNew),
		WithReplaceRecipients(),
	))

	assert.NoError(t, DecryptFile(context.Background(), enc, dec, WithRecipient(rNew)))
	out, err := os.ReadFile(dec)
	assert.NoError(t, err)
	assert.Equal(t, "rewrap-file", string(out))
}

func TestRewrapValidation(t *testing.T) {
	err := Rewrap(context.Background(), "same", "same")
	assert.Error(t, err)

	err = Rewrap(context.Background(), "a", "b")
	assert.Error(t, err)

	_, err = Inspect(context.Background(), "/does/not/exist")
	assert.Error(t, err)
}

type errCloseWriter struct {
	bytes.Buffer
}

func (e *errCloseWriter) Close() error {
	return errors.New("close writer fail")
}

type errCloseReader struct {
	*bytes.Reader
}

func (e *errCloseReader) Close() error {
	return errors.New("close reader fail")
}

func TestFileHelpersErrorBranches(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "err-branches")
	assert.NoError(t, err)

	err = EncryptFile(context.Background(), "/does/not/exist", "/tmp/nope", WithRecipient(r))
	assert.Error(t, err)

	tmp := t.TempDir()
	src := filepath.Join(tmp, "in.txt")
	enc := filepath.Join(tmp, "in.enc")
	dec := filepath.Join(tmp, "out.txt")
	assert.NoError(t, os.WriteFile(src, []byte("x"), 0o600))
	assert.NoError(t, EncryptFile(context.Background(), src, enc, WithRecipient(r)))

	// Destination is a directory: create/open for write must fail.
	err = EncryptFile(context.Background(), src, tmp, WithRecipient(r))
	assert.Error(t, err)

	err = DecryptFile(context.Background(), "/does/not/exist", dec, WithRecipient(r))
	assert.Error(t, err)

	err = DecryptFile(context.Background(), enc, tmp, WithRecipient(r))
	assert.Error(t, err)
}

func TestEncryptDecryptCloserErrorBranches(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "closer")
	assert.NoError(t, err)

	ewTarget := &errCloseWriter{}
	ew, err := NewEncryptWriter(context.Background(), ewTarget, WithRecipient(r))
	assert.NoError(t, err)
	_, err = ew.Write([]byte("payload"))
	assert.NoError(t, err)
	err = ew.Close()
	assert.Error(t, err)
	_, err = ew.Write([]byte("again"))
	assert.Error(t, err)

	var encrypted bytes.Buffer
	w, err := NewEncryptWriter(context.Background(), &encrypted, WithRecipient(r))
	assert.NoError(t, err)
	_, _ = w.Write([]byte("abc"))
	assert.NoError(t, w.Close())

	rdBase := bytes.NewReader(encrypted.Bytes())
	rd, err := NewDecryptReader(context.Background(), &errCloseReader{Reader: rdBase}, WithRecipient(r))
	assert.NoError(t, err)
	_, err = io.ReadAll(rd)
	assert.NoError(t, err)
	err = rd.Close()
	assert.Error(t, err)
}
