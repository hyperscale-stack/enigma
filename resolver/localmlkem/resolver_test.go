package localmlkem

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/document"
	"github.com/hyperscale-stack/enigma/keymgmt"
	keymgmtlocal "github.com/hyperscale-stack/enigma/keymgmt/localmlkem"
	"github.com/stretchr/testify/assert"
)

func TestResolveRecipientAndDocumentRoundTrip(t *testing.T) {
	root := t.TempDir()
	km, err := keymgmtlocal.NewManager(root)
	assert.NoError(t, err)

	desc, err := km.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Name:            "org-main",
		Purpose:         keymgmt.PurposeRecipientDecrypt,
		Algorithm:       keymgmt.AlgorithmMLKEM768,
		ProtectionLevel: keymgmt.ProtectionSoftware,
	})
	assert.NoError(t, err)

	res, err := New(root)
	assert.NoError(t, err)
	rcp, err := res.ResolveRecipient(context.Background(), desc.Reference)
	assert.NoError(t, err)

	var encrypted bytes.Buffer
	ew, err := document.NewEncryptWriter(context.Background(), &encrypted, document.WithRecipient(rcp))
	assert.NoError(t, err)
	_, err = ew.Write([]byte("resolver-integration-payload"))
	assert.NoError(t, err)
	assert.NoError(t, ew.Close())

	rcp2, err := res.ResolveRecipient(context.Background(), desc.Reference)
	assert.NoError(t, err)
	dr, err := document.NewDecryptReader(context.Background(), bytes.NewReader(encrypted.Bytes()), document.WithRecipient(rcp2))
	assert.NoError(t, err)
	pt, err := io.ReadAll(dr)
	assert.NoError(t, err)
	assert.Equal(t, "resolver-integration-payload", string(pt))
}

func TestResolveRecipientErrors(t *testing.T) {
	root := t.TempDir()
	res, err := New(root)
	assert.NoError(t, err)

	_, err = res.ResolveRecipient(context.Background(), keymgmt.KeyReference{})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	_, err = res.ResolveRecipient(context.Background(), keymgmt.KeyReference{Backend: "unknown", ID: "x"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	_, err = res.ResolveRecipient(context.Background(), keymgmt.KeyReference{Backend: keymgmtlocal.BackendName, ID: "missing"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrKeyNotFound))
}
