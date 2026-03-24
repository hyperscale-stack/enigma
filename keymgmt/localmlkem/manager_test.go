package localmlkem

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/keymgmt"
	"github.com/stretchr/testify/assert"
)

func TestCreateGetDeleteLifecycle(t *testing.T) {
	m, err := NewManager(t.TempDir())
	assert.NoError(t, err)

	desc, err := m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Name:            "tenant-a",
		Purpose:         keymgmt.PurposeKeyEncapsulation,
		Algorithm:       keymgmt.AlgorithmMLKEM768,
		ProtectionLevel: keymgmt.ProtectionSoftware,
		Metadata:        map[string]string{"tenant": "a"},
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, desc.ID)
	assert.Equal(t, BackendName, desc.Reference.Backend)
	assert.NotContains(t, desc.Reference.URI, "seed")
	assert.Equal(t, keymgmt.KeyClassAsymmetricKEM, desc.Class)
	assert.Equal(t, keymgmt.SecurityLevelLocalPQ, desc.SecurityLevel)

	out, err := m.GetKey(context.Background(), desc.Reference)
	assert.NoError(t, err)
	assert.Equal(t, desc.ID, out.ID)
	assert.Equal(t, "a", out.Metadata["tenant"])

	assert.NoError(t, m.DeleteKey(context.Background(), desc.Reference))

	_, err = m.GetKey(context.Background(), desc.Reference)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrKeyNotFound))
}

func TestCreateKeyUnsupportedRequests(t *testing.T) {
	m, err := NewManager(t.TempDir())
	assert.NoError(t, err)

	_, err = m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{Algorithm: keymgmt.AlgorithmMLKEM768})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Purpose:         keymgmt.PurposeKeyEncapsulation,
		Algorithm:       keymgmt.AlgorithmRSAOAEP3072SHA256,
		ProtectionLevel: keymgmt.ProtectionSoftware,
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrKeyAlgorithmMismatch))

	_, err = m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Purpose:         keymgmt.PurposeKeyEncapsulation,
		Algorithm:       keymgmt.AlgorithmMLKEM768,
		ProtectionLevel: keymgmt.ProtectionHSM,
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedCapability))
}

func TestInvalidReferenceAndDeleteNotFound(t *testing.T) {
	m, err := NewManager(t.TempDir())
	assert.NoError(t, err)

	_, err = m.GetKey(context.Background(), keymgmt.KeyReference{})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	err = m.DeleteKey(context.Background(), keymgmt.KeyReference{Backend: BackendName, ID: "missing"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrKeyNotFound))
}

func TestRotateSuccessorWorkflow(t *testing.T) {
	m, err := NewManager(t.TempDir())
	assert.NoError(t, err)

	created, err := m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Name:            "primary",
		Purpose:         keymgmt.PurposeRecipientDecrypt,
		Algorithm:       keymgmt.AlgorithmMLKEM1024,
		ProtectionLevel: keymgmt.ProtectionSoftware,
	})
	assert.NoError(t, err)

	succ, err := m.RotateKey(context.Background(), created.Reference, keymgmt.RotateKeyRequest{
		SuccessorName: "primary-v2",
		Metadata:      map[string]string{"rotation": "planned"},
	})
	assert.NoError(t, err)
	assert.NotEqual(t, created.ID, succ.ID)
	assert.Equal(t, created.Algorithm, succ.Algorithm)
	assert.Equal(t, "planned", succ.Metadata["rotation"])

	oldDesc, err := m.GetKey(context.Background(), created.Reference)
	assert.NoError(t, err)
	assert.NotEmpty(t, oldDesc.Metadata["successor_uri"])
}

func TestCapabilities(t *testing.T) {
	m, err := NewManager(t.TempDir())
	assert.NoError(t, err)

	caps := m.Capabilities(context.Background())
	assert.True(t, caps.CanCreateKeys)
	assert.True(t, caps.CanDeleteKeys)
	assert.False(t, caps.CanRotateProviderNative)
	assert.True(t, caps.CanExportPublicKey)
	assert.True(t, caps.CanResolveRecipient)
	assert.True(t, caps.SupportsPQNatively)
	assert.False(t, caps.SupportsClassicalWrapping)
	assert.True(t, caps.SupportsRewrapWorkflow)
}
