package field

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
	"github.com/stretchr/testify/assert"
)

type recipientStub struct{}

func (recipientStub) WrapKey(_ context.Context, _ []byte) (*recipient.WrappedKey, error) {
	return &recipient.WrappedKey{RecipientType: recipient.TypeAWSKMS, Ciphertext: []byte{1}}, nil
}

func (recipientStub) UnwrapKey(_ context.Context, _ *recipient.WrappedKey) ([]byte, error) {
	return []byte("dek"), nil
}

func (recipientStub) Descriptor() recipient.Descriptor {
	return recipient.Descriptor{Type: recipient.TypeAWSKMS, Capability: recipient.CapabilityCloudClassical}
}

func TestFieldOptions(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "field-opt")
	assert.NoError(t, err)

	cfg, err := buildConfig(
		WithRecipient(r),
		WithDefaultProfile(enigma.ProfileCompliance),
		WithAEADSuite(enigma.SuiteAES256GCM),
		WithMetadata(map[string]string{"k": "v"}),
	)
	assert.NoError(t, err)
	assert.Equal(t, enigma.SuiteAES256GCM, cfg.resolvedSuite())
	assert.Equal(t, "v", cfg.metadata["k"])
}

func TestFieldOptionsErrorsAndValidation(t *testing.T) {
	_, err := buildConfig(WithRecipient(nil))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = buildConfig(WithDefaultProfile("bad"))
	assert.Error(t, err)

	_, err = buildConfig(WithAEADSuite(enigma.AEADSuite(777)))
	assert.Error(t, err)

	err = validateEncryptConfig(defaultConfig())
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNoRecipients))

	cfg, err := buildConfig(WithRecipient(recipientStub{}), WithDefaultProfile(enigma.ProfileLocalPQ))
	assert.NoError(t, err)
	err = validateEncryptConfig(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrCapabilityMismatch))
}

func TestFieldMetadataAndResolvedSuiteBranches(t *testing.T) {
	cfg, err := buildConfig(nil, WithMetadata(nil))
	assert.NoError(t, err)
	assert.Nil(t, cfg.metadata)

	cfg = defaultConfig()
	cfg.profile = enigma.Profile("unknown")
	assert.Equal(t, enigma.SuiteXChaCha20Poly1305, cfg.resolvedSuite())
}
