package document

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
	"github.com/stretchr/testify/assert"
)

func TestOptionsAndConfigValidation(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "k")
	assert.NoError(t, err)

	cfg, err := buildConfig(
		WithRecipient(r),
		WithNewRecipient(r),
		WithRemoveRecipientKeyRef("k"),
		WithReplaceRecipients(),
		WithDefaultProfile(enigma.ProfileCompliance),
		WithAEADSuite(enigma.SuiteAES256GCM),
		WithChunkSize(4096),
		WithMetadata(map[string]string{"a": "b"}),
	)
	assert.NoError(t, err)
	assert.Len(t, cfg.recipients, 1)
	assert.Len(t, cfg.newRecipients, 1)
	assert.True(t, cfg.replaceRecipients)
	assert.Equal(t, enigma.SuiteAES256GCM, cfg.resolvedSuite())
	assert.Equal(t, "b", cfg.metadata["a"])
}

func TestOptionValidationErrors(t *testing.T) {
	_, err := buildConfig(WithRecipient(nil))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = buildConfig(WithNewRecipient(nil))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = buildConfig(WithRemoveRecipientKeyRef(""))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = buildConfig(WithDefaultProfile("nope"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = buildConfig(WithAEADSuite(enigma.AEADSuite(999)))
	assert.Error(t, err)

	_, err = buildConfig(WithChunkSize(1))
	assert.Error(t, err)
}

func TestValidateEncryptConfig(t *testing.T) {
	err := validateEncryptConfig(defaultConfig())
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNoRecipients))

	r, err := localmlkem.Generate(localmlkem.MLKEM768, "k")
	assert.NoError(t, err)
	cfg, err := buildConfig(WithRecipient(r), WithDefaultProfile(enigma.ProfileLocalPQ))
	assert.NoError(t, err)
	assert.NoError(t, validateEncryptConfig(cfg))

	stub := recipientStub{}
	cfg, err = buildConfig(WithRecipient(stub), WithDefaultProfile(enigma.ProfileLocalPQ))
	assert.NoError(t, err)
	err = validateEncryptConfig(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrCapabilityMismatch))
}

func TestMetadataAndBuildConfigExtraBranches(t *testing.T) {
	cfg, err := buildConfig(nil, WithMetadata(nil))
	assert.NoError(t, err)
	assert.Nil(t, cfg.metadata)

	src := map[string]string{"a": "b"}
	cfg, err = buildConfig(WithMetadata(src))
	assert.NoError(t, err)
	src["a"] = "c"
	assert.Equal(t, "b", cfg.metadata["a"])
}

func TestResolvedSuiteAndValidationExtraBranches(t *testing.T) {
	cfg := defaultConfig()
	cfg.profile = enigma.Profile("unknown")
	assert.Equal(t, enigma.SuiteXChaCha20Poly1305, cfg.resolvedSuite())

	cfg = defaultConfig()
	cfg.recipients = []recipient.Recipient{recipientStub{}}
	bad := enigma.AEADSuite(0x9999)
	cfg.suite = &bad
	err := validateEncryptConfig(cfg)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))
}

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
