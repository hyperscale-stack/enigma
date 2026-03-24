package scwkm

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/keymgmt"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/stretchr/testify/assert"
)

type stubRecipient struct{}

func (stubRecipient) WrapKey(context.Context, []byte) (*recipient.WrappedKey, error) {
	return nil, nil
}

func (stubRecipient) UnwrapKey(context.Context, *recipient.WrappedKey) ([]byte, error) {
	return nil, nil
}

func (stubRecipient) Descriptor() recipient.Descriptor {
	return recipient.Descriptor{Type: recipient.TypeSCWKM, Capability: recipient.CapabilityCloudClassical}
}

func TestNewValidation(t *testing.T) {
	_, err := New(Config{})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = New(Config{Region: "invalid"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = New(Config{Region: "fr-par", AccessKey: "SCWXXXXXXXXXXXXXXXXX"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestResolveRecipientBehavior(t *testing.T) {
	r, err := New(Config{Region: "fr-par"})
	assert.NoError(t, err)

	r.factory = func(_ Config, _ keymgmt.KeyReference) (recipient.Recipient, error) {
		return stubRecipient{}, nil
	}

	got, err := r.ResolveRecipient(context.Background(), keymgmt.KeyReference{Backend: "scaleway_kms", ID: "k1"})
	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, recipient.TypeSCWKM, got.Descriptor().Type)
}

func TestResolveRecipientErrorMapping(t *testing.T) {
	r, err := New(Config{Region: "fr-par"})
	assert.NoError(t, err)

	r.factory = func(_ Config, _ keymgmt.KeyReference) (recipient.Recipient, error) {
		return nil, enigma.WrapError("factory", enigma.ErrInvalidKeyReference, fmt.Errorf("bad reference"))
	}
	_, err = r.ResolveRecipient(context.Background(), keymgmt.KeyReference{})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	r.factory = func(_ Config, _ keymgmt.KeyReference) (recipient.Recipient, error) {
		return nil, fmt.Errorf("unexpected failure")
	}
	_, err = r.ResolveRecipient(context.Background(), keymgmt.KeyReference{Backend: "scaleway_kms", ID: "k1"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrResolveRecipientFailed))
}
