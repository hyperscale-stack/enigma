package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/keymgmt"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/stretchr/testify/assert"
)

type stubResolver struct{}

func (stubResolver) ResolveRecipient(_ context.Context, _ keymgmt.KeyReference) (recipient.Recipient, error) {
	return nil, errors.New("resolve failure")
}

func TestRegistryValidation(t *testing.T) {
	r := NewRegistry()

	err := r.RegisterBackend("", stubResolver{})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	err = r.RegisterBackend("localmlkem", nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestRegistryResolveErrors(t *testing.T) {
	r := NewRegistry()

	_, err := r.ResolveRecipient(context.Background(), keymgmt.KeyReference{})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	_, err = r.ResolveRecipient(context.Background(), keymgmt.KeyReference{Backend: "missing"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrResolveRecipientFailed))

	assert.NoError(t, r.RegisterBackend("broken", stubResolver{}))
	_, err = r.ResolveRecipient(context.Background(), keymgmt.KeyReference{Backend: "broken", ID: "x"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrResolveRecipientFailed))
}
