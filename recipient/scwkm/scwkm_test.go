package scwkm

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/stretchr/testify/assert"
)

func TestStubBehaviorAndDescriptor(t *testing.T) {
	r := New("fr-par/kms/key")
	d := r.Descriptor()
	assert.Equal(t, "scaleway-km", string(d.Type))
	assert.Equal(t, "cloud-classical", string(d.Capability))
	assert.Equal(t, "fr-par/kms/key", d.KeyRef)
	assert.True(t, d.RewrapCompatible)

	_, err := r.WrapKey(context.Background(), []byte("dek"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNotImplemented))

	_, err = r.UnwrapKey(context.Background(), nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNotImplemented))
}
