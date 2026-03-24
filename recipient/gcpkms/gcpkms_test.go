package gcpkms

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/stretchr/testify/assert"
)

func TestDescriptorModeAndStubBehavior(t *testing.T) {
	r1 := New("gcp/key", "")
	d1 := r1.Descriptor()
	assert.Equal(t, "cloud-classical", string(d1.Capability))
	assert.Equal(t, "classical", d1.Metadata["mode"])

	r2 := New("gcp/key", ModePQNative)
	d2 := r2.Descriptor()
	assert.Equal(t, "cloud-pq-native", string(d2.Capability))
	assert.Equal(t, "pq-native", d2.Metadata["mode"])

	_, err := r2.WrapKey(context.Background(), []byte("dek"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNotImplemented))

	_, err = r2.UnwrapKey(context.Background(), nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNotImplemented))
}
