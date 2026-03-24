package container

import (
	"testing"

	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/stretchr/testify/assert"
)

func TestWrappedKeyConversions(t *testing.T) {
	wk := &recipient.WrappedKey{
		RecipientType:   recipient.TypeLocalMLKEM,
		Capability:      recipient.CapabilityLocalPQ,
		WrapAlgorithm:   "alg",
		KeyRef:          "key-ref",
		EncapsulatedKey: []byte{1, 2},
		Nonce:           []byte{3, 4},
		Ciphertext:      []byte{5, 6},
		Metadata:        map[string]string{"x": "y"},
	}
	entry := RecipientEntryFromWrappedKey(wk)
	assert.Equal(t, wk.RecipientType, entry.RecipientType)
	assert.Equal(t, "y", entry.Metadata["x"])

	wk2 := entry.WrappedKey()
	assert.Equal(t, wk.KeyRef, wk2.KeyRef)
	assert.Equal(t, wk.Ciphertext, wk2.Ciphertext)
	wk2.Metadata["x"] = "z"
	assert.Equal(t, "y", entry.Metadata["x"])
}
