package kdf

import (
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/stretchr/testify/assert"
)

func TestDeriveDeterministicAndSeparated(t *testing.T) {
	dek := []byte("01234567890123456789012345678901")
	ctx := []byte("nonce-context")

	m1, err := Derive(dek, ctx, enigma.SuiteXChaCha20Poly1305)
	assert.NoError(t, err)
	m2, err := Derive(dek, ctx, enigma.SuiteXChaCha20Poly1305)
	assert.NoError(t, err)

	assert.Equal(t, m1.ContentKey, m2.ContentKey)
	assert.Equal(t, 32, len(m1.ContentKey))
	assert.Equal(t, 32, len(m1.HeaderAuthKey))
	assert.Equal(t, 32, len(m1.NonceSalt))
	assert.Equal(t, 32, len(m1.Reserved))
	assert.NotEqual(t, m1.ContentKey, m1.HeaderAuthKey)
}
