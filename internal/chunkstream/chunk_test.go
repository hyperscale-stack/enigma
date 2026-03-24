package chunkstream

import (
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/stretchr/testify/assert"
)

func TestNonceForIndex(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	ctx := []byte("context")

	n1, err := NonceForIndex(salt, ctx, 1, 12)
	assert.NoError(t, err)
	n2, err := NonceForIndex(salt, ctx, 1, 12)
	assert.NoError(t, err)
	n3, err := NonceForIndex(salt, ctx, 2, 12)
	assert.NoError(t, err)

	assert.Equal(t, n1, n2)
	assert.NotEqual(t, n1, n3)

	_, err = NonceForIndex(salt, ctx, 1, 0)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestChunkAAD(t *testing.T) {
	aad := ChunkAAD([]byte("imm"), 7, 42, true)
	assert.Greater(t, len(aad), 0)
	assert.Contains(t, string(aad), "enigma/chunk/aad/v1")
}
