package chunkstream

import (
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/stretchr/testify/assert"
)

func TestNonceForIndexInsufficientMaterial(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	ctx := []byte("ctx")
	_, err := NonceForIndex(salt, ctx, 1, 64)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}
