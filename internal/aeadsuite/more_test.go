package aeadsuite

import (
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/stretchr/testify/assert"
)

func TestAdditionalUnsupportedBranches(t *testing.T) {
	_, err := NonceSize(enigma.AEADSuite(9999))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))

	_, err = New(enigma.AEADSuite(9999), make([]byte, 32))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))
}
