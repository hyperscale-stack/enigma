package aeadsuite

import (
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/stretchr/testify/assert"
)

func TestKeySizeAndNonceSize(t *testing.T) {
	ks, err := KeySize(enigma.SuiteXChaCha20Poly1305)
	assert.NoError(t, err)
	assert.Equal(t, 32, ks)

	ns, err := NonceSize(enigma.SuiteXChaCha20Poly1305)
	assert.NoError(t, err)
	assert.Equal(t, 24, ns)

	ns, err = NonceSize(enigma.SuiteAES256GCM)
	assert.NoError(t, err)
	assert.Equal(t, 12, ns)

	_, err = KeySize(enigma.AEADSuite(0xffff))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))
}

func TestNewAEAD(t *testing.T) {
	key := make([]byte, 32)
	a, err := New(enigma.SuiteXChaCha20Poly1305, key)
	assert.NoError(t, err)
	assert.NotNil(t, a)

	a, err = New(enigma.SuiteAES256GCM, key)
	assert.NoError(t, err)
	assert.NotNil(t, a)

	_, err = New(enigma.SuiteAES256GCM, []byte("short"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = New(enigma.SuiteXChaCha20Poly1305, []byte("short"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}
