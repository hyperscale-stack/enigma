package enigma

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAEADSuiteString(t *testing.T) {
	assert.Equal(t, "xchacha20-poly1305", SuiteXChaCha20Poly1305.String())
	assert.Equal(t, "aes-256-gcm", SuiteAES256GCM.String())
	assert.Equal(t, "unknown-suite(999)", AEADSuite(999).String())
}

func TestParseAEADSuite(t *testing.T) {
	s, err := ParseAEADSuite(uint16(SuiteXChaCha20Poly1305))
	assert.NoError(t, err)
	assert.Equal(t, SuiteXChaCha20Poly1305, s)

	s, err = ParseAEADSuite(uint16(SuiteAES256GCM))
	assert.NoError(t, err)
	assert.Equal(t, SuiteAES256GCM, s)

	_, err = ParseAEADSuite(0x9999)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsupportedAlgorithm))
}
