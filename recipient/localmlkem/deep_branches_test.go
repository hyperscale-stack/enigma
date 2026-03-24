package localmlkem

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/stretchr/testify/assert"
)

func TestGenerateAndAccessorsMoreBranches(t *testing.T) {
	r1024, err := Generate(MLKEM1024, "g1024")
	assert.NoError(t, err)
	assert.NotEmpty(t, r1024.Seed())
	assert.NotEmpty(t, r1024.PublicKey())

	rNoDK1024 := &Recipient{set: MLKEM1024}
	assert.Nil(t, rNoDK1024.Seed())
	assert.Nil(t, rNoDK1024.PublicKey())
}

func TestWrapMissingEncapsulationKeyFor1024(t *testing.T) {
	r := &Recipient{set: MLKEM1024, keyRef: "x"}
	_, err := r.WrapKey(context.Background(), []byte("01234567890123456789012345678901"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrWrapFailed))
}

func TestNewFromSeedInvalidFor1024AndPublicKeyInvalidFor1024(t *testing.T) {
	_, err := NewFromSeed(MLKEM1024, []byte("short"), "x")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = NewFromPublicKey(MLKEM1024, []byte("invalid"), "x")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}
