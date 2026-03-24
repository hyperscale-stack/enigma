package localmlkem

import (
	"context"
	"crypto/mlkem"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/stretchr/testify/assert"
)

func TestConstructorsAndRoundTripForMLKEM1024(t *testing.T) {
	r, err := Generate(MLKEM1024, "k1024")
	assert.NoError(t, err)
	assert.NotEmpty(t, r.Seed())
	assert.NotEmpty(t, r.PublicKey())

	fromSeed, err := NewFromSeed(MLKEM1024, r.Seed(), "k1024")
	assert.NoError(t, err)
	assert.NotEmpty(t, fromSeed.PublicKey())

	fromPub, err := NewFromPublicKey(MLKEM1024, r.PublicKey(), "k1024")
	assert.NoError(t, err)
	assert.NotEmpty(t, fromPub.PublicKey())

	dek := []byte("01234567890123456789012345678901")
	wk, err := fromPub.WrapKey(context.Background(), dek)
	assert.NoError(t, err)
	out, err := r.UnwrapKey(context.Background(), wk)
	assert.NoError(t, err)
	assert.Equal(t, dek, out)
}

func TestConstructorUnknownSetBranches(t *testing.T) {
	seed := make([]byte, mlkem.SeedSize)

	_, err := NewFromSeed(ParameterSet("unknown"), seed, "k")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))

	_, err = NewFromPublicKey(ParameterSet("unknown"), []byte("pk"), "k")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))
}

func TestSeedPublicAndWrapUnknownSetBranches(t *testing.T) {
	r := &Recipient{set: ParameterSet("unknown"), keyRef: "x"}
	assert.Nil(t, r.Seed())
	assert.Nil(t, r.PublicKey())

	_, err := r.WrapKey(context.Background(), []byte("01234567890123456789012345678901"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))
}

func TestUnwrapKeyErrorBranches(t *testing.T) {
	r, err := Generate(MLKEM768, "key-a")
	assert.NoError(t, err)

	dek := []byte("01234567890123456789012345678901")
	wk, err := r.WrapKey(context.Background(), dek)
	assert.NoError(t, err)

	sameKeyDifferentRef, err := NewFromSeed(MLKEM768, r.Seed(), "key-b")
	assert.NoError(t, err)
	_, err = sameKeyDifferentRef.UnwrapKey(context.Background(), wk)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrRecipientNotFound))

	badEncap := *wk
	badEncap.EncapsulatedKey = []byte("bad")
	_, err = r.UnwrapKey(context.Background(), &badEncap)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnwrapFailed))

	badCiphertext := *wk
	badCiphertext.Ciphertext = append([]byte(nil), wk.Ciphertext...)
	badCiphertext.Ciphertext[0] ^= 0x01
	_, err = r.UnwrapKey(context.Background(), &badCiphertext)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnwrapFailed))
}

func TestUnwrapMissingDecapsulationKeyForMLKEM1024(t *testing.T) {
	full, err := Generate(MLKEM1024, "k")
	assert.NoError(t, err)

	wk, err := full.WrapKey(context.Background(), []byte("01234567890123456789012345678901"))
	assert.NoError(t, err)

	pubOnly, err := NewFromPublicKey(MLKEM1024, full.PublicKey(), "k")
	assert.NoError(t, err)

	_, err = pubOnly.UnwrapKey(context.Background(), wk)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnwrapFailed))
}

func TestDescriptorForMLKEM1024(t *testing.T) {
	r, err := Generate(MLKEM1024, "desc")
	assert.NoError(t, err)

	d := r.Descriptor()
	assert.Equal(t, recipient.TypeLocalMLKEM, d.Type)
	assert.Equal(t, recipient.CapabilityLocalPQ, d.Capability)
	assert.Equal(t, "ml-kem-1024", d.Metadata["parameter_set"])
}
