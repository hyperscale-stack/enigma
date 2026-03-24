package localmlkem

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/stretchr/testify/assert"
)

func TestSeedPublicAndConstructors(t *testing.T) {
	r, err := Generate(MLKEM768, "ref-1")
	assert.NoError(t, err)
	seed := r.Seed()
	pub := r.PublicKey()
	assert.Len(t, seed, 64)
	assert.NotEmpty(t, pub)

	fromSeed, err := NewFromSeed(MLKEM768, seed, "ref-1")
	assert.NoError(t, err)
	assert.NotEmpty(t, fromSeed.PublicKey())

	fromPub, err := NewFromPublicKey(MLKEM768, pub, "ref-1")
	assert.NoError(t, err)
	assert.NotEmpty(t, fromPub.PublicKey())

	d := r.Descriptor()
	assert.Equal(t, recipient.TypeLocalMLKEM, d.Type)
	assert.Equal(t, recipient.CapabilityLocalPQ, d.Capability)
	assert.Equal(t, "ml-kem-768", d.Metadata["parameter_set"])
}

func TestConstructorsInvalidInputs(t *testing.T) {
	_, err := Generate(ParameterSet("bad"), "x")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))

	_, err = NewFromSeed(MLKEM768, []byte("short"), "x")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = NewFromPublicKey(MLKEM768, []byte("bad-pub"), "x")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestWrapUnwrap1024(t *testing.T) {
	r, err := Generate(MLKEM1024, "key-1024")
	assert.NoError(t, err)
	dek := []byte("01234567890123456789012345678901")
	wk, err := r.WrapKey(context.Background(), dek)
	assert.NoError(t, err)
	assert.Equal(t, WrapAlgorithmMLKEM1024AESGCM, wk.WrapAlgorithm)

	out, err := r.UnwrapKey(context.Background(), wk)
	assert.NoError(t, err)
	assert.Equal(t, dek, out)
}

func TestUnwrapValidationBranches(t *testing.T) {
	r, err := Generate(MLKEM768, "a")
	assert.NoError(t, err)

	_, err = r.UnwrapKey(context.Background(), nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = r.UnwrapKey(context.Background(), &recipient.WrappedKey{RecipientType: recipient.TypeAWSKMS})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrRecipientNotFound))

	wk := &recipient.WrappedKey{RecipientType: recipient.TypeLocalMLKEM, WrapAlgorithm: "unknown", KeyRef: "a"}
	_, err = r.UnwrapKey(context.Background(), wk)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))
}

func TestSetForWrapAlgorithm(t *testing.T) {
	assert.Equal(t, MLKEM1024, setForWrapAlgorithm(WrapAlgorithmMLKEM1024AESGCM))
	assert.Equal(t, MLKEM768, setForWrapAlgorithm("other"))
}

func TestNilReceiverAndMissingKeyBranches(t *testing.T) {
	var nilRecipient *Recipient
	assert.Nil(t, nilRecipient.Seed())
	assert.Nil(t, nilRecipient.PublicKey())

	r := &Recipient{set: MLKEM768, keyRef: "x"}
	_, err := r.WrapKey(context.Background(), []byte("01234567890123456789012345678901"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrWrapFailed))

	rPubOnly, err := NewFromPublicKey(MLKEM768, r.Seed(), "x")
	assert.Error(t, err)
	assert.Nil(t, rPubOnly)

	rNoDK, err := NewFromPublicKey(MLKEM768, nilRecipient.PublicKey(), "x")
	assert.Error(t, err)
	assert.Nil(t, rNoDK)
}

func TestWrapKeyEmptyDEK(t *testing.T) {
	r, err := Generate(MLKEM768, "k")
	assert.NoError(t, err)
	_, err = r.WrapKey(context.Background(), nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestUnwrapMissingDecapsulationKey(t *testing.T) {
	r, err := Generate(MLKEM768, "k")
	assert.NoError(t, err)

	wk, err := r.WrapKey(context.Background(), []byte("01234567890123456789012345678901"))
	assert.NoError(t, err)

	pubOnly, err := NewFromPublicKey(MLKEM768, r.PublicKey(), "k")
	assert.NoError(t, err)
	_, err = pubOnly.UnwrapKey(context.Background(), wk)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnwrapFailed))
}
