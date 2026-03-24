package field

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/container"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/stretchr/testify/assert"
)

type cloudRecipientStub3 struct{}

func (cloudRecipientStub3) WrapKey(_ context.Context, _ []byte) (*recipient.WrappedKey, error) {
	return &recipient.WrappedKey{RecipientType: recipient.TypeAWSKMS, Ciphertext: []byte{1}}, nil
}

func (cloudRecipientStub3) UnwrapKey(_ context.Context, _ *recipient.WrappedKey) ([]byte, error) {
	return nil, errors.New("unwrap failed")
}

func (cloudRecipientStub3) Descriptor() recipient.Descriptor {
	return recipient.Descriptor{Type: recipient.TypeAWSKMS, Capability: recipient.CapabilityCloudClassical}
}

func TestEncryptValueCapabilityMismatch(t *testing.T) {
	_, err := EncryptValue(context.Background(), []byte("x"), WithRecipient(cloudRecipientStub3{}), WithDefaultProfile(enigma.ProfileLocalPQ))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrCapabilityMismatch))
}

func TestFieldUnwrapWithRecipientsNoMatchingType(t *testing.T) {
	entries := []container.RecipientEntry{{RecipientType: recipient.TypeLocalMLKEM, Ciphertext: []byte{1}}}
	_, err := unwrapWithRecipients(context.Background(), []recipient.Recipient{cloudRecipientStub3{}}, entries)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnwrapFailed))
}

func TestEncodeMapTooManyEntries(t *testing.T) {
	m := make(map[string]string, 1<<16)
	for i := 0; i < 1<<16; i++ {
		m[strconv.Itoa(i)] = ""
	}
	var b bytes.Buffer
	err := encodeMap(&b, m)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}
