package field

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/internal/wire"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
	"github.com/stretchr/testify/assert"
)

type failingWrapRecipient struct{}

func (failingWrapRecipient) WrapKey(_ context.Context, _ []byte) (*recipient.WrappedKey, error) {
	return nil, errors.New("wrap failed")
}

func (failingWrapRecipient) UnwrapKey(_ context.Context, _ *recipient.WrappedKey) ([]byte, error) {
	return nil, errors.New("unwrap failed")
}

func (failingWrapRecipient) Descriptor() recipient.Descriptor {
	return recipient.Descriptor{Type: recipient.TypeLocalMLKEM, Capability: recipient.CapabilityLocalPQ}
}

func TestEncryptDecryptAdditionalErrorBranches(t *testing.T) {
	_, err := EncryptValue(context.Background(), []byte("x"), WithRecipient(failingWrapRecipient{}))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrWrapFailed))

	_, err = DecryptValue(context.Background(), []byte("123456"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrNoRecipients))
}

func TestDecryptValueHeaderAuthMismatch(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "field-int")
	assert.NoError(t, err)
	blob, err := EncryptValue(context.Background(), []byte("secret"), WithRecipient(r))
	assert.NoError(t, err)

	reader := bytes.NewReader(blob)
	magic := make([]byte, 4)
	_, err = reader.Read(magic)
	assert.NoError(t, err)
	_, err = wire.ReadU8(reader)
	assert.NoError(t, err)
	_, err = wire.ReadU8(reader)
	assert.NoError(t, err)
	_, err = wire.ReadBytesWithU16Len(reader, "immutable", ^uint16(0))
	assert.NoError(t, err)
	recLen, err := wire.ReadU32(reader)
	assert.NoError(t, err)
	_, err = wire.ReadBytes(reader, recLen)
	assert.NoError(t, err)
	tagLen, err := wire.ReadU16(reader)
	assert.NoError(t, err)
	tagOffset := len(blob) - reader.Len()
	assert.Greater(t, int(tagLen), 0)

	mut := append([]byte(nil), blob...)
	mut[tagOffset] ^= 0x01
	_, err = DecryptValue(context.Background(), mut, WithRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrIntegrity))
}

func TestDecryptValueUnsupportedSuiteInImmutable(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "field-suite")
	assert.NoError(t, err)
	blob, err := EncryptValue(context.Background(), []byte("secret"), WithRecipient(r))
	assert.NoError(t, err)

	mut := append([]byte(nil), blob...)
	immLen := binary.BigEndian.Uint16(mut[6:8])
	assert.GreaterOrEqual(t, int(immLen), 2)
	immStart := 8
	mut[immStart] = 0xFF
	mut[immStart+1] = 0xFF

	_, err = DecryptValue(context.Background(), mut, WithRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))
}

func TestDecodeMapZeroEntries(t *testing.T) {
	var b bytes.Buffer
	assert.NoError(t, wire.WriteU16(&b, 0))
	out, err := decodeMap(bytes.NewReader(b.Bytes()))
	assert.NoError(t, err)
	assert.Nil(t, out)
}

func TestDecryptValueTruncatedSections(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "field-trunc")
	assert.NoError(t, err)
	blob, err := EncryptValue(context.Background(), []byte("secret"), WithRecipient(r))
	assert.NoError(t, err)

	immLen := int(binary.BigEndian.Uint16(blob[6:8]))
	recLenOffset := 8 + immLen

	mut := append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(mut[recLenOffset:recLenOffset+4], uint32(len(blob)))
	_, err = DecryptValue(context.Background(), mut, WithRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	short := append([]byte(nil), blob[:len(blob)-2]...)
	_, err = DecryptValue(context.Background(), short, WithRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}
