package container

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/internal/wire"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/stretchr/testify/assert"
)

func TestEncodeImmutableHeaderValidationErrors(t *testing.T) {
	_, err := EncodeImmutableHeader(ImmutableHeader{Suite: enigma.SuiteXChaCha20Poly1305, ChunkSize: 0, NonceContext: bytes.Repeat([]byte{1}, 16)})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = EncodeImmutableHeader(ImmutableHeader{Suite: enigma.SuiteXChaCha20Poly1305, ChunkSize: 1, NonceContext: []byte("short")})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = EncodeImmutableHeader(ImmutableHeader{Suite: enigma.AEADSuite(0xff), ChunkSize: 1, NonceContext: bytes.Repeat([]byte{1}, 16)})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))
}

func TestDecodeImmutableHeaderTrailingBytes(t *testing.T) {
	raw, err := EncodeImmutableHeader(ImmutableHeader{Suite: enigma.SuiteAES256GCM, ChunkSize: 4096, NonceContext: bytes.Repeat([]byte{1}, 16)})
	assert.NoError(t, err)
	_, err = DecodeImmutableHeader(append(raw, 0x01))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}

func TestEncodeRecipientsValidationErrors(t *testing.T) {
	_, err := EncodeRecipients(nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = EncodeRecipients([]RecipientEntry{{Ciphertext: []byte{1}}})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = EncodeRecipients([]RecipientEntry{{RecipientType: recipient.TypeLocalMLKEM}})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestDecodeRecipientsValidationErrors(t *testing.T) {
	_, err := DecodeRecipients([]byte{0, 0})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	raw, err := EncodeRecipients([]RecipientEntry{{
		RecipientType: recipient.TypeLocalMLKEM,
		Capability:    recipient.CapabilityLocalPQ,
		WrapAlgorithm: "alg",
		KeyRef:        "k",
		Ciphertext:    []byte{1},
	}})
	assert.NoError(t, err)
	_, err = DecodeRecipients(append(raw, 0x00))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}

func TestWriteHeaderValidationErrors(t *testing.T) {
	_, err := WriteHeader(io.Discard, Header{Version: 9})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedVersion))

	_, err = WriteHeader(io.Discard, Header{ImmutableRaw: []byte{1}, RecipientsRaw: []byte{1}})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = WriteHeader(io.Discard, Header{ImmutableRaw: make([]byte, maxHeaderSectionLen+1), RecipientsRaw: []byte{1}, HeaderAuthTag: []byte{1}})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestReadHeaderValidationErrors(t *testing.T) {
	_, _, err := ReadHeader(bytes.NewReader([]byte("BAD!")))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	var b bytes.Buffer
	_, _ = b.WriteString(enigma.ContainerMagic)
	_ = wire.WriteU8(&b, enigma.ContainerVersion)
	_ = wire.WriteU8(&b, 0)
	_ = wire.WriteU32(&b, 0)
	_ = wire.WriteU32(&b, 0)
	_ = wire.WriteU16(&b, 0)
	_, _, err = ReadHeader(bytes.NewReader(b.Bytes()))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}

func TestChunkFrameAndFooterErrors(t *testing.T) {
	err := WriteChunkFrame(io.Discard, ChunkFrame{Ciphertext: make([]byte, maxChunkCiphertext+1)})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = ReadChunkFrame(bytes.NewReader([]byte{0x99}))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	_, err = ReadChunkFrame(bytes.NewReader(nil))
	assert.Equal(t, io.EOF, err)

	var badFooter bytes.Buffer
	_ = binary.Write(&badFooter, binary.BigEndian, uint32(10))
	_, err = ReadFooter(bytes.NewReader(badFooter.Bytes()))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}

func TestSerializeNoChunks(t *testing.T) {
	header := Header{
		ImmutableRaw:  []byte{1},
		RecipientsRaw: []byte{1},
		HeaderAuthTag: []byte{1},
	}
	_, err := Serialize(Envelope{Header: header})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}
