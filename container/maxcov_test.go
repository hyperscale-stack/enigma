package container

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/internal/wire"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/stretchr/testify/assert"
)

type alwaysErrWriter struct{}

func (alwaysErrWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failed")
}

func makeValidHeader() Header {
	return Header{
		Immutable: ImmutableHeader{
			Suite:        enigma.SuiteXChaCha20Poly1305,
			ChunkSize:    1024,
			NonceContext: bytes.Repeat([]byte{0xA5}, 16),
			CreatedUnix:  7,
			Profile:      enigma.ProfileLocalPQ,
			Metadata:     map[string]string{"a": "b"},
		},
		Recipients: []RecipientEntry{{
			RecipientType: recipient.TypeLocalMLKEM,
			Capability:    recipient.CapabilityLocalPQ,
			WrapAlgorithm: "mlkem-768+aes256gcm",
			KeyRef:        "k1",
			Ciphertext:    []byte{1, 2, 3},
		}},
		HeaderAuthTag: []byte{9, 9, 9},
	}
}

func TestWriteHeaderDefaultsAndAutoEncode(t *testing.T) {
	h := makeValidHeader()
	var b bytes.Buffer

	n, err := WriteHeader(&b, h)
	assert.NoError(t, err)
	assert.Greater(t, n, int64(0))

	parsed, off, err := ReadHeader(bytes.NewReader(b.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, uint8(enigma.ContainerVersion), parsed.Version)
	assert.Equal(t, off, n)
	assert.Equal(t, uint32(1024), parsed.Immutable.ChunkSize)
	assert.Equal(t, "b", parsed.Immutable.Metadata["a"])
}

func TestWriteHeaderAutoEncodeErrorFromImmutable(t *testing.T) {
	h := Header{
		Immutable: ImmutableHeader{
			Suite:        enigma.SuiteXChaCha20Poly1305,
			ChunkSize:    0,
			NonceContext: bytes.Repeat([]byte{1}, 16),
		},
		Recipients: []RecipientEntry{{RecipientType: recipient.TypeLocalMLKEM, Ciphertext: []byte{1}}},
		HeaderAuthTag: []byte{1},
	}
	_, err := WriteHeader(io.Discard, h)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestReadHeaderTooLargeSection(t *testing.T) {
	var b bytes.Buffer
	_, _ = b.Write([]byte(enigma.ContainerMagic))
	assert.NoError(t, wire.WriteU8(&b, enigma.ContainerVersion))
	assert.NoError(t, wire.WriteU8(&b, 0))
	assert.NoError(t, wire.WriteU32(&b, maxHeaderSectionLen+1))
	assert.NoError(t, wire.WriteU32(&b, 1))
	assert.NoError(t, wire.WriteU16(&b, 1))

	_, _, err := ReadHeader(bytes.NewReader(b.Bytes()))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}

func TestImmutableAndRecipientRoundTripExtraBranches(t *testing.T) {
	_, err := DecodeImmutableHeader([]byte{0x00})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	raw, err := EncodeImmutableHeader(ImmutableHeader{
		Suite:        enigma.SuiteAES256GCM,
		ChunkSize:    2048,
		NonceContext: bytes.Repeat([]byte{3}, 16),
		Profile:      enigma.ProfileCompliance,
		Metadata:     map[string]string{"z": "9", "a": "1"},
	})
	assert.NoError(t, err)
	out, err := DecodeImmutableHeader(raw)
	assert.NoError(t, err)
	assert.Equal(t, "1", out.Metadata["a"])

	entries := []RecipientEntry{{
		RecipientType: recipient.TypeLocalMLKEM,
		Capability:    recipient.CapabilityLocalPQ,
		WrapAlgorithm: "alg",
		KeyRef:        "ref",
		Ciphertext:    []byte{8, 8},
		Metadata:      map[string]string{"k1": "v1", "k2": "v2"},
	}}
	recRaw, err := EncodeRecipients(entries)
	assert.NoError(t, err)
	decoded, err := DecodeRecipients(recRaw)
	assert.NoError(t, err)
	assert.Equal(t, "v1", decoded[0].Metadata["k1"])
}

func TestReadChunkFrameShortReadAndWriteFailures(t *testing.T) {
	_, err := ReadChunkFrame(bytes.NewReader([]byte{chunkTypeData, 1, 2, 3}))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	err = WriteChunkFrame(alwaysErrWriter{}, ChunkFrame{Index: 0, PlaintextLen: 1, Ciphertext: []byte{1}, Final: true})
	assert.Error(t, err)

	err = WriteFooter(alwaysErrWriter{}, []byte{1, 2})
	assert.Error(t, err)
}

func TestSerializeAndParseRemainingErrorBranches(t *testing.T) {
	_, err := Serialize(Envelope{
		Header: Header{ImmutableRaw: []byte{1}, RecipientsRaw: []byte{1}},
		Chunks: []ChunkFrame{{Index: 0, PlaintextLen: 0, Ciphertext: []byte{1}, Final: true}},
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	h := makeValidHeader()
	var b bytes.Buffer
	_, err = WriteHeader(&b, h)
	assert.NoError(t, err)
	err = WriteChunkFrame(&b, ChunkFrame{Index: 0, PlaintextLen: 1, Ciphertext: []byte{9}, Final: false})
	assert.NoError(t, err)
	_, err = Parse(b.Bytes())
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	env := Envelope{
		Header: h,
		Chunks: []ChunkFrame{{Index: 0, PlaintextLen: 0, Ciphertext: []byte{7}, Final: true}},
		Footer: nil,
	}
	blob, err := Serialize(env)
	assert.NoError(t, err)
	blob = append(blob, 0xFF)
	_, err = Parse(blob)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}

func TestDecodeRecipientsDuplicateMetadata(t *testing.T) {
	var b bytes.Buffer
	assert.NoError(t, wire.WriteU16(&b, 1))
	assert.NoError(t, wire.WriteBytesWithU16Len(&b, []byte(recipient.TypeLocalMLKEM)))
	assert.NoError(t, wire.WriteBytesWithU16Len(&b, []byte(recipient.CapabilityLocalPQ)))
	assert.NoError(t, wire.WriteBytesWithU16Len(&b, []byte("alg")))
	assert.NoError(t, wire.WriteBytesWithU16Len(&b, []byte("k")))
	assert.NoError(t, wire.WriteBytesWithU32Len(&b, nil))
	assert.NoError(t, wire.WriteBytesWithU32Len(&b, nil))
	assert.NoError(t, wire.WriteBytesWithU32Len(&b, []byte{1}))
	assert.NoError(t, wire.WriteU16(&b, 2))
	assert.NoError(t, wire.WriteBytesWithU16Len(&b, []byte("dup")))
	assert.NoError(t, wire.WriteBytesWithU16Len(&b, []byte("v1")))
	assert.NoError(t, wire.WriteBytesWithU16Len(&b, []byte("dup")))
	assert.NoError(t, wire.WriteBytesWithU16Len(&b, []byte("v2")))

	_, err := DecodeRecipients(b.Bytes())
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}
