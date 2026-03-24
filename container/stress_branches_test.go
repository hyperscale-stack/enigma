package container

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
	"github.com/stretchr/testify/assert"
)

type failAfterWriter struct {
	remaining int
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("forced write failure")
	}
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, errors.New("forced write failure")
	}
	w.remaining -= len(p)
	return len(p), nil
}

func validHeaderRaw(t *testing.T) Header {
	t.Helper()
	immRaw, err := EncodeImmutableHeader(ImmutableHeader{
		Suite:        enigma.SuiteXChaCha20Poly1305,
		ChunkSize:    4096,
		NonceContext: bytes.Repeat([]byte{1}, 16),
		Profile:      enigma.ProfileLocalPQ,
	})
	assert.NoError(t, err)
	recRaw, err := EncodeRecipients([]RecipientEntry{{
		RecipientType: recipient.TypeLocalMLKEM,
		Capability:    recipient.CapabilityLocalPQ,
		WrapAlgorithm: "mlkem-768+aes256gcm",
		KeyRef:        "k",
		Ciphertext:    []byte{1, 2, 3},
	}})
	assert.NoError(t, err)
	return Header{
		Version:       enigma.ContainerVersion,
		Flags:         0,
		ImmutableRaw:  immRaw,
		RecipientsRaw: recRaw,
		HeaderAuthTag: []byte{9, 9, 9, 9},
	}
}

func TestWriteHeaderAndReadHeaderTruncationMatrix(t *testing.T) {
	h := validHeaderRaw(t)
	var full bytes.Buffer
	_, err := WriteHeader(&full, h)
	assert.NoError(t, err)
	blob := full.Bytes()

	for budget := 0; budget < len(blob); budget++ {
		w := &failAfterWriter{remaining: budget}
		_, err := WriteHeader(w, h)
		if err == nil {
			continue
		}
		assert.Error(t, err)
	}

	for i := 0; i < len(blob); i++ {
		_, _, err := ReadHeader(bytes.NewReader(blob[:i]))
		if err == nil {
			continue
		}
		assert.Error(t, err)
	}
}

func TestChunkFrameReadWriteFailureMatrix(t *testing.T) {
	frame := ChunkFrame{Index: 1, PlaintextLen: 3, Ciphertext: []byte{7, 8, 9}, Final: true}
	var full bytes.Buffer
	assert.NoError(t, WriteChunkFrame(&full, frame))
	blob := full.Bytes()

	for budget := 0; budget < len(blob); budget++ {
		w := &failAfterWriter{remaining: budget}
		err := WriteChunkFrame(w, frame)
		if err == nil {
			continue
		}
		assert.Error(t, err)
	}

	for i := 0; i < len(blob); i++ {
		_, err := ReadChunkFrame(bytes.NewReader(blob[:i]))
		if err == nil || errors.Is(err, io.EOF) {
			continue
		}
		assert.Error(t, err)
	}
}

func TestEncodeEdgeCases(t *testing.T) {
	_, err := EncodeImmutableHeader(ImmutableHeader{
		Suite:        enigma.SuiteXChaCha20Poly1305,
		ChunkSize:    1024,
		NonceContext: bytes.Repeat([]byte{1}, 65),
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = DecodeImmutableHeader([]byte{0xFF, 0xFF})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))

	tooManyRecipients := make([]RecipientEntry, int(^uint16(0))+1)
	_, err = EncodeRecipients(tooManyRecipients)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestEncodeStringMapTooManyEntries(t *testing.T) {
	m := make(map[string]string, 1<<16)
	for i := 0; i < 1<<16; i++ {
		m[strconv.Itoa(i)] = ""
	}
	var b bytes.Buffer
	err := encodeStringMap(&b, m)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestSerializeChunkWriteFailureAndParseHeaderFailure(t *testing.T) {
	h := validHeaderRaw(t)
	_, err := Serialize(Envelope{
		Header: h,
		Chunks: []ChunkFrame{{
			Index:        0,
			PlaintextLen: 0,
			Ciphertext:   make([]byte, maxChunkCiphertext+1),
			Final:        true,
		}},
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = Parse([]byte("BAD!"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}
