package container

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
)

func makeTestEnvelope(t *testing.T) []byte {
	t.Helper()
	h := Header{
		Version: enigma.ContainerVersion,
		Flags:   0,
		Immutable: ImmutableHeader{
			Suite:        enigma.SuiteXChaCha20Poly1305,
			ChunkSize:    32,
			NonceContext: bytes.Repeat([]byte{0x42}, 16),
			CreatedUnix:  123456,
			Profile:      enigma.ProfileLocalPQ,
			Metadata:     map[string]string{"k": "v"},
		},
		Recipients: []RecipientEntry{
			{
				RecipientType:   recipient.TypeLocalMLKEM,
				Capability:      recipient.CapabilityLocalPQ,
				WrapAlgorithm:   "mlkem-768+aes256gcm",
				KeyRef:          "test-key",
				EncapsulatedKey: bytes.Repeat([]byte{1}, 32),
				Nonce:           bytes.Repeat([]byte{2}, 12),
				Ciphertext:      bytes.Repeat([]byte{3}, 64),
			},
		},
		HeaderAuthTag: bytes.Repeat([]byte{9}, 32),
	}
	env := Envelope{
		Header: h,
		Chunks: []ChunkFrame{
			{Index: 0, PlaintextLen: 10, Ciphertext: bytes.Repeat([]byte{7}, 26), Final: true},
		},
	}
	blob, err := Serialize(env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return blob
}

func TestRoundTripEnvelope(t *testing.T) {
	blob := makeTestEnvelope(t)
	env, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if env.Header.Immutable.Suite != enigma.SuiteXChaCha20Poly1305 {
		t.Fatalf("suite mismatch")
	}
	if len(env.Header.Recipients) != 1 {
		t.Fatalf("recipient mismatch")
	}
	if len(env.Chunks) != 1 || !env.Chunks[0].Final {
		t.Fatalf("chunk parsing mismatch")
	}
}

func TestUnknownVersion(t *testing.T) {
	blob := makeTestEnvelope(t)
	blob[4] = 77
	_, err := Parse(blob)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, enigma.ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestCorruptedChunkType(t *testing.T) {
	blob := makeTestEnvelope(t)
	r := bytes.NewReader(blob)
	_, offset, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	blob[offset] = 0x99
	_, err = Parse(blob)
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !errors.Is(err, enigma.ErrInvalidContainer) {
		t.Fatalf("expected invalid container, got %v", err)
	}
}

func TestTruncatedHeader(t *testing.T) {
	blob := makeTestEnvelope(t)
	_, err := Parse(blob[:10])
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !errors.Is(err, enigma.ErrInvalidContainer) {
		t.Fatalf("expected invalid container, got %v", err)
	}
}

func TestUnsupportedAlgorithmIdentifier(t *testing.T) {
	blob := makeTestEnvelope(t)
	r := bytes.NewReader(blob)
	h, _, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if len(h.ImmutableRaw) < 2 {
		t.Fatalf("immutable raw too short")
	}
	h.ImmutableRaw[0], h.ImmutableRaw[1] = 0xff, 0xfe
	var buf bytes.Buffer
	if _, err := WriteHeader(&buf, h); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, _, err := ReadHeader(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatalf("expected header decode error")
	}
}
