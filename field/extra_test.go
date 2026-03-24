package field

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/internal/wire"
	"github.com/hyperscale-stack/enigma/recipient/localmlkem"
	"github.com/stretchr/testify/assert"
)

func TestEncodeDecodeValueImmutableBranches(t *testing.T) {
	_, err := encodeValueImmutable(valueImmutable{Suite: enigma.AEADSuite(999), NonceContext: bytes.Repeat([]byte{1}, 16)})
	assert.Error(t, err)

	_, err = encodeValueImmutable(valueImmutable{Suite: enigma.SuiteXChaCha20Poly1305, NonceContext: []byte("short")})
	assert.Error(t, err)

	raw, err := encodeValueImmutable(valueImmutable{Suite: enigma.SuiteAES256GCM, NonceContext: bytes.Repeat([]byte{1}, 16), Profile: enigma.ProfileCompliance, Metadata: map[string]string{"k": "v"}})
	assert.NoError(t, err)
	v, err := decodeValueImmutable(raw)
	assert.NoError(t, err)
	assert.Equal(t, enigma.SuiteAES256GCM, v.Suite)
	assert.Equal(t, "v", v.Metadata["k"])

	_, err = decodeValueImmutable(append(raw, 0x01))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}

func TestEncodeDecodeMapBranches(t *testing.T) {
	var b bytes.Buffer
	assert.NoError(t, encodeMap(&b, map[string]string{"a": "1", "b": "2"}))
	m, err := decodeMap(bytes.NewReader(b.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, "1", m["a"])
	assert.Equal(t, "2", m["b"])

	var dup bytes.Buffer
	assert.NoError(t, wire.WriteU16(&dup, 2))
	assert.NoError(t, wire.WriteBytesWithU16Len(&dup, []byte("k")))
	assert.NoError(t, wire.WriteBytesWithU16Len(&dup, []byte("1")))
	assert.NoError(t, wire.WriteBytesWithU16Len(&dup, []byte("k")))
	assert.NoError(t, wire.WriteBytesWithU16Len(&dup, []byte("2")))
	_, err = decodeMap(bytes.NewReader(dup.Bytes()))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	assert.Nil(t, cloneMap(nil))
	orig := map[string]string{"x": "y"}
	out := cloneMap(orig)
	out["x"] = "z"
	assert.Equal(t, "y", orig["x"])
}

func TestDecryptValueErrorBranches(t *testing.T) {
	r, err := localmlkem.Generate(localmlkem.MLKEM768, "field-extra")
	assert.NoError(t, err)

	_, err = DecryptValue(context.Background(), []byte{1, 2, 3}, WithRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	blob, err := EncryptValue(context.Background(), []byte("secret"), WithRecipient(r))
	assert.NoError(t, err)

	badMagic := append([]byte(nil), blob...)
	copy(badMagic[:4], []byte("BAD!"))
	_, err = DecryptValue(context.Background(), badMagic, WithRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	withTrailing := append(append([]byte(nil), blob...), 0x01)
	_, err = DecryptValue(context.Background(), withTrailing, WithRecipient(r))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))

	corruptedTag := append([]byte(nil), blob...)
	// tag is after magic(4)+version(1)+flags(1)+imm_len_prefixed+rec_len_prefixed.
	// flip last byte to ensure tag mismatch or parse rejection.
	corruptedTag[len(corruptedTag)-1] ^= 0x01
	_, err = DecryptValue(context.Background(), corruptedTag, WithRecipient(r))
	assert.Error(t, err)
}
