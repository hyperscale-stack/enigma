package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdditionalReadErrorBranches(t *testing.T) {
	_, err := ReadU8(bytes.NewReader(nil))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF))

	_, err = ReadU32(bytes.NewReader([]byte{1, 2, 3}))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, io.ErrUnexpectedEOF))

	_, err = ReadU64(bytes.NewReader([]byte{1, 2, 3, 4}))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, io.ErrUnexpectedEOF))

	out, err := ReadBytes(bytes.NewReader(nil), 0)
	assert.NoError(t, err)
	assert.Nil(t, out)
}

func TestAdditionalLengthEncodingBranches(t *testing.T) {
	_, err := ReadBytesWithU16Len(bytes.NewReader([]byte{0x00}), "f", 10)
	assert.Error(t, err)

	err = WriteBytesWithU32Len(failWriter{}, []byte{1, 2, 3})
	assert.Error(t, err)
}
