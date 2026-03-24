package wire

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/stretchr/testify/assert"
)

type failWriter struct{}

func (f failWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write fail")
}

func TestWriteAndReadPrimitives(t *testing.T) {
	var b bytes.Buffer
	assert.NoError(t, WriteU8(&b, 1))
	assert.NoError(t, WriteU16(&b, 2))
	assert.NoError(t, WriteU32(&b, 3))
	assert.NoError(t, WriteU64(&b, 4))
	assert.NoError(t, WriteI64(&b, 5))
	assert.NoError(t, WriteBytes(&b, []byte("xx")))

	r := bytes.NewReader(b.Bytes())
	v8, err := ReadU8(r)
	assert.NoError(t, err)
	assert.Equal(t, uint8(1), v8)
	v16, err := ReadU16(r)
	assert.NoError(t, err)
	assert.Equal(t, uint16(2), v16)
	v32, err := ReadU32(r)
	assert.NoError(t, err)
	assert.Equal(t, uint32(3), v32)
	v64, err := ReadU64(r)
	assert.NoError(t, err)
	assert.Equal(t, uint64(4), v64)
	vi64, err := ReadI64(r)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), vi64)
	payload, err := ReadBytes(r, 2)
	assert.NoError(t, err)
	assert.Equal(t, []byte("xx"), payload)
}

func TestReadFailures(t *testing.T) {
	_, err := ReadU16(bytes.NewReader([]byte{1}))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, io.ErrUnexpectedEOF))

	_, err = ReadBytes(bytes.NewReader([]byte{1}), 2)
	assert.Error(t, err)
}

func TestReadBytesWithU16LenValidation(t *testing.T) {
	var b bytes.Buffer
	assert.NoError(t, WriteU16(&b, 5))
	assert.NoError(t, WriteBytes(&b, []byte("hello")))
	out, err := ReadBytesWithU16Len(bytes.NewReader(b.Bytes()), "f", 10)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), out)

	_, err = ReadBytesWithU16Len(bytes.NewReader(b.Bytes()), "f", 4)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidContainer))
}

func TestLengthWriters(t *testing.T) {
	var b bytes.Buffer
	assert.NoError(t, WriteBytesWithU16Len(&b, []byte("abc")))
	assert.NoError(t, WriteBytesWithU32Len(&b, []byte("def")))

	err := WriteBytesWithU16Len(failWriter{}, []byte("x"))
	assert.Error(t, err)

	tooLarge := make([]byte, math.MaxUint16+1)
	err = WriteBytesWithU16Len(&bytes.Buffer{}, tooLarge)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}
