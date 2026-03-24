package enigma

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpErrorErrorStringAndUnwrap(t *testing.T) {
	base := fmt.Errorf("boom")
	err := &OpError{Op: "x.y", Kind: ErrInvalidArgument, Err: base}
	assert.Equal(t, "x.y: boom", err.Error())
	assert.Equal(t, base, err.Unwrap())

	err = &OpError{Op: "x.y", Kind: ErrInvalidArgument}
	assert.Equal(t, "x.y: enigma: invalid argument", err.Error())

	err = &OpError{Kind: ErrInvalidContainer}
	assert.Equal(t, "enigma: invalid container", err.Error())

	err = &OpError{Err: base}
	assert.Equal(t, "boom", err.Error())

	err = &OpError{Op: "op.only"}
	assert.Equal(t, "op.only: enigma error", err.Error())

	err = &OpError{}
	assert.Equal(t, "enigma: error", err.Error())

	var nilErr *OpError
	assert.Equal(t, "<nil>", nilErr.Error())
	assert.Nil(t, nilErr.Unwrap())
	assert.False(t, nilErr.Is(ErrInvalidArgument))
}

func TestOpErrorIsAndWrapError(t *testing.T) {
	base := fmt.Errorf("boom")
	err := &OpError{Op: "x", Kind: ErrUnwrapFailed, Err: base}
	assert.True(t, err.Is(ErrUnwrapFailed))
	assert.True(t, errors.Is(err, base))

	wrapped := WrapError("x", ErrIntegrity, base)
	assert.NotNil(t, wrapped)
	assert.True(t, errors.Is(wrapped, ErrIntegrity))
	assert.True(t, errors.Is(wrapped, base))

	assert.Nil(t, WrapError("", nil, nil))
}
