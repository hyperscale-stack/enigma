package mem

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZeroAndZeroMany(t *testing.T) {
	b1 := []byte{1, 2, 3}
	b2 := []byte{4, 5, 6}
	Zero(b1)
	assert.Equal(t, []byte{0, 0, 0}, b1)
	ZeroMany(b1, b2)
	assert.Equal(t, []byte{0, 0, 0}, b1)
	assert.Equal(t, []byte{0, 0, 0}, b2)
}

func TestClone(t *testing.T) {
	assert.Nil(t, Clone(nil))
	assert.Nil(t, Clone([]byte{}))

	in := []byte{9, 8, 7}
	out := Clone(in)
	assert.Equal(t, in, out)
	out[0] = 1
	assert.Equal(t, byte(9), in[0])
}
