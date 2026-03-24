package recipient

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCloneMap(t *testing.T) {
	assert.Nil(t, CloneMap(nil))
	assert.Nil(t, CloneMap(map[string]string{}))

	in := map[string]string{"a": "b"}
	out := CloneMap(in)
	assert.Equal(t, in, out)
	out["a"] = "c"
	assert.Equal(t, "b", in["a"])
}
