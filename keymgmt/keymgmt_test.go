package keymgmt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCloneMap(t *testing.T) {
	assert.Nil(t, CloneMap(nil))

	in := map[string]string{"k": "v"}
	out := CloneMap(in)
	assert.Equal(t, "v", out["k"])
	out["k"] = "x"
	assert.Equal(t, "v", in["k"])
}
