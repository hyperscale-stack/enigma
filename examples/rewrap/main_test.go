package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMainRuns(t *testing.T) {
	main()
}

func TestMainPanicsWhenTempDirUnavailable(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	assert.Panics(t, main)
}
