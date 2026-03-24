package container

import "testing"

func FuzzParse(f *testing.F) {
	f.Add([]byte("ENGM\x01\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
