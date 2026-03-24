package mem

import "runtime"

// Zero best-effort clears a byte slice.
func Zero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}

func ZeroMany(buffers ...[]byte) {
	for _, b := range buffers {
		Zero(b)
	}
}

func Clone(buf []byte) []byte {
	if len(buf) == 0 {
		return nil
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out
}
