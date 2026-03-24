package chunkstream

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/hyperscale-stack/enigma"
)

func NonceForIndex(nonceSalt, nonceContext []byte, index uint64, nonceSize int) ([]byte, error) {
	if nonceSize <= 0 {
		return nil, enigma.WrapError("chunkstream.NonceForIndex", enigma.ErrInvalidArgument, fmt.Errorf("invalid nonce size %d", nonceSize))
	}
	mac := hmac.New(sha256.New, nonceSalt)
	mac.Write([]byte("enigma/chunk/nonce/v1"))
	mac.Write(nonceContext)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], index)
	mac.Write(b[:])
	sum := mac.Sum(nil)
	if len(sum) < nonceSize {
		return nil, enigma.WrapError("chunkstream.NonceForIndex", enigma.ErrInvalidArgument, fmt.Errorf("insufficient nonce material"))
	}
	return append([]byte(nil), sum[:nonceSize]...), nil
}

func ChunkAAD(immutableRaw []byte, index uint64, plaintextLen uint32, final bool) []byte {
	out := make([]byte, 0, len(immutableRaw)+32)
	out = append(out, []byte("enigma/chunk/aad/v1")...)
	var b [13]byte
	binary.BigEndian.PutUint64(b[0:8], index)
	binary.BigEndian.PutUint32(b[8:12], plaintextLen)
	if final {
		b[12] = 1
	}
	out = append(out, b[:]...)
	out = append(out, immutableRaw...)
	return out
}
