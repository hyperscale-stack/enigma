package wire

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/hyperscale-stack/enigma"
)

func WriteU8(w io.Writer, v uint8) error {
	_, err := w.Write([]byte{v})
	return err
}

func WriteU16(w io.Writer, v uint16) error {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func WriteU32(w io.Writer, v uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func WriteU64(w io.Writer, v uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func WriteI64(w io.Writer, v int64) error {
	return WriteU64(w, uint64(v))
}

func WriteBytes(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

func ReadU8(r io.Reader) (uint8, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func ReadU16(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func ReadU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func ReadU64(r io.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func ReadI64(r io.Reader) (int64, error) {
	v, err := ReadU64(r)
	return int64(v), err
}

func ReadBytes(r io.Reader, n uint32) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func ReadBytesWithU16Len(r io.Reader, field string, maxLen uint16) ([]byte, error) {
	n, err := ReadU16(r)
	if err != nil {
		return nil, err
	}
	if maxLen > 0 && n > maxLen {
		return nil, enigma.WrapError("wire.ReadBytesWithU16Len", enigma.ErrInvalidContainer, fmt.Errorf("%s length %d exceeds max %d", field, n, maxLen))
	}
	return ReadBytes(r, uint32(n))
}

func WriteBytesWithU16Len(w io.Writer, b []byte) error {
	if len(b) > int(^uint16(0)) {
		return enigma.WrapError("wire.WriteBytesWithU16Len", enigma.ErrInvalidArgument, fmt.Errorf("length too large: %d", len(b)))
	}
	if err := WriteU16(w, uint16(len(b))); err != nil {
		return err
	}
	return WriteBytes(w, b)
}

func WriteBytesWithU32Len(w io.Writer, b []byte) error {
	if len(b) > int(^uint32(0)) {
		return enigma.WrapError("wire.WriteBytesWithU32Len", enigma.ErrInvalidArgument, fmt.Errorf("length too large: %d", len(b)))
	}
	if err := WriteU32(w, uint32(len(b))); err != nil {
		return err
	}
	return WriteBytes(w, b)
}
