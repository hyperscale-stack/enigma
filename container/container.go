package container

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/internal/wire"
	"github.com/hyperscale-stack/enigma/recipient"
)

const (
	maxHeaderSectionLen = 16 << 20
	maxChunkCiphertext  = 64 << 20
	chunkTypeData       = uint8(0x01)
	chunkTypeFinal      = uint8(0x02)
)

type ImmutableHeader struct {
	Suite        enigma.AEADSuite
	ChunkSize    uint32
	NonceContext []byte
	CreatedUnix  int64
	Profile      enigma.Profile
	Metadata     map[string]string
}

type RecipientEntry struct {
	RecipientType   recipient.RecipientType
	Capability      recipient.CapabilityLevel
	WrapAlgorithm   string
	KeyRef          string
	EncapsulatedKey []byte
	Nonce           []byte
	Ciphertext      []byte
	Metadata        map[string]string
}

type Header struct {
	Version       uint8
	Flags         uint8
	ImmutableRaw  []byte
	RecipientsRaw []byte
	HeaderAuthTag []byte

	Immutable  ImmutableHeader
	Recipients []RecipientEntry
}

type ChunkFrame struct {
	Index        uint64
	PlaintextLen uint32
	Ciphertext   []byte
	Final        bool
}

type Envelope struct {
	Header Header
	Chunks []ChunkFrame
	Footer []byte
}

func RecipientEntryFromWrappedKey(wk *recipient.WrappedKey) RecipientEntry {
	return RecipientEntry{
		RecipientType:   wk.RecipientType,
		Capability:      wk.Capability,
		WrapAlgorithm:   wk.WrapAlgorithm,
		KeyRef:          wk.KeyRef,
		EncapsulatedKey: append([]byte(nil), wk.EncapsulatedKey...),
		Nonce:           append([]byte(nil), wk.Nonce...),
		Ciphertext:      append([]byte(nil), wk.Ciphertext...),
		Metadata:        recipient.CloneMap(wk.Metadata),
	}
}

func (e RecipientEntry) WrappedKey() *recipient.WrappedKey {
	return &recipient.WrappedKey{
		RecipientType:   e.RecipientType,
		Capability:      e.Capability,
		WrapAlgorithm:   e.WrapAlgorithm,
		KeyRef:          e.KeyRef,
		EncapsulatedKey: append([]byte(nil), e.EncapsulatedKey...),
		Nonce:           append([]byte(nil), e.Nonce...),
		Ciphertext:      append([]byte(nil), e.Ciphertext...),
		Metadata:        recipient.CloneMap(e.Metadata),
	}
}

func EncodeImmutableHeader(h ImmutableHeader) ([]byte, error) {
	if h.ChunkSize == 0 {
		return nil, enigma.WrapError("container.EncodeImmutableHeader", enigma.ErrInvalidArgument, fmt.Errorf("chunk size must be > 0"))
	}
	if len(h.NonceContext) < 8 || len(h.NonceContext) > 64 {
		return nil, enigma.WrapError("container.EncodeImmutableHeader", enigma.ErrInvalidArgument, fmt.Errorf("nonce context length must be in [8,64]"))
	}
	if _, err := enigma.ParseAEADSuite(uint16(h.Suite)); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := wire.WriteU16(&b, uint16(h.Suite)); err != nil {
		return nil, err
	}
	if err := wire.WriteU32(&b, h.ChunkSize); err != nil {
		return nil, err
	}
	if err := wire.WriteBytesWithU16Len(&b, h.NonceContext); err != nil {
		return nil, err
	}
	if err := wire.WriteI64(&b, h.CreatedUnix); err != nil {
		return nil, err
	}
	if err := wire.WriteBytesWithU16Len(&b, []byte(h.Profile)); err != nil {
		return nil, err
	}
	if err := encodeStringMap(&b, h.Metadata); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func DecodeImmutableHeader(raw []byte) (ImmutableHeader, error) {
	r := bytes.NewReader(raw)
	suiteID, err := wire.ReadU16(r)
	if err != nil {
		return ImmutableHeader{}, enigma.WrapError("container.DecodeImmutableHeader", enigma.ErrInvalidContainer, err)
	}
	suite, err := enigma.ParseAEADSuite(suiteID)
	if err != nil {
		return ImmutableHeader{}, err
	}
	chunkSize, err := wire.ReadU32(r)
	if err != nil {
		return ImmutableHeader{}, enigma.WrapError("container.DecodeImmutableHeader", enigma.ErrInvalidContainer, err)
	}
	nonceContext, err := wire.ReadBytesWithU16Len(r, "immutable.nonce_context", 64)
	if err != nil {
		return ImmutableHeader{}, enigma.WrapError("container.DecodeImmutableHeader", enigma.ErrInvalidContainer, err)
	}
	createdUnix, err := wire.ReadI64(r)
	if err != nil {
		return ImmutableHeader{}, enigma.WrapError("container.DecodeImmutableHeader", enigma.ErrInvalidContainer, err)
	}
	profile, err := wire.ReadBytesWithU16Len(r, "immutable.profile", 256)
	if err != nil {
		return ImmutableHeader{}, enigma.WrapError("container.DecodeImmutableHeader", enigma.ErrInvalidContainer, err)
	}
	metadata, err := decodeStringMap(r)
	if err != nil {
		return ImmutableHeader{}, enigma.WrapError("container.DecodeImmutableHeader", enigma.ErrInvalidContainer, err)
	}
	if r.Len() != 0 {
		return ImmutableHeader{}, enigma.WrapError("container.DecodeImmutableHeader", enigma.ErrInvalidContainer, fmt.Errorf("unexpected trailing bytes in immutable header"))
	}
	h := ImmutableHeader{
		Suite:        suite,
		ChunkSize:    chunkSize,
		NonceContext: nonceContext,
		CreatedUnix:  createdUnix,
		Profile:      enigma.Profile(profile),
		Metadata:     metadata,
	}
	if _, err := EncodeImmutableHeader(h); err != nil {
		return ImmutableHeader{}, err
	}
	return h, nil
}

func EncodeRecipients(entries []RecipientEntry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, enigma.WrapError("container.EncodeRecipients", enigma.ErrInvalidArgument, fmt.Errorf("at least one recipient is required"))
	}
	if len(entries) > int(^uint16(0)) {
		return nil, enigma.WrapError("container.EncodeRecipients", enigma.ErrInvalidArgument, fmt.Errorf("too many recipients"))
	}
	var b bytes.Buffer
	if err := wire.WriteU16(&b, uint16(len(entries))); err != nil {
		return nil, err
	}
	for i, e := range entries {
		if e.RecipientType == "" {
			return nil, enigma.WrapError("container.EncodeRecipients", enigma.ErrInvalidArgument, fmt.Errorf("recipient[%d] missing type", i))
		}
		if len(e.Ciphertext) == 0 {
			return nil, enigma.WrapError("container.EncodeRecipients", enigma.ErrInvalidArgument, fmt.Errorf("recipient[%d] missing ciphertext", i))
		}
		if err := wire.WriteBytesWithU16Len(&b, []byte(e.RecipientType)); err != nil {
			return nil, err
		}
		if err := wire.WriteBytesWithU16Len(&b, []byte(e.Capability)); err != nil {
			return nil, err
		}
		if err := wire.WriteBytesWithU16Len(&b, []byte(e.WrapAlgorithm)); err != nil {
			return nil, err
		}
		if err := wire.WriteBytesWithU16Len(&b, []byte(e.KeyRef)); err != nil {
			return nil, err
		}
		if err := wire.WriteBytesWithU32Len(&b, e.EncapsulatedKey); err != nil {
			return nil, err
		}
		if err := wire.WriteBytesWithU32Len(&b, e.Nonce); err != nil {
			return nil, err
		}
		if err := wire.WriteBytesWithU32Len(&b, e.Ciphertext); err != nil {
			return nil, err
		}
		if err := encodeStringMap(&b, e.Metadata); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func DecodeRecipients(raw []byte) ([]RecipientEntry, error) {
	r := bytes.NewReader(raw)
	n, err := wire.ReadU16(r)
	if err != nil {
		return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
	}
	if n == 0 {
		return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, fmt.Errorf("empty recipient list"))
	}
	out := make([]RecipientEntry, 0, n)
	for i := 0; i < int(n); i++ {
		rType, err := wire.ReadBytesWithU16Len(r, "recipient.type", 256)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		capabilityRaw, err := wire.ReadBytesWithU16Len(r, "recipient.capability", 256)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		wrapAlg, err := wire.ReadBytesWithU16Len(r, "recipient.wrap_algorithm", 512)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		keyRef, err := wire.ReadBytesWithU16Len(r, "recipient.key_ref", 1024)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		encapLen, err := wire.ReadU32(r)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		encap, err := wire.ReadBytes(r, encapLen)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		nonceLen, err := wire.ReadU32(r)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		nonce, err := wire.ReadBytes(r, nonceLen)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		ctLen, err := wire.ReadU32(r)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		ct, err := wire.ReadBytes(r, ctLen)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		metadata, err := decodeStringMap(r)
		if err != nil {
			return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, err)
		}
		out = append(out, RecipientEntry{
			RecipientType:   recipient.RecipientType(rType),
			Capability:      recipient.CapabilityLevel(capabilityRaw),
			WrapAlgorithm:   string(wrapAlg),
			KeyRef:          string(keyRef),
			EncapsulatedKey: encap,
			Nonce:           nonce,
			Ciphertext:      ct,
			Metadata:        metadata,
		})
	}
	if r.Len() != 0 {
		return nil, enigma.WrapError("container.DecodeRecipients", enigma.ErrInvalidContainer, fmt.Errorf("unexpected trailing bytes in recipient section"))
	}
	return out, nil
}

func WriteHeader(w io.Writer, h Header) (int64, error) {
	if h.Version == 0 {
		h.Version = enigma.ContainerVersion
	}
	if h.Version != enigma.ContainerVersion {
		return 0, enigma.WrapError("container.WriteHeader", enigma.ErrUnsupportedVersion, fmt.Errorf("version %d", h.Version))
	}
	if len(h.ImmutableRaw) == 0 {
		raw, err := EncodeImmutableHeader(h.Immutable)
		if err != nil {
			return 0, err
		}
		h.ImmutableRaw = raw
	}
	if len(h.RecipientsRaw) == 0 {
		raw, err := EncodeRecipients(h.Recipients)
		if err != nil {
			return 0, err
		}
		h.RecipientsRaw = raw
	}
	if len(h.HeaderAuthTag) == 0 {
		return 0, enigma.WrapError("container.WriteHeader", enigma.ErrInvalidArgument, fmt.Errorf("missing header auth tag"))
	}
	if len(h.ImmutableRaw) > maxHeaderSectionLen || len(h.RecipientsRaw) > maxHeaderSectionLen || len(h.HeaderAuthTag) > int(^uint16(0)) {
		return 0, enigma.WrapError("container.WriteHeader", enigma.ErrInvalidArgument, fmt.Errorf("header sections exceed limits"))
	}

	var written int64
	if _, err := w.Write([]byte(enigma.ContainerMagic)); err != nil {
		return written, enigma.WrapError("container.WriteHeader", enigma.ErrInvalidContainer, err)
	}
	written += int64(len(enigma.ContainerMagic))
	if err := wire.WriteU8(w, h.Version); err != nil {
		return written, err
	}
	written++
	if err := wire.WriteU8(w, h.Flags); err != nil {
		return written, err
	}
	written++
	if err := wire.WriteU32(w, uint32(len(h.ImmutableRaw))); err != nil {
		return written, err
	}
	written += 4
	if err := wire.WriteU32(w, uint32(len(h.RecipientsRaw))); err != nil {
		return written, err
	}
	written += 4
	if err := wire.WriteU16(w, uint16(len(h.HeaderAuthTag))); err != nil {
		return written, err
	}
	written += 2
	if err := wire.WriteBytes(w, h.ImmutableRaw); err != nil {
		return written, err
	}
	written += int64(len(h.ImmutableRaw))
	if err := wire.WriteBytes(w, h.RecipientsRaw); err != nil {
		return written, err
	}
	written += int64(len(h.RecipientsRaw))
	if err := wire.WriteBytes(w, h.HeaderAuthTag); err != nil {
		return written, err
	}
	written += int64(len(h.HeaderAuthTag))
	return written, nil
}

func ReadHeader(r io.Reader) (Header, int64, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, err)
	}
	if string(magic[:]) != enigma.ContainerMagic {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, fmt.Errorf("invalid magic"))
	}
	version, err := wire.ReadU8(r)
	if err != nil {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, err)
	}
	if version != enigma.ContainerVersion {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrUnsupportedVersion, fmt.Errorf("version %d", version))
	}
	flags, err := wire.ReadU8(r)
	if err != nil {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, err)
	}
	immLen, err := wire.ReadU32(r)
	if err != nil {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, err)
	}
	recLen, err := wire.ReadU32(r)
	if err != nil {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, err)
	}
	tagLen, err := wire.ReadU16(r)
	if err != nil {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, err)
	}
	if immLen == 0 || recLen == 0 || tagLen == 0 {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, fmt.Errorf("empty header section"))
	}
	if immLen > maxHeaderSectionLen || recLen > maxHeaderSectionLen {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, fmt.Errorf("header section too large"))
	}

	immutableRaw, err := wire.ReadBytes(r, immLen)
	if err != nil {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, err)
	}
	recipientsRaw, err := wire.ReadBytes(r, recLen)
	if err != nil {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, err)
	}
	tag, err := wire.ReadBytes(r, uint32(tagLen))
	if err != nil {
		return Header{}, 0, enigma.WrapError("container.ReadHeader", enigma.ErrInvalidContainer, err)
	}

	immutable, err := DecodeImmutableHeader(immutableRaw)
	if err != nil {
		return Header{}, 0, err
	}
	recipients, err := DecodeRecipients(recipientsRaw)
	if err != nil {
		return Header{}, 0, err
	}
	h := Header{
		Version:       version,
		Flags:         flags,
		ImmutableRaw:  immutableRaw,
		RecipientsRaw: recipientsRaw,
		HeaderAuthTag: tag,
		Immutable:     immutable,
		Recipients:    recipients,
	}
	offset := int64(4 + 1 + 1 + 4 + 4 + 2)
	offset += int64(len(immutableRaw) + len(recipientsRaw) + len(tag))
	return h, offset, nil
}

func WriteChunkFrame(w io.Writer, frame ChunkFrame) error {
	if len(frame.Ciphertext) > maxChunkCiphertext {
		return enigma.WrapError("container.WriteChunkFrame", enigma.ErrInvalidArgument, fmt.Errorf("chunk too large"))
	}
	t := chunkTypeData
	if frame.Final {
		t = chunkTypeFinal
	}
	if err := wire.WriteU8(w, t); err != nil {
		return err
	}
	if err := wire.WriteU64(w, frame.Index); err != nil {
		return err
	}
	if err := wire.WriteU32(w, frame.PlaintextLen); err != nil {
		return err
	}
	if err := wire.WriteU32(w, uint32(len(frame.Ciphertext))); err != nil {
		return err
	}
	if err := wire.WriteBytes(w, frame.Ciphertext); err != nil {
		return err
	}
	return nil
}

func ReadChunkFrame(r io.Reader) (ChunkFrame, error) {
	t, err := wire.ReadU8(r)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ChunkFrame{}, io.EOF
		}
		return ChunkFrame{}, enigma.WrapError("container.ReadChunkFrame", enigma.ErrInvalidContainer, err)
	}
	if t != chunkTypeData && t != chunkTypeFinal {
		return ChunkFrame{}, enigma.WrapError("container.ReadChunkFrame", enigma.ErrInvalidContainer, fmt.Errorf("unknown chunk type %d", t))
	}
	idx, err := wire.ReadU64(r)
	if err != nil {
		return ChunkFrame{}, enigma.WrapError("container.ReadChunkFrame", enigma.ErrInvalidContainer, err)
	}
	ptLen, err := wire.ReadU32(r)
	if err != nil {
		return ChunkFrame{}, enigma.WrapError("container.ReadChunkFrame", enigma.ErrInvalidContainer, err)
	}
	ctLen, err := wire.ReadU32(r)
	if err != nil {
		return ChunkFrame{}, enigma.WrapError("container.ReadChunkFrame", enigma.ErrInvalidContainer, err)
	}
	if ctLen > maxChunkCiphertext {
		return ChunkFrame{}, enigma.WrapError("container.ReadChunkFrame", enigma.ErrInvalidContainer, fmt.Errorf("chunk exceeds max size"))
	}
	ct, err := wire.ReadBytes(r, ctLen)
	if err != nil {
		return ChunkFrame{}, enigma.WrapError("container.ReadChunkFrame", enigma.ErrInvalidContainer, err)
	}
	return ChunkFrame{Index: idx, PlaintextLen: ptLen, Ciphertext: ct, Final: t == chunkTypeFinal}, nil
}

func WriteFooter(w io.Writer, footer []byte) error {
	if err := wire.WriteU32(w, uint32(len(footer))); err != nil {
		return err
	}
	return wire.WriteBytes(w, footer)
}

func ReadFooter(r io.Reader) ([]byte, error) {
	lenFooter, err := wire.ReadU32(r)
	if err != nil {
		return nil, enigma.WrapError("container.ReadFooter", enigma.ErrInvalidContainer, err)
	}
	footer, err := wire.ReadBytes(r, lenFooter)
	if err != nil {
		return nil, enigma.WrapError("container.ReadFooter", enigma.ErrInvalidContainer, err)
	}
	return footer, nil
}

func Serialize(env Envelope) ([]byte, error) {
	var b bytes.Buffer
	if _, err := WriteHeader(&b, env.Header); err != nil {
		return nil, err
	}
	if len(env.Chunks) == 0 {
		return nil, enigma.WrapError("container.Serialize", enigma.ErrInvalidArgument, fmt.Errorf("missing chunk stream"))
	}
	for _, chunk := range env.Chunks {
		if err := WriteChunkFrame(&b, chunk); err != nil {
			return nil, err
		}
	}
	if err := WriteFooter(&b, env.Footer); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func Parse(data []byte) (*Envelope, error) {
	r := bytes.NewReader(data)
	h, _, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}
	var chunks []ChunkFrame
	for {
		chunk, err := ReadChunkFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, enigma.WrapError("container.Parse", enigma.ErrInvalidContainer, fmt.Errorf("missing final chunk"))
			}
			return nil, err
		}
		chunks = append(chunks, chunk)
		if chunk.Final {
			break
		}
	}
	footer, err := ReadFooter(r)
	if err != nil {
		return nil, err
	}
	if r.Len() != 0 {
		return nil, enigma.WrapError("container.Parse", enigma.ErrInvalidContainer, fmt.Errorf("unexpected trailing bytes"))
	}
	return &Envelope{Header: h, Chunks: chunks, Footer: footer}, nil
}

func encodeStringMap(w io.Writer, m map[string]string) error {
	if len(m) > int(^uint16(0)) {
		return enigma.WrapError("container.encodeStringMap", enigma.ErrInvalidArgument, fmt.Errorf("too many metadata entries"))
	}
	if err := wire.WriteU16(w, uint16(len(m))); err != nil {
		return err
	}
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := wire.WriteBytesWithU16Len(w, []byte(k)); err != nil {
			return err
		}
		if err := wire.WriteBytesWithU16Len(w, []byte(m[k])); err != nil {
			return err
		}
	}
	return nil
}

func decodeStringMap(r io.Reader) (map[string]string, error) {
	n, err := wire.ReadU16(r)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	out := make(map[string]string, n)
	for i := 0; i < int(n); i++ {
		k, err := wire.ReadBytesWithU16Len(r, "metadata.key", 1024)
		if err != nil {
			return nil, err
		}
		v, err := wire.ReadBytesWithU16Len(r, "metadata.value", 4096)
		if err != nil {
			return nil, err
		}
		ks := string(k)
		if _, exists := out[ks]; exists {
			return nil, enigma.WrapError("container.decodeStringMap", enigma.ErrInvalidContainer, fmt.Errorf("duplicate metadata key %q", ks))
		}
		out[ks] = string(v)
	}
	return out, nil
}
