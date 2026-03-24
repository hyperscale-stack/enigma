package document

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/container"
	"github.com/hyperscale-stack/enigma/internal/aeadsuite"
	"github.com/hyperscale-stack/enigma/internal/chunkstream"
	"github.com/hyperscale-stack/enigma/internal/kdf"
	"github.com/hyperscale-stack/enigma/mem"
	"github.com/hyperscale-stack/enigma/recipient"
)

const dekSize = 32

type Encryptor struct {
	opts []Option
}

func NewEncryptor(opts ...Option) (*Encryptor, error) {
	cfg, err := buildConfig(opts...)
	if err != nil {
		return nil, err
	}
	if err := validateEncryptConfig(cfg); err != nil {
		return nil, err
	}
	return &Encryptor{opts: opts}, nil
}

func (e *Encryptor) EncryptFile(ctx context.Context, srcPath, dstPath string, opts ...Option) error {
	combined := append([]Option(nil), e.opts...)
	combined = append(combined, opts...)
	return EncryptFile(ctx, srcPath, dstPath, combined...)
}

func EncryptFile(ctx context.Context, srcPath, dstPath string, opts ...Option) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return enigma.WrapError("document.EncryptFile", enigma.ErrInvalidArgument, err)
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return enigma.WrapError("document.EncryptFile", enigma.ErrInvalidArgument, err)
	}
	defer func() {
		_ = dst.Close()
	}()

	ew, err := NewEncryptWriter(ctx, dst, opts...)
	if err != nil {
		_ = os.Remove(dstPath)
		return err
	}
	if _, err := io.Copy(ew, src); err != nil {
		_ = ew.Close()
		_ = os.Remove(dstPath)
		return enigma.WrapError("document.EncryptFile", enigma.ErrInvalidArgument, err)
	}
	if err := ew.Close(); err != nil {
		_ = os.Remove(dstPath)
		return err
	}
	return nil
}

func DecryptFile(ctx context.Context, srcPath, dstPath string, opts ...Option) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return enigma.WrapError("document.DecryptFile", enigma.ErrInvalidArgument, err)
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return enigma.WrapError("document.DecryptFile", enigma.ErrInvalidArgument, err)
	}
	defer func() {
		_ = dst.Close()
	}()

	dr, err := NewDecryptReader(ctx, src, opts...)
	if err != nil {
		_ = os.Remove(dstPath)
		return err
	}
	if _, err := io.Copy(dst, dr); err != nil {
		_ = dr.Close()
		_ = os.Remove(dstPath)
		return enigma.WrapError("document.DecryptFile", enigma.ErrDecryptFailed, err)
	}
	if err := dr.Close(); err != nil {
		_ = os.Remove(dstPath)
		return err
	}
	return nil
}

type EncryptWriter struct {
	w io.Writer

	aead         cipherAEAD
	nonceSalt    []byte
	nonceContext []byte
	immutableRaw []byte
	chunkSize    int

	index   uint64
	buf     []byte
	closed  bool
	written bool
	closer  io.Closer
}

type cipherAEAD interface {
	NonceSize() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func NewEncryptWriter(ctx context.Context, w io.Writer, opts ...Option) (*EncryptWriter, error) {
	cfg, err := buildConfig(opts...)
	if err != nil {
		return nil, err
	}
	if err := validateEncryptConfig(cfg); err != nil {
		return nil, err
	}
	suite := cfg.resolvedSuite()

	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, enigma.WrapError("document.NewEncryptWriter", enigma.ErrInvalidArgument, err)
	}
	defer mem.Zero(dek)

	nonceContext := make([]byte, 16)
	if _, err := rand.Read(nonceContext); err != nil {
		return nil, enigma.WrapError("document.NewEncryptWriter", enigma.ErrInvalidArgument, err)
	}

	material, err := kdf.Derive(dek, nonceContext, suite)
	if err != nil {
		return nil, err
	}
	defer mem.ZeroMany(material.Reserved)

	entries, err := wrapForRecipients(ctx, cfg.recipients, dek)
	if err != nil {
		mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt)
		return nil, err
	}
	immutable := container.ImmutableHeader{
		Suite:        suite,
		ChunkSize:    uint32(cfg.chunkSize),
		NonceContext: append([]byte(nil), nonceContext...),
		CreatedUnix:  time.Now().Unix(),
		Profile:      cfg.profile,
		Metadata:     cloneMap(cfg.metadata),
	}
	immutableRaw, err := container.EncodeImmutableHeader(immutable)
	if err != nil {
		mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt)
		return nil, err
	}
	recipientsRaw, err := container.EncodeRecipients(entries)
	if err != nil {
		mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt)
		return nil, err
	}
	tag := computeHeaderAuthTag(material.HeaderAuthKey, enigma.ContainerVersion, 0, immutableRaw, recipientsRaw)

	h := container.Header{
		Version:       enigma.ContainerVersion,
		Flags:         0,
		ImmutableRaw:  immutableRaw,
		RecipientsRaw: recipientsRaw,
		HeaderAuthTag: tag,
		Immutable:     immutable,
		Recipients:    entries,
	}
	if _, err := container.WriteHeader(w, h); err != nil {
		mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt)
		return nil, err
	}
	a, err := aeadsuite.New(suite, material.ContentKey)
	if err != nil {
		mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt)
		return nil, err
	}

	ew := &EncryptWriter{
		w:            w,
		aead:         a,
		nonceSalt:    material.NonceSalt,
		nonceContext: nonceContext,
		immutableRaw: immutableRaw,
		chunkSize:    cfg.chunkSize,
	}
	if c, ok := w.(io.Closer); ok {
		ew.closer = c
	}
	mem.Zero(material.ContentKey)
	mem.Zero(material.HeaderAuthKey)
	return ew, nil
}

func (w *EncryptWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, enigma.WrapError("document.EncryptWriter.Write", enigma.ErrInvalidArgument, fmt.Errorf("writer is closed"))
	}
	w.buf = append(w.buf, p...)
	for len(w.buf) >= w.chunkSize {
		chunk := mem.Clone(w.buf[:w.chunkSize])
		w.buf = w.buf[w.chunkSize:]
		if err := w.flushChunk(chunk, false); err != nil {
			mem.Zero(chunk)
			return 0, err
		}
		mem.Zero(chunk)
	}
	return len(p), nil
}

func (w *EncryptWriter) Close() error {
	if w.closed {
		return nil
	}
	defer func() {
		w.closed = true
		mem.ZeroMany(w.nonceSalt, w.nonceContext, w.buf)
		w.buf = nil
	}()

	finalChunk := mem.Clone(w.buf)
	w.buf = nil
	if len(finalChunk) == 0 {
		finalChunk = make([]byte, 0)
	}
	if err := w.flushChunk(finalChunk, true); err != nil {
		mem.Zero(finalChunk)
		return err
	}
	mem.Zero(finalChunk)
	if err := container.WriteFooter(w.w, nil); err != nil {
		return enigma.WrapError("document.EncryptWriter.Close", enigma.ErrInvalidContainer, err)
	}
	if w.closer != nil {
		if err := w.closer.Close(); err != nil {
			return enigma.WrapError("document.EncryptWriter.Close", enigma.ErrInvalidArgument, err)
		}
	}
	return nil
}

func (w *EncryptWriter) flushChunk(plaintext []byte, final bool) error {
	nonce, err := chunkstream.NonceForIndex(w.nonceSalt, w.nonceContext, w.index, w.aead.NonceSize())
	if err != nil {
		return err
	}
	aad := chunkstream.ChunkAAD(w.immutableRaw, w.index, uint32(len(plaintext)), final)
	ct := w.aead.Seal(nil, nonce, plaintext, aad)
	frame := container.ChunkFrame{
		Index:        w.index,
		PlaintextLen: uint32(len(plaintext)),
		Ciphertext:   ct,
		Final:        final,
	}
	if err := container.WriteChunkFrame(w.w, frame); err != nil {
		return enigma.WrapError("document.EncryptWriter.flushChunk", enigma.ErrInvalidContainer, err)
	}
	w.index++
	w.written = true
	mem.Zero(nonce)
	return nil
}

type DecryptReader struct {
	r io.Reader

	aead         cipherAEAD
	nonceSalt    []byte
	nonceContext []byte
	immutableRaw []byte

	expectedIndex uint64
	buf           []byte
	contentDone   bool
	closed        bool
	closer        io.Closer
}

func NewDecryptReader(ctx context.Context, r io.Reader, opts ...Option) (*DecryptReader, error) {
	cfg, err := buildConfig(opts...)
	if err != nil {
		return nil, err
	}
	if len(cfg.recipients) == 0 {
		return nil, enigma.WrapError("document.NewDecryptReader", enigma.ErrNoRecipients, nil)
	}

	h, _, err := container.ReadHeader(r)
	if err != nil {
		return nil, err
	}
	dek, err := unwrapWithRecipients(ctx, cfg.recipients, h.Recipients)
	if err != nil {
		return nil, err
	}
	defer mem.Zero(dek)

	material, err := kdf.Derive(dek, h.Immutable.NonceContext, h.Immutable.Suite)
	if err != nil {
		return nil, err
	}
	defer mem.Zero(material.Reserved)

	expectedTag := computeHeaderAuthTag(material.HeaderAuthKey, h.Version, h.Flags, h.ImmutableRaw, h.RecipientsRaw)
	if !hmac.Equal(expectedTag, h.HeaderAuthTag) {
		mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt)
		return nil, enigma.WrapError("document.NewDecryptReader", enigma.ErrIntegrity, fmt.Errorf("header auth tag mismatch"))
	}

	a, err := aeadsuite.New(h.Immutable.Suite, material.ContentKey)
	if err != nil {
		mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt)
		return nil, err
	}

	dr := &DecryptReader{
		r:            r,
		aead:         a,
		nonceSalt:    material.NonceSalt,
		nonceContext: append([]byte(nil), h.Immutable.NonceContext...),
		immutableRaw: append([]byte(nil), h.ImmutableRaw...),
	}
	if c, ok := r.(io.Closer); ok {
		dr.closer = c
	}
	mem.Zero(material.ContentKey)
	mem.Zero(material.HeaderAuthKey)
	return dr, nil
}

func (r *DecryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.buf) == 0 {
		if r.contentDone {
			return 0, io.EOF
		}
		if err := r.loadNextChunk(); err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	if n == 0 && r.contentDone {
		return 0, io.EOF
	}
	return n, nil
}

func (r *DecryptReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	mem.ZeroMany(r.nonceSalt, r.nonceContext, r.buf)
	r.buf = nil
	if r.closer != nil {
		if err := r.closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (r *DecryptReader) loadNextChunk() error {
	frame, err := container.ReadChunkFrame(r.r)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return enigma.WrapError("document.DecryptReader.loadNextChunk", enigma.ErrInvalidContainer, fmt.Errorf("missing final chunk"))
		}
		return err
	}
	if frame.Index != r.expectedIndex {
		return enigma.WrapError("document.DecryptReader.loadNextChunk", enigma.ErrInvalidContainer, fmt.Errorf("chunk index mismatch: got %d want %d", frame.Index, r.expectedIndex))
	}
	nonce, err := chunkstream.NonceForIndex(r.nonceSalt, r.nonceContext, frame.Index, r.aead.NonceSize())
	if err != nil {
		return err
	}
	aad := chunkstream.ChunkAAD(r.immutableRaw, frame.Index, frame.PlaintextLen, frame.Final)
	pt, err := r.aead.Open(nil, nonce, frame.Ciphertext, aad)
	mem.Zero(nonce)
	if err != nil {
		return enigma.WrapError("document.DecryptReader.loadNextChunk", enigma.ErrDecryptFailed, err)
	}
	if uint32(len(pt)) != frame.PlaintextLen {
		return enigma.WrapError("document.DecryptReader.loadNextChunk", enigma.ErrInvalidContainer, fmt.Errorf("plaintext length mismatch"))
	}
	r.expectedIndex++
	r.buf = pt
	if frame.Final {
		r.contentDone = true
		if _, err := container.ReadFooter(r.r); err != nil {
			return err
		}
	}
	return nil
}

type InspectInfo struct {
	Version     uint8
	Flags       uint8
	Suite       enigma.AEADSuite
	ChunkSize   uint32
	Profile     enigma.Profile
	CreatedUnix int64
	Metadata    map[string]string
	Recipients  []recipient.Descriptor
}

func Inspect(ctx context.Context, path string) (*InspectInfo, error) {
	_ = ctx
	f, err := os.Open(path)
	if err != nil {
		return nil, enigma.WrapError("document.Inspect", enigma.ErrInvalidArgument, err)
	}
	defer f.Close()
	return InspectReader(context.Background(), f)
}

func InspectReader(ctx context.Context, r io.Reader) (*InspectInfo, error) {
	_ = ctx
	h, _, err := container.ReadHeader(r)
	if err != nil {
		return nil, err
	}
	recipientsOut := make([]recipient.Descriptor, 0, len(h.Recipients))
	for _, rec := range h.Recipients {
		recipientsOut = append(recipientsOut, recipient.Descriptor{
			Type:             rec.RecipientType,
			Capability:       rec.Capability,
			KeyRef:           rec.KeyRef,
			RewrapCompatible: true,
			Metadata:         cloneMap(rec.Metadata),
		})
	}
	return &InspectInfo{
		Version:     h.Version,
		Flags:       h.Flags,
		Suite:       h.Immutable.Suite,
		ChunkSize:   h.Immutable.ChunkSize,
		Profile:     h.Immutable.Profile,
		CreatedUnix: h.Immutable.CreatedUnix,
		Metadata:    cloneMap(h.Immutable.Metadata),
		Recipients:  recipientsOut,
	}, nil
}

func RewrapFile(ctx context.Context, path string, opts ...Option) error {
	tmp := path + ".rewrap.tmp"
	if err := Rewrap(ctx, path, tmp, opts...); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return enigma.WrapError("document.RewrapFile", enigma.ErrInvalidArgument, err)
	}
	return nil
}

func Rewrap(ctx context.Context, srcPath, dstPath string, opts ...Option) error {
	if srcPath == dstPath {
		return enigma.WrapError("document.Rewrap", enigma.ErrInvalidArgument, fmt.Errorf("src and dst must differ; use RewrapFile for in-place rewrite"))
	}
	cfg, err := buildConfig(opts...)
	if err != nil {
		return err
	}
	if len(cfg.newRecipients) == 0 && len(cfg.removeRecipientRef) == 0 && !cfg.replaceRecipients {
		return enigma.WrapError("document.Rewrap", enigma.ErrInvalidArgument, fmt.Errorf("no rewrap operation requested"))
	}
	if len(cfg.recipients) == 0 && len(cfg.newRecipients) == 0 {
		return enigma.WrapError("document.Rewrap", enigma.ErrNoRecipients, fmt.Errorf("at least one unwrap-capable recipient is required"))
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return enigma.WrapError("document.Rewrap", enigma.ErrInvalidArgument, err)
	}
	defer src.Close()

	h, chunkOffset, err := container.ReadHeader(src)
	if err != nil {
		return err
	}
	unwrapCandidates := append([]recipient.Recipient{}, cfg.recipients...)
	unwrapCandidates = append(unwrapCandidates, cfg.newRecipients...)
	dek, err := unwrapWithRecipients(ctx, unwrapCandidates, h.Recipients)
	if err != nil {
		return err
	}
	defer mem.Zero(dek)

	material, err := kdf.Derive(dek, h.Immutable.NonceContext, h.Immutable.Suite)
	if err != nil {
		return err
	}
	defer mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt, material.Reserved)

	expectedTag := computeHeaderAuthTag(material.HeaderAuthKey, h.Version, h.Flags, h.ImmutableRaw, h.RecipientsRaw)
	if !hmac.Equal(expectedTag, h.HeaderAuthTag) {
		return enigma.WrapError("document.Rewrap", enigma.ErrIntegrity, fmt.Errorf("header auth tag mismatch"))
	}

	updated := make([]container.RecipientEntry, 0, len(h.Recipients)+len(cfg.newRecipients))
	if !cfg.replaceRecipients {
		for _, rec := range h.Recipients {
			if _, remove := cfg.removeRecipientRef[rec.KeyRef]; remove {
				continue
			}
			updated = append(updated, rec)
		}
	}
	for _, rcp := range cfg.newRecipients {
		wk, err := rcp.WrapKey(ctx, dek)
		if err != nil {
			return enigma.WrapError("document.Rewrap", enigma.ErrWrapFailed, err)
		}
		updated = append(updated, container.RecipientEntryFromWrappedKey(wk))
	}
	if len(updated) == 0 {
		return enigma.WrapError("document.Rewrap", enigma.ErrNoRecipients, fmt.Errorf("rewrap would leave container without recipients"))
	}

	newRecipientsRaw, err := container.EncodeRecipients(updated)
	if err != nil {
		return err
	}
	newTag := computeHeaderAuthTag(material.HeaderAuthKey, h.Version, h.Flags, h.ImmutableRaw, newRecipientsRaw)
	newHeader := container.Header{
		Version:       h.Version,
		Flags:         h.Flags,
		ImmutableRaw:  h.ImmutableRaw,
		RecipientsRaw: newRecipientsRaw,
		HeaderAuthTag: newTag,
		Immutable:     h.Immutable,
		Recipients:    updated,
	}

	if _, err := src.Seek(chunkOffset, io.SeekStart); err != nil {
		return enigma.WrapError("document.Rewrap", enigma.ErrInvalidArgument, err)
	}
	dst, err := os.Create(dstPath)
	if err != nil {
		return enigma.WrapError("document.Rewrap", enigma.ErrInvalidArgument, err)
	}
	defer func() {
		_ = dst.Close()
	}()

	if _, err := container.WriteHeader(dst, newHeader); err != nil {
		_ = os.Remove(dstPath)
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = os.Remove(dstPath)
		return enigma.WrapError("document.Rewrap", enigma.ErrInvalidArgument, err)
	}
	return nil
}

func wrapForRecipients(ctx context.Context, recs []recipient.Recipient, dek []byte) ([]container.RecipientEntry, error) {
	entries := make([]container.RecipientEntry, 0, len(recs))
	for _, r := range recs {
		wk, err := r.WrapKey(ctx, dek)
		if err != nil {
			return nil, enigma.WrapError("document.wrapForRecipients", enigma.ErrWrapFailed, err)
		}
		entries = append(entries, container.RecipientEntryFromWrappedKey(wk))
	}
	return entries, nil
}

func unwrapWithRecipients(ctx context.Context, recs []recipient.Recipient, entries []container.RecipientEntry) ([]byte, error) {
	var unwrapErr error
	for _, e := range entries {
		wk := e.WrappedKey()
		for _, r := range recs {
			d := r.Descriptor()
			if d.Type != e.RecipientType {
				continue
			}
			dek, err := r.UnwrapKey(ctx, wk)
			if err == nil {
				return dek, nil
			}
			unwrapErr = err
		}
	}
	if unwrapErr == nil {
		unwrapErr = fmt.Errorf("no matching recipients")
	}
	return nil, enigma.WrapError("document.unwrapWithRecipients", enigma.ErrUnwrapFailed, unwrapErr)
}

func computeHeaderAuthTag(headerKey []byte, version, flags uint8, immutableRaw, recipientsRaw []byte) []byte {
	mac := hmac.New(sha256.New, headerKey)
	mac.Write([]byte("enigma/header-auth/v1"))
	mac.Write([]byte{version, flags})
	mac.Write(immutableRaw)
	mac.Write(recipientsRaw)
	return mac.Sum(nil)
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
