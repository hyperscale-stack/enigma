package field

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/container"
	"github.com/hyperscale-stack/enigma/internal/aeadsuite"
	"github.com/hyperscale-stack/enigma/internal/chunkstream"
	"github.com/hyperscale-stack/enigma/internal/kdf"
	"github.com/hyperscale-stack/enigma/internal/wire"
	"github.com/hyperscale-stack/enigma/mem"
	"github.com/hyperscale-stack/enigma/recipient"
)

const (
	fieldMagic   = "ENFV"
	fieldVersion = 1
	dekSize      = 32
)

type valueImmutable struct {
	Suite        enigma.AEADSuite
	NonceContext []byte
	Profile      enigma.Profile
	Metadata     map[string]string
}

func EncryptValue(ctx context.Context, plaintext []byte, opts ...Option) ([]byte, error) {
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
		return nil, enigma.WrapError("field.EncryptValue", enigma.ErrInvalidArgument, err)
	}
	defer mem.Zero(dek)

	nonceContext := make([]byte, 16)
	if _, err := rand.Read(nonceContext); err != nil {
		return nil, enigma.WrapError("field.EncryptValue", enigma.ErrInvalidArgument, err)
	}

	material, err := kdf.Derive(dek, nonceContext, suite)
	if err != nil {
		return nil, err
	}
	defer mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt, material.Reserved)

	recEntries := make([]container.RecipientEntry, 0, len(cfg.recipients))
	for _, r := range cfg.recipients {
		wk, err := r.WrapKey(ctx, dek)
		if err != nil {
			return nil, enigma.WrapError("field.EncryptValue", enigma.ErrWrapFailed, err)
		}
		recEntries = append(recEntries, container.RecipientEntryFromWrappedKey(wk))
	}
	recipientsRaw, err := container.EncodeRecipients(recEntries)
	if err != nil {
		return nil, err
	}
	immutable := valueImmutable{Suite: suite, NonceContext: nonceContext, Profile: cfg.profile, Metadata: cloneMap(cfg.metadata)}
	immutableRaw, err := encodeValueImmutable(immutable)
	if err != nil {
		return nil, err
	}

	tag := computeHeaderAuthTag(material.HeaderAuthKey, immutableRaw, recipientsRaw)
	aead, err := aeadsuite.New(suite, material.ContentKey)
	if err != nil {
		return nil, err
	}
	nonce, err := chunkstream.NonceForIndex(material.NonceSalt, nonceContext, 0, aead.NonceSize())
	if err != nil {
		return nil, err
	}
	aad := computeValueAAD(immutableRaw, recipientsRaw)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	mem.Zero(nonce)

	var out bytes.Buffer
	if _, err := out.Write([]byte(fieldMagic)); err != nil {
		return nil, err
	}
	if err := wire.WriteU8(&out, fieldVersion); err != nil {
		return nil, err
	}
	if err := wire.WriteU8(&out, 0); err != nil {
		return nil, err
	}
	if err := wire.WriteBytesWithU16Len(&out, immutableRaw); err != nil {
		return nil, err
	}
	if err := wire.WriteBytesWithU32Len(&out, recipientsRaw); err != nil {
		return nil, err
	}
	if err := wire.WriteBytesWithU16Len(&out, tag); err != nil {
		return nil, err
	}
	if err := wire.WriteBytesWithU32Len(&out, ciphertext); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func DecryptValue(ctx context.Context, blob []byte, opts ...Option) ([]byte, error) {
	cfg, err := buildConfig(opts...)
	if err != nil {
		return nil, err
	}
	if len(cfg.recipients) == 0 {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrNoRecipients, nil)
	}
	if len(blob) < 6 {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, fmt.Errorf("blob too small"))
	}
	r := bytes.NewReader(blob)
	magic := make([]byte, 4)
	if _, err := r.Read(magic); err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, err)
	}
	if string(magic) != fieldMagic {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, fmt.Errorf("invalid magic"))
	}
	version, err := wire.ReadU8(r)
	if err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, err)
	}
	if version != fieldVersion {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrUnsupportedVersion, fmt.Errorf("version %d", version))
	}
	if _, err := wire.ReadU8(r); err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, err)
	}
	immutableRaw, err := wire.ReadBytesWithU16Len(r, "field.immutable", ^uint16(0))
	if err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, err)
	}
	recLen, err := wire.ReadU32(r)
	if err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, err)
	}
	recipientsRaw, err := wire.ReadBytes(r, recLen)
	if err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, err)
	}
	tag, err := wire.ReadBytesWithU16Len(r, "field.header_tag", ^uint16(0))
	if err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, err)
	}
	ctLen, err := wire.ReadU32(r)
	if err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, err)
	}
	ciphertext, err := wire.ReadBytes(r, ctLen)
	if err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, err)
	}
	if r.Len() != 0 {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrInvalidContainer, fmt.Errorf("unexpected trailing bytes"))
	}
	immutable, err := decodeValueImmutable(immutableRaw)
	if err != nil {
		return nil, err
	}
	recEntries, err := container.DecodeRecipients(recipientsRaw)
	if err != nil {
		return nil, err
	}

	dek, err := unwrapWithRecipients(ctx, cfg.recipients, recEntries)
	if err != nil {
		return nil, err
	}
	defer mem.Zero(dek)

	material, err := kdf.Derive(dek, immutable.NonceContext, immutable.Suite)
	if err != nil {
		return nil, err
	}
	defer mem.ZeroMany(material.ContentKey, material.HeaderAuthKey, material.NonceSalt, material.Reserved)

	expectedTag := computeHeaderAuthTag(material.HeaderAuthKey, immutableRaw, recipientsRaw)
	if !hmac.Equal(expectedTag, tag) {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrIntegrity, fmt.Errorf("header auth tag mismatch"))
	}
	aead, err := aeadsuite.New(immutable.Suite, material.ContentKey)
	if err != nil {
		return nil, err
	}
	nonce, err := chunkstream.NonceForIndex(material.NonceSalt, immutable.NonceContext, 0, aead.NonceSize())
	if err != nil {
		return nil, err
	}
	aad := computeValueAAD(immutableRaw, recipientsRaw)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	mem.Zero(nonce)
	if err != nil {
		return nil, enigma.WrapError("field.DecryptValue", enigma.ErrDecryptFailed, err)
	}
	return plaintext, nil
}

func encodeValueImmutable(v valueImmutable) ([]byte, error) {
	if _, err := enigma.ParseAEADSuite(uint16(v.Suite)); err != nil {
		return nil, err
	}
	if len(v.NonceContext) < 8 || len(v.NonceContext) > 64 {
		return nil, enigma.WrapError("field.encodeValueImmutable", enigma.ErrInvalidArgument, fmt.Errorf("invalid nonce context length"))
	}
	var b bytes.Buffer
	if err := wire.WriteU16(&b, uint16(v.Suite)); err != nil {
		return nil, err
	}
	if err := wire.WriteBytesWithU16Len(&b, v.NonceContext); err != nil {
		return nil, err
	}
	if err := wire.WriteBytesWithU16Len(&b, []byte(v.Profile)); err != nil {
		return nil, err
	}
	if err := encodeMap(&b, v.Metadata); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func decodeValueImmutable(raw []byte) (valueImmutable, error) {
	r := bytes.NewReader(raw)
	suiteID, err := wire.ReadU16(r)
	if err != nil {
		return valueImmutable{}, enigma.WrapError("field.decodeValueImmutable", enigma.ErrInvalidContainer, err)
	}
	suite, err := enigma.ParseAEADSuite(suiteID)
	if err != nil {
		return valueImmutable{}, err
	}
	nonceContext, err := wire.ReadBytesWithU16Len(r, "field.nonce_context", 64)
	if err != nil {
		return valueImmutable{}, enigma.WrapError("field.decodeValueImmutable", enigma.ErrInvalidContainer, err)
	}
	profile, err := wire.ReadBytesWithU16Len(r, "field.profile", 256)
	if err != nil {
		return valueImmutable{}, enigma.WrapError("field.decodeValueImmutable", enigma.ErrInvalidContainer, err)
	}
	metadata, err := decodeMap(r)
	if err != nil {
		return valueImmutable{}, enigma.WrapError("field.decodeValueImmutable", enigma.ErrInvalidContainer, err)
	}
	if r.Len() != 0 {
		return valueImmutable{}, enigma.WrapError("field.decodeValueImmutable", enigma.ErrInvalidContainer, fmt.Errorf("unexpected trailing bytes in immutable section"))
	}
	return valueImmutable{Suite: suite, NonceContext: nonceContext, Profile: enigma.Profile(profile), Metadata: metadata}, nil
}

func unwrapWithRecipients(ctx context.Context, recs []recipient.Recipient, entries []container.RecipientEntry) ([]byte, error) {
	var unwrapErr error
	for _, e := range entries {
		wk := e.WrappedKey()
		for _, r := range recs {
			if r.Descriptor().Type != e.RecipientType {
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
	return nil, enigma.WrapError("field.unwrapWithRecipients", enigma.ErrUnwrapFailed, unwrapErr)
}

func computeHeaderAuthTag(headerKey []byte, immutableRaw, recipientsRaw []byte) []byte {
	mac := hmac.New(sha256.New, headerKey)
	mac.Write([]byte("enigma/field/header-auth/v1"))
	mac.Write(immutableRaw)
	mac.Write(recipientsRaw)
	return mac.Sum(nil)
}

func computeValueAAD(immutableRaw, recipientsRaw []byte) []byte {
	out := make([]byte, 0, len(immutableRaw)+len(recipientsRaw)+24)
	out = append(out, []byte("enigma/field/aad/v1")...)
	out = append(out, immutableRaw...)
	out = append(out, recipientsRaw...)
	return out
}

func encodeMap(w *bytes.Buffer, m map[string]string) error {
	if len(m) > int(^uint16(0)) {
		return enigma.WrapError("field.encodeMap", enigma.ErrInvalidArgument, fmt.Errorf("too many metadata entries"))
	}
	if err := wire.WriteU16(w, uint16(len(m))); err != nil {
		return err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := m[k]
		if err := wire.WriteBytesWithU16Len(w, []byte(k)); err != nil {
			return err
		}
		if err := wire.WriteBytesWithU16Len(w, []byte(v)); err != nil {
			return err
		}
	}
	return nil
}

func decodeMap(r *bytes.Reader) (map[string]string, error) {
	n, err := wire.ReadU16(r)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	out := make(map[string]string, n)
	for i := 0; i < int(n); i++ {
		k, err := wire.ReadBytesWithU16Len(r, "field.metadata.key", 1024)
		if err != nil {
			return nil, err
		}
		v, err := wire.ReadBytesWithU16Len(r, "field.metadata.value", 4096)
		if err != nil {
			return nil, err
		}
		ks := string(k)
		if _, ok := out[ks]; ok {
			return nil, enigma.WrapError("field.decodeMap", enigma.ErrInvalidContainer, fmt.Errorf("duplicate metadata key %q", ks))
		}
		out[ks] = string(v)
	}
	return out, nil
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
