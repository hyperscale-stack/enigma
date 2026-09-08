package scwkm

import (
	"context"
	"errors"
	"fmt"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/internal/scwkmapi"
	"github.com/hyperscale-stack/enigma/keymgmt"
	keymgmtscwkm "github.com/hyperscale-stack/enigma/keymgmt/scwkm"
	"github.com/hyperscale-stack/enigma/recipient"
	keymanager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

const (
	// WrapAlgorithmEncryptV1 wraps the DEK through the classical Key Manager encrypt/decrypt
	// endpoints (AES-256-GCM or RSA-OAEP keys).
	WrapAlgorithmEncryptV1 = "scwkm+encrypt-v1"
	// WrapAlgorithmMLKEM768WrapV1 wraps the DEK through the native ML-KEM-768 wrap/unwrap endpoints.
	WrapAlgorithmMLKEM768WrapV1 = "scwkm+mlkem-768-wrap-v1"
	// WrapAlgorithmMLKEM1024WrapV1 wraps the DEK through the native ML-KEM-1024 wrap/unwrap endpoints.
	WrapAlgorithmMLKEM1024WrapV1 = "scwkm+mlkem-1024-wrap-v1"
)

type Config = scwkmapi.Config

type Recipient struct {
	api       scwkmapi.Client
	region    scw.Region
	keyID     string
	keyRef    string
	projectID string
	algorithm keymgmt.KeyAlgorithm
}

// New builds a recipient for a classical Key Manager key (AES-256-GCM or RSA-OAEP).
// Use NewWithAlgorithm or NewFromReference for ML-KEM keys.
func New(cfg Config, keyID string) (*Recipient, error) {
	return NewWithAlgorithm(cfg, keyID, "")
}

// NewWithAlgorithm builds a recipient for an explicitly known key algorithm. ML-KEM
// algorithms select the native Key Manager wrap/unwrap path; every other algorithm keeps
// the classical encrypt/decrypt path.
func NewWithAlgorithm(cfg Config, keyID string, alg keymgmt.KeyAlgorithm) (*Recipient, error) {
	if keyID == "" {
		return nil, enigma.WrapError("recipient/scwkm.New", enigma.ErrInvalidArgument, fmt.Errorf("missing key id"))
	}
	client, region, err := scwkmapi.New(cfg)
	if err != nil {
		return nil, enigma.WrapError("recipient/scwkm.New", enigma.ErrInvalidArgument, err)
	}
	keyRef := keymgmtscwkm.BuildReferenceWithAlgorithm(keyID, region, cfg.ProjectID, "", alg).URI
	return &Recipient{api: client, region: region, keyID: keyID, keyRef: keyRef, projectID: cfg.ProjectID, algorithm: alg}, nil
}

func NewFromReference(cfg Config, ref keymgmt.KeyReference) (*Recipient, error) {
	var fallback scw.Region
	if cfg.Region != "" {
		parsed, err := scw.ParseRegion(cfg.Region)
		if err != nil {
			return nil, enigma.WrapError("recipient/scwkm.NewFromReference", enigma.ErrInvalidArgument, err)
		}
		fallback = parsed
	}
	resolved, err := keymgmtscwkm.ResolveReference(ref, fallback)
	if err != nil {
		return nil, err
	}
	if cfg.Region != "" {
		configuredRegion, _ := scw.ParseRegion(cfg.Region)
		if configuredRegion != resolved.Region {
			return nil, enigma.WrapError("recipient/scwkm.NewFromReference", enigma.ErrInvalidKeyReference, fmt.Errorf("reference region %q does not match configured region %q", resolved.Region, configuredRegion))
		}
	}
	cfg.Region = string(resolved.Region)
	if cfg.ProjectID == "" {
		cfg.ProjectID = resolved.ProjectID
	}
	client, region, err := scwkmapi.New(cfg)
	if err != nil {
		return nil, enigma.WrapError("recipient/scwkm.NewFromReference", enigma.ErrInvalidArgument, err)
	}
	return &Recipient{api: client, region: region, keyID: resolved.KeyID, keyRef: resolved.URI, projectID: cfg.ProjectID, algorithm: resolved.Algorithm}, nil
}

// wrapAlgorithm reports the wrap algorithm identifier stored in the container for this key.
func (r *Recipient) wrapAlgorithm() string {
	switch r.algorithm {
	case keymgmt.AlgorithmMLKEM768:
		return WrapAlgorithmMLKEM768WrapV1
	case keymgmt.AlgorithmMLKEM1024:
		return WrapAlgorithmMLKEM1024WrapV1
	case keymgmt.AlgorithmAES256GCM, keymgmt.AlgorithmRSAOAEP3072SHA256:
		return WrapAlgorithmEncryptV1
	default:
		return WrapAlgorithmEncryptV1
	}
}

func (r *Recipient) capability() recipient.CapabilityLevel {
	if r.wrapAlgorithm() == WrapAlgorithmEncryptV1 {
		return recipient.CapabilityCloudClassical
	}
	return recipient.CapabilityCloudPQNative
}

func (r *Recipient) metadata() map[string]string {
	meta := map[string]string{
		"backend":    keymgmtscwkm.BackendName,
		"region":     string(r.region),
		"key_id":     r.keyID,
		"project_id": r.projectID,
	}
	if r.algorithm != "" {
		meta["algorithm"] = string(r.algorithm)
	}
	return meta
}

func (r *Recipient) WrapKey(ctx context.Context, dek []byte) (*recipient.WrappedKey, error) {
	if len(dek) == 0 {
		return nil, enigma.WrapError("recipient/scwkm.WrapKey", enigma.ErrInvalidArgument, fmt.Errorf("empty dek"))
	}
	if r.api == nil {
		return nil, enigma.WrapError("recipient/scwkm.WrapKey", enigma.ErrInvalidArgument, fmt.Errorf("nil api client"))
	}
	if r.keyID == "" {
		return nil, enigma.WrapError("recipient/scwkm.WrapKey", enigma.ErrInvalidArgument, fmt.Errorf("missing key id"))
	}

	wrapAlgorithm := r.wrapAlgorithm()

	ciphertext, err := r.wrapDEK(ctx, wrapAlgorithm, dek)
	if err != nil {
		return nil, err
	}

	return &recipient.WrappedKey{
		RecipientType: recipient.TypeSCWKM,
		Capability:    r.capability(),
		WrapAlgorithm: wrapAlgorithm,
		KeyRef:        r.keyRef,
		Ciphertext:    append([]byte(nil), ciphertext...),
		Metadata:      r.metadata(),
	}, nil
}

// wrapDEK sends the DEK to the endpoint matching the key algorithm: ML-KEM keys go through
// the native wrap endpoint, classical keys keep the encrypt endpoint.
func (r *Recipient) wrapDEK(ctx context.Context, wrapAlgorithm string, dek []byte) ([]byte, error) {
	if wrapAlgorithm != WrapAlgorithmEncryptV1 {
		resp, err := r.api.WrapKey(ctx, &keymanager.WrapKeyRequest{
			Region:    r.region,
			KeyID:     r.keyID,
			Plaintext: append([]byte(nil), dek...),
		})
		if err != nil {
			return nil, mapSDKRecipientError("recipient/scwkm.WrapKey", enigma.ErrWrapFailed, err)
		}
		if resp == nil {
			return nil, enigma.WrapError("recipient/scwkm.WrapKey", enigma.ErrWrapFailed, fmt.Errorf("empty wrap key response"))
		}
		return resp.Ciphertext, nil
	}

	resp, err := r.api.Encrypt(ctx, &keymanager.EncryptRequest{
		Region:    r.region,
		KeyID:     r.keyID,
		Plaintext: append([]byte(nil), dek...),
	})
	if err != nil {
		return nil, mapSDKRecipientError("recipient/scwkm.WrapKey", enigma.ErrWrapFailed, err)
	}
	if resp == nil {
		return nil, enigma.WrapError("recipient/scwkm.WrapKey", enigma.ErrWrapFailed, fmt.Errorf("empty encrypt response"))
	}
	return resp.Ciphertext, nil
}

func (r *Recipient) UnwrapKey(ctx context.Context, wk *recipient.WrappedKey) ([]byte, error) {
	if wk == nil {
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrInvalidArgument, fmt.Errorf("nil wrapped key"))
	}
	if r.api == nil {
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrInvalidArgument, fmt.Errorf("nil api client"))
	}
	if wk.RecipientType != recipient.TypeSCWKM {
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrRecipientNotFound, fmt.Errorf("recipient type %q", wk.RecipientType))
	}
	switch wk.WrapAlgorithm {
	case WrapAlgorithmEncryptV1, WrapAlgorithmMLKEM768WrapV1, WrapAlgorithmMLKEM1024WrapV1:
	default:
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("wrap algorithm %q", wk.WrapAlgorithm))
	}
	if len(wk.Ciphertext) == 0 {
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrInvalidArgument, fmt.Errorf("empty wrapped ciphertext"))
	}
	if r.keyRef != "" && wk.KeyRef != "" && r.keyRef != wk.KeyRef {
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrRecipientNotFound, fmt.Errorf("key ref mismatch"))
	}

	// Dispatch on the stored wrap algorithm so containers wrapped before ML-KEM support keep
	// resolving through the classical decrypt endpoint.
	if wk.WrapAlgorithm != WrapAlgorithmEncryptV1 {
		resp, err := r.api.UnwrapKey(ctx, &keymanager.UnwrapKeyRequest{
			Region:     r.region,
			KeyID:      r.keyID,
			Ciphertext: append([]byte(nil), wk.Ciphertext...),
		})
		if err != nil {
			return nil, mapSDKRecipientError("recipient/scwkm.UnwrapKey", enigma.ErrUnwrapFailed, err)
		}
		if resp == nil {
			return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrUnwrapFailed, fmt.Errorf("empty unwrap key response"))
		}
		return append([]byte(nil), resp.Plaintext...), nil
	}

	resp, err := r.api.Decrypt(ctx, &keymanager.DecryptRequest{
		Region:     r.region,
		KeyID:      r.keyID,
		Ciphertext: append([]byte(nil), wk.Ciphertext...),
	})
	if err != nil {
		return nil, mapSDKRecipientError("recipient/scwkm.UnwrapKey", enigma.ErrUnwrapFailed, err)
	}
	if resp == nil {
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrUnwrapFailed, fmt.Errorf("empty decrypt response"))
	}
	return append([]byte(nil), resp.Plaintext...), nil
}

func (r *Recipient) Descriptor() recipient.Descriptor {
	return recipient.Descriptor{
		Type:             recipient.TypeSCWKM,
		Capability:       r.capability(),
		KeyRef:           r.keyRef,
		RewrapCompatible: true,
		Metadata:         r.metadata(),
	}
}

func mapSDKRecipientError(op string, kind error, err error) error {
	if err == nil {
		return nil
	}
	var notFound *scw.ResourceNotFoundError
	if errors.As(err, &notFound) {
		if errors.Is(kind, enigma.ErrUnwrapFailed) {
			return enigma.WrapError(op, enigma.ErrRecipientNotFound, err)
		}
		return enigma.WrapError(op, enigma.ErrWrapFailed, err)
	}
	var invalid *scw.InvalidArgumentsError
	if errors.As(err, &invalid) {
		return enigma.WrapError(op, enigma.ErrInvalidArgument, err)
	}
	return enigma.WrapError(op, kind, err)
}
