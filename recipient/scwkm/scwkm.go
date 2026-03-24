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
	WrapAlgorithmEncryptV1 = "scwkm+encrypt-v1"
)

type Config = scwkmapi.Config

type Recipient struct {
	api       scwkmapi.Client
	region    scw.Region
	keyID     string
	keyRef    string
	projectID string
}

func New(cfg Config, keyID string) (*Recipient, error) {
	if keyID == "" {
		return nil, enigma.WrapError("recipient/scwkm.New", enigma.ErrInvalidArgument, fmt.Errorf("missing key id"))
	}
	client, region, err := scwkmapi.New(cfg)
	if err != nil {
		return nil, enigma.WrapError("recipient/scwkm.New", enigma.ErrInvalidArgument, err)
	}
	keyRef := keymgmtscwkm.BuildReference(keyID, region, cfg.ProjectID, "").URI
	return &Recipient{api: client, region: region, keyID: keyID, keyRef: keyRef, projectID: cfg.ProjectID}, nil
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
	return &Recipient{api: client, region: region, keyID: resolved.KeyID, keyRef: resolved.URI, projectID: cfg.ProjectID}, nil
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

	return &recipient.WrappedKey{
		RecipientType: recipient.TypeSCWKM,
		Capability:    recipient.CapabilityCloudClassical,
		WrapAlgorithm: WrapAlgorithmEncryptV1,
		KeyRef:        r.keyRef,
		Ciphertext:    append([]byte(nil), resp.Ciphertext...),
		Metadata: map[string]string{
			"backend":    keymgmtscwkm.BackendName,
			"region":     string(r.region),
			"key_id":     r.keyID,
			"project_id": r.projectID,
		},
	}, nil
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
	if wk.WrapAlgorithm != WrapAlgorithmEncryptV1 {
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("wrap algorithm %q", wk.WrapAlgorithm))
	}
	if len(wk.Ciphertext) == 0 {
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrInvalidArgument, fmt.Errorf("empty wrapped ciphertext"))
	}
	if r.keyRef != "" && wk.KeyRef != "" && r.keyRef != wk.KeyRef {
		return nil, enigma.WrapError("recipient/scwkm.UnwrapKey", enigma.ErrRecipientNotFound, fmt.Errorf("key ref mismatch"))
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
		Capability:       recipient.CapabilityCloudClassical,
		KeyRef:           r.keyRef,
		RewrapCompatible: true,
		Metadata: map[string]string{
			"backend":    keymgmtscwkm.BackendName,
			"region":     string(r.region),
			"key_id":     r.keyID,
			"project_id": r.projectID,
		},
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
