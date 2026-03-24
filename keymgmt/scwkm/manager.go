package scwkm

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/internal/scwkmapi"
	"github.com/hyperscale-stack/enigma/keymgmt"
	keymanager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

const (
	BackendName              = scwkmapi.BackendName
	referenceScheme          = "enigma-scwkm"
	referenceHost            = "key"
	defaultReferenceVersion  = "0"
	metadataRegion           = "region"
	metadataProjectID        = "project_id"
	metadataKeyState         = "key_state"
	metadataKeyOrigin        = "key_origin"
	metadataRotationCount    = "rotation_count"
	metadataKeyName          = "key_name"
	metadataRequestedPurpose = "requested_purpose"
)

type Config = scwkmapi.Config

type Manager struct {
	api            scwkmapi.Client
	defaultRegion  scw.Region
	defaultProject string
}

type Reference struct {
	KeyID     string
	Region    scw.Region
	ProjectID string
	Version   string
	URI       string
}

func NewManager(cfg Config) (*Manager, error) {
	client, region, err := scwkmapi.New(cfg)
	if err != nil {
		return nil, enigma.WrapError("keymgmt/scwkm.NewManager", enigma.ErrInvalidArgument, err)
	}
	return &Manager{api: client, defaultRegion: region, defaultProject: cfg.ProjectID}, nil
}

func (m *Manager) CreateKey(ctx context.Context, req keymgmt.CreateKeyRequest) (*keymgmt.KeyDescriptor, error) {
	if req.Algorithm == "" {
		return nil, enigma.WrapError("keymgmt/scwkm.CreateKey", enigma.ErrInvalidArgument, fmt.Errorf("missing key algorithm"))
	}
	if req.Purpose == "" {
		return nil, enigma.WrapError("keymgmt/scwkm.CreateKey", enigma.ErrInvalidArgument, fmt.Errorf("missing key purpose"))
	}
	if req.Purpose == keymgmt.PurposeKeyEncapsulation {
		return nil, enigma.WrapError("keymgmt/scwkm.CreateKey", enigma.ErrUnsupportedCapability, fmt.Errorf("purpose %q requires KEM capabilities not provided by this backend", req.Purpose))
	}
	if req.Purpose != keymgmt.PurposeKeyWrapping && req.Purpose != keymgmt.PurposeRecipientDecrypt {
		return nil, enigma.WrapError("keymgmt/scwkm.CreateKey", enigma.ErrInvalidArgument, fmt.Errorf("unsupported key purpose %q", req.Purpose))
	}
	if req.Exportable {
		return nil, enigma.WrapError("keymgmt/scwkm.CreateKey", enigma.ErrUnsupportedCapability, fmt.Errorf("exportable key material is not supported"))
	}
	if req.ProtectionLevel != "" && req.ProtectionLevel != keymgmt.ProtectionKMS {
		return nil, enigma.WrapError("keymgmt/scwkm.CreateKey", enigma.ErrUnsupportedCapability, fmt.Errorf("protection level %q is not supported by scaleway kms backend", req.ProtectionLevel))
	}

	usage, _, err := usageForAlgorithm(req.Algorithm)
	if err != nil {
		return nil, err
	}

	createReq := &keymanager.CreateKeyRequest{
		Region:    m.defaultRegion,
		ProjectID: m.defaultProject,
		Usage:     usage,
	}
	if req.Name != "" {
		name := req.Name
		createReq.Name = &name
	}

	k, err := m.api.CreateKey(ctx, createReq)
	if err != nil {
		return nil, mapSDKError("keymgmt/scwkm.CreateKey", enigma.ErrCreateKeyFailed, err)
	}
	if k == nil {
		return nil, enigma.WrapError("keymgmt/scwkm.CreateKey", enigma.ErrCreateKeyFailed, fmt.Errorf("empty key response"))
	}
	return descriptorFromKey(k, req.Purpose, keymgmt.CloneMap(req.Metadata))
}

func (m *Manager) GetKey(ctx context.Context, ref keymgmt.KeyReference) (*keymgmt.KeyDescriptor, error) {
	resolved, err := ResolveReference(ref, m.defaultRegion)
	if err != nil {
		return nil, err
	}
	k, err := m.api.GetKey(ctx, &keymanager.GetKeyRequest{Region: resolved.Region, KeyID: resolved.KeyID})
	if err != nil {
		return nil, mapSDKError("keymgmt/scwkm.GetKey", enigma.ErrKeyNotFound, err)
	}
	if k == nil {
		return nil, enigma.WrapError("keymgmt/scwkm.GetKey", enigma.ErrKeyNotFound, fmt.Errorf("empty key response"))
	}
	return descriptorFromKey(k, keymgmt.PurposeKeyWrapping, nil)
}

func (m *Manager) RotateKey(ctx context.Context, ref keymgmt.KeyReference, req keymgmt.RotateKeyRequest) (*keymgmt.KeyDescriptor, error) {
	resolved, err := ResolveReference(ref, m.defaultRegion)
	if err != nil {
		return nil, enigma.WrapError("keymgmt/scwkm.RotateKey", enigma.ErrRotateKeyFailed, err)
	}
	k, err := m.api.RotateKey(ctx, &keymanager.RotateKeyRequest{Region: resolved.Region, KeyID: resolved.KeyID})
	if err != nil {
		return nil, mapSDKError("keymgmt/scwkm.RotateKey", enigma.ErrRotateKeyFailed, err)
	}
	if k == nil {
		return nil, enigma.WrapError("keymgmt/scwkm.RotateKey", enigma.ErrRotateKeyFailed, fmt.Errorf("empty key response"))
	}
	metadata := map[string]string(nil)
	if req.SuccessorName != "" {
		metadata = map[string]string{"requested_successor_name": req.SuccessorName}
	}
	for mk, mv := range req.Metadata {
		if metadata == nil {
			metadata = make(map[string]string, len(req.Metadata))
		}
		metadata[mk] = mv
	}
	return descriptorFromKey(k, keymgmt.PurposeKeyWrapping, metadata)
}

func (m *Manager) DeleteKey(ctx context.Context, ref keymgmt.KeyReference) error {
	resolved, err := ResolveReference(ref, m.defaultRegion)
	if err != nil {
		return err
	}
	if err := m.api.DeleteKey(ctx, &keymanager.DeleteKeyRequest{Region: resolved.Region, KeyID: resolved.KeyID}); err != nil {
		return mapSDKError("keymgmt/scwkm.DeleteKey", enigma.ErrDeleteKeyFailed, err)
	}
	return nil
}

func (m *Manager) Capabilities(ctx context.Context) keymgmt.CapabilitySet {
	_ = ctx
	return capabilitySet()
}

func capabilitySet() keymgmt.CapabilitySet {
	return keymgmt.CapabilitySet{
		CanCreateKeys:             true,
		CanDeleteKeys:             true,
		CanRotateProviderNative:   true,
		CanExportPublicKey:        true,
		CanResolveRecipient:       true,
		SupportsPQNatively:        false,
		SupportsClassicalWrapping: true,
		SupportsRewrapWorkflow:    true,
	}
}

func BuildReference(keyID string, region scw.Region, projectID, version string) keymgmt.KeyReference {
	if version == "" {
		version = defaultReferenceVersion
	}
	uri := buildURI(keyID, region, projectID, version)
	return keymgmt.KeyReference{
		Backend: BackendName,
		URI:     uri,
		ID:      keyID,
		Version: version,
	}
}

func ResolveReference(ref keymgmt.KeyReference, fallbackRegion scw.Region) (Reference, error) {
	if ref.Backend == "" {
		return Reference{}, enigma.WrapError("keymgmt/scwkm.ResolveReference", enigma.ErrInvalidKeyReference, fmt.Errorf("missing backend"))
	}
	if ref.Backend != BackendName {
		return Reference{}, enigma.WrapError("keymgmt/scwkm.ResolveReference", enigma.ErrInvalidKeyReference, fmt.Errorf("backend %q", ref.Backend))
	}

	resolved := Reference{KeyID: ref.ID, Version: ref.Version, URI: ref.URI}
	if resolved.URI != "" {
		parsed, err := parseReferenceURI(resolved.URI)
		if err != nil {
			return Reference{}, err
		}
		if resolved.KeyID == "" {
			resolved.KeyID = parsed.KeyID
		}
		if resolved.Version == "" {
			resolved.Version = parsed.Version
		}
		resolved.ProjectID = parsed.ProjectID
		resolved.Region = parsed.Region
	}
	if resolved.KeyID == "" {
		return Reference{}, enigma.WrapError("keymgmt/scwkm.ResolveReference", enigma.ErrInvalidKeyReference, fmt.Errorf("missing key id"))
	}
	if resolved.Region == "" {
		if fallbackRegion == "" {
			return Reference{}, enigma.WrapError("keymgmt/scwkm.ResolveReference", enigma.ErrInvalidKeyReference, fmt.Errorf("missing region"))
		}
		resolved.Region = fallbackRegion
	}
	if resolved.Version == "" {
		resolved.Version = defaultReferenceVersion
	}
	if resolved.URI == "" {
		resolved.URI = buildURI(resolved.KeyID, resolved.Region, resolved.ProjectID, resolved.Version)
	}
	return resolved, nil
}

func parseReferenceURI(raw string) (Reference, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Reference{}, enigma.WrapError("keymgmt/scwkm.ResolveReference", enigma.ErrInvalidKeyReference, err)
	}
	if u.Scheme != referenceScheme {
		return Reference{}, enigma.WrapError("keymgmt/scwkm.ResolveReference", enigma.ErrInvalidKeyReference, fmt.Errorf("unexpected scheme %q", u.Scheme))
	}
	if u.Host != "" && u.Host != referenceHost {
		return Reference{}, enigma.WrapError("keymgmt/scwkm.ResolveReference", enigma.ErrInvalidKeyReference, fmt.Errorf("unexpected host %q", u.Host))
	}
	keyID := strings.TrimPrefix(u.EscapedPath(), "/")
	keyID, err = url.PathUnescape(keyID)
	if err != nil {
		return Reference{}, enigma.WrapError("keymgmt/scwkm.ResolveReference", enigma.ErrInvalidKeyReference, err)
	}
	q := u.Query()
	parsed := Reference{
		KeyID:     keyID,
		Version:   q.Get("version"),
		ProjectID: q.Get(metadataProjectID),
	}
	if rawRegion := q.Get(metadataRegion); rawRegion != "" {
		region, err := scw.ParseRegion(rawRegion)
		if err != nil {
			return Reference{}, enigma.WrapError("keymgmt/scwkm.ResolveReference", enigma.ErrInvalidKeyReference, fmt.Errorf("invalid region %q: %w", rawRegion, err))
		}
		parsed.Region = region
	}
	return parsed, nil
}

func buildURI(keyID string, region scw.Region, projectID, version string) string {
	u := &url.URL{Scheme: referenceScheme, Host: referenceHost, Path: "/" + url.PathEscape(keyID)}
	q := u.Query()
	q.Set(metadataRegion, string(region))
	if projectID != "" {
		q.Set(metadataProjectID, projectID)
	}
	if version != "" {
		q.Set("version", version)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func descriptorFromKey(k *keymanager.Key, requestedPurpose keymgmt.KeyPurpose, metadata map[string]string) (*keymgmt.KeyDescriptor, error) {
	alg, class, err := algorithmAndClassFromUsage(k.Usage)
	if err != nil {
		return nil, err
	}
	if requestedPurpose == "" {
		requestedPurpose = purposeFromClass(class)
	}

	version := strconv.FormatUint(uint64(k.RotationCount), 10)
	ref := BuildReference(k.ID, k.Region, k.ProjectID, version)

	merged := map[string]string{
		metadataRegion:        string(k.Region),
		metadataProjectID:     k.ProjectID,
		metadataKeyState:      string(k.State),
		metadataKeyOrigin:     string(k.Origin),
		metadataRotationCount: version,
	}
	if k.Name != "" {
		merged[metadataKeyName] = k.Name
	}
	if requestedPurpose != "" {
		merged[metadataRequestedPurpose] = string(requestedPurpose)
	}
	for mk, mv := range metadata {
		merged[mk] = mv
	}

	return &keymgmt.KeyDescriptor{
		ID:            k.ID,
		Backend:       BackendName,
		Class:         class,
		Purpose:       requestedPurpose,
		Algorithm:     alg,
		SecurityLevel: keymgmt.SecurityLevelCloudClassic,
		Reference:     ref,
		Capabilities:  capabilitySet(),
		Metadata:      merged,
	}, nil
}

func purposeFromClass(class keymgmt.KeyClass) keymgmt.KeyPurpose {
	switch class {
	case keymgmt.KeyClassAsymmetricKEM:
		return keymgmt.PurposeKeyEncapsulation
	case keymgmt.KeyClassAsymmetricEncryption, keymgmt.KeyClassSymmetricWrapping:
		return keymgmt.PurposeKeyWrapping
	default:
		return keymgmt.PurposeKeyWrapping
	}
}

func usageForAlgorithm(alg keymgmt.KeyAlgorithm) (*keymanager.KeyUsage, keymgmt.KeyClass, error) {
	switch alg {
	case keymgmt.AlgorithmAES256GCM:
		usage := keymanager.KeyAlgorithmSymmetricEncryptionAes256Gcm
		return &keymanager.KeyUsage{SymmetricEncryption: &usage}, keymgmt.KeyClassSymmetricWrapping, nil
	case keymgmt.AlgorithmRSAOAEP3072SHA256:
		usage := keymanager.KeyAlgorithmAsymmetricEncryptionRsaOaep3072Sha256
		return &keymanager.KeyUsage{AsymmetricEncryption: &usage}, keymgmt.KeyClassAsymmetricEncryption, nil
	case keymgmt.AlgorithmMLKEM768, keymgmt.AlgorithmMLKEM1024:
		return nil, "", enigma.WrapError("keymgmt/scwkm.usageForAlgorithm", enigma.ErrKeyAlgorithmMismatch, fmt.Errorf("algorithm %q requires PQ support not provided by scaleway kms", alg))
	default:
		return nil, "", enigma.WrapError("keymgmt/scwkm.usageForAlgorithm", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("algorithm %q", alg))
	}
}

func algorithmAndClassFromUsage(usage *keymanager.KeyUsage) (keymgmt.KeyAlgorithm, keymgmt.KeyClass, error) {
	if usage == nil {
		return "", "", enigma.WrapError("keymgmt/scwkm.algorithmAndClassFromUsage", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("missing key usage"))
	}
	if usage.SymmetricEncryption != nil {
		switch *usage.SymmetricEncryption {
		case keymanager.KeyAlgorithmSymmetricEncryptionUnknownSymmetricEncryption:
			return "", "", enigma.WrapError("keymgmt/scwkm.algorithmAndClassFromUsage", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unknown symmetric usage"))
		case keymanager.KeyAlgorithmSymmetricEncryptionAes256Gcm:
			return keymgmt.AlgorithmAES256GCM, keymgmt.KeyClassSymmetricWrapping, nil
		default:
			return "", "", enigma.WrapError("keymgmt/scwkm.algorithmAndClassFromUsage", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unsupported symmetric usage %q", usage.SymmetricEncryption.String()))
		}
	}
	if usage.AsymmetricEncryption != nil {
		switch *usage.AsymmetricEncryption {
		case keymanager.KeyAlgorithmAsymmetricEncryptionUnknownAsymmetricEncryption:
			return "", "", enigma.WrapError("keymgmt/scwkm.algorithmAndClassFromUsage", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unknown asymmetric usage"))
		case keymanager.KeyAlgorithmAsymmetricEncryptionRsaOaep2048Sha256:
			return "", "", enigma.WrapError("keymgmt/scwkm.algorithmAndClassFromUsage", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unsupported asymmetric usage %q", usage.AsymmetricEncryption.String()))
		case keymanager.KeyAlgorithmAsymmetricEncryptionRsaOaep3072Sha256:
			return keymgmt.AlgorithmRSAOAEP3072SHA256, keymgmt.KeyClassAsymmetricEncryption, nil
		case keymanager.KeyAlgorithmAsymmetricEncryptionRsaOaep4096Sha256:
			return "", "", enigma.WrapError("keymgmt/scwkm.algorithmAndClassFromUsage", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unsupported asymmetric usage %q", usage.AsymmetricEncryption.String()))
		default:
			return "", "", enigma.WrapError("keymgmt/scwkm.algorithmAndClassFromUsage", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unsupported asymmetric usage %q", usage.AsymmetricEncryption.String()))
		}
	}
	return "", "", enigma.WrapError("keymgmt/scwkm.algorithmAndClassFromUsage", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("usage is not supported for envelope wrapping"))
}

func mapSDKError(op string, kind error, err error) error {
	if err == nil {
		return nil
	}
	var notFound *scw.ResourceNotFoundError
	if errors.As(err, &notFound) {
		return enigma.WrapError(op, enigma.ErrKeyNotFound, err)
	}
	var invalid *scw.InvalidArgumentsError
	if errors.As(err, &invalid) {
		return enigma.WrapError(op, enigma.ErrInvalidArgument, err)
	}
	return enigma.WrapError(op, kind, err)
}
