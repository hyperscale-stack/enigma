package scwkm

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/internal/scwkmapi"
	"github.com/hyperscale-stack/enigma/keymgmt"
	keymanager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/stretchr/testify/assert"
)

type mockAPI struct {
	createFn func(ctx context.Context, req *keymanager.CreateKeyRequest) (*keymanager.Key, error)
	getFn    func(ctx context.Context, req *keymanager.GetKeyRequest) (*keymanager.Key, error)
	rotateFn func(ctx context.Context, req *keymanager.RotateKeyRequest) (*keymanager.Key, error)
	delFn    func(ctx context.Context, req *keymanager.DeleteKeyRequest) error
	encFn    func(ctx context.Context, req *keymanager.EncryptRequest) (*keymanager.EncryptResponse, error)
	decFn    func(ctx context.Context, req *keymanager.DecryptRequest) (*keymanager.DecryptResponse, error)
}

func managerForTest(t *testing.T, api scwkmapi.Client, region, projectID string) *Manager {
	t.Helper()
	parsedRegion, err := scw.ParseRegion(region)
	assert.NoError(t, err)
	return &Manager{api: api, defaultRegion: parsedRegion, defaultProject: projectID}
}

func (m *mockAPI) CreateKey(ctx context.Context, req *keymanager.CreateKeyRequest) (*keymanager.Key, error) {
	if m.createFn == nil {
		return nil, fmt.Errorf("unexpected CreateKey")
	}
	return m.createFn(ctx, req)
}

func (m *mockAPI) GetKey(ctx context.Context, req *keymanager.GetKeyRequest) (*keymanager.Key, error) {
	if m.getFn == nil {
		return nil, fmt.Errorf("unexpected GetKey")
	}
	return m.getFn(ctx, req)
}

func (m *mockAPI) RotateKey(ctx context.Context, req *keymanager.RotateKeyRequest) (*keymanager.Key, error) {
	if m.rotateFn == nil {
		return nil, fmt.Errorf("unexpected RotateKey")
	}
	return m.rotateFn(ctx, req)
}

func (m *mockAPI) DeleteKey(ctx context.Context, req *keymanager.DeleteKeyRequest) error {
	if m.delFn == nil {
		return fmt.Errorf("unexpected DeleteKey")
	}
	return m.delFn(ctx, req)
}

func (m *mockAPI) Encrypt(ctx context.Context, req *keymanager.EncryptRequest) (*keymanager.EncryptResponse, error) {
	if m.encFn == nil {
		return nil, fmt.Errorf("unexpected Encrypt")
	}
	return m.encFn(ctx, req)
}

func (m *mockAPI) Decrypt(ctx context.Context, req *keymanager.DecryptRequest) (*keymanager.DecryptResponse, error) {
	if m.decFn == nil {
		return nil, fmt.Errorf("unexpected Decrypt")
	}
	return m.decFn(ctx, req)
}

func TestBuildAndResolveReferenceRoundTrip(t *testing.T) {
	ref := BuildReference("key-1", scw.RegionFrPar, "proj-1", "7")
	assert.Equal(t, BackendName, ref.Backend)
	assert.NotEmpty(t, ref.URI)

	resolved, err := ResolveReference(ref, "")
	assert.NoError(t, err)
	assert.Equal(t, "key-1", resolved.KeyID)
	assert.Equal(t, scw.RegionFrPar, resolved.Region)
	assert.Equal(t, "proj-1", resolved.ProjectID)
	assert.Equal(t, "7", resolved.Version)
}

func TestResolveReferenceValidation(t *testing.T) {
	_, err := ResolveReference(keymgmt.KeyReference{}, scw.RegionFrPar)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	_, err = ResolveReference(keymgmt.KeyReference{Backend: "other", ID: "x"}, scw.RegionFrPar)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	_, err = ResolveReference(keymgmt.KeyReference{Backend: BackendName, URI: "not-a-uri"}, scw.RegionFrPar)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	badScheme := keymgmt.KeyReference{Backend: BackendName, URI: "http://key/k1?region=fr-par"}
	_, err = ResolveReference(badScheme, scw.RegionFrPar)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	missingRegion := keymgmt.KeyReference{Backend: BackendName, ID: "k1"}
	_, err = ResolveReference(missingRegion, "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))
}

func TestNewManagerValidation(t *testing.T) {
	_, err := NewManager(Config{})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = NewManager(Config{Region: "invalid-region"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = NewManager(Config{Region: "fr-par", AccessKey: "SCWXXXXXXXXXXXXXXXXX"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestCapabilities(t *testing.T) {
	m := managerForTest(t, &mockAPI{}, "fr-par", "")
	caps := m.Capabilities(context.Background())
	assert.True(t, caps.CanCreateKeys)
	assert.True(t, caps.CanDeleteKeys)
	assert.True(t, caps.CanRotateProviderNative)
	assert.True(t, caps.CanExportPublicKey)
	assert.True(t, caps.CanResolveRecipient)
	assert.False(t, caps.SupportsPQNatively)
	assert.True(t, caps.SupportsClassicalWrapping)
	assert.True(t, caps.SupportsRewrapWorkflow)
}

func TestCreateGetRotateDeleteSuccess(t *testing.T) {
	algSym := keymanager.KeyAlgorithmSymmetricEncryptionAes256Gcm
	api := &mockAPI{}
	api.createFn = func(_ context.Context, req *keymanager.CreateKeyRequest) (*keymanager.Key, error) {
		assert.Equal(t, scw.RegionFrPar, req.Region)
		assert.Equal(t, "project-a", req.ProjectID)
		assert.NotNil(t, req.Usage)
		assert.NotNil(t, req.Usage.SymmetricEncryption)
		assert.Equal(t, algSym, *req.Usage.SymmetricEncryption)
		if assert.NotNil(t, req.Name) {
			assert.Equal(t, "tenant-a", *req.Name)
		}
		return &keymanager.Key{
			ID:            "k-1",
			ProjectID:     "project-a",
			Name:          "tenant-a",
			Usage:         &keymanager.KeyUsage{SymmetricEncryption: &algSym},
			RotationCount: 0,
			Region:        scw.RegionFrPar,
			State:         keymanager.KeyStateEnabled,
			Origin:        keymanager.KeyOriginScalewayKms,
		}, nil
	}
	api.getFn = func(_ context.Context, req *keymanager.GetKeyRequest) (*keymanager.Key, error) {
		assert.Equal(t, "k-1", req.KeyID)
		assert.Equal(t, scw.RegionFrPar, req.Region)
		return &keymanager.Key{
			ID:            "k-1",
			ProjectID:     "project-a",
			Usage:         &keymanager.KeyUsage{SymmetricEncryption: &algSym},
			RotationCount: 1,
			Region:        scw.RegionFrPar,
			State:         keymanager.KeyStateEnabled,
			Origin:        keymanager.KeyOriginScalewayKms,
		}, nil
	}
	api.rotateFn = func(_ context.Context, req *keymanager.RotateKeyRequest) (*keymanager.Key, error) {
		assert.Equal(t, "k-1", req.KeyID)
		assert.Equal(t, scw.RegionFrPar, req.Region)
		return &keymanager.Key{
			ID:            "k-1",
			ProjectID:     "project-a",
			Usage:         &keymanager.KeyUsage{SymmetricEncryption: &algSym},
			RotationCount: 2,
			Region:        scw.RegionFrPar,
			State:         keymanager.KeyStateEnabled,
			Origin:        keymanager.KeyOriginScalewayKms,
		}, nil
	}
	api.delFn = func(_ context.Context, req *keymanager.DeleteKeyRequest) error {
		assert.Equal(t, "k-1", req.KeyID)
		assert.Equal(t, scw.RegionFrPar, req.Region)
		return nil
	}

	m := managerForTest(t, api, "fr-par", "project-a")

	desc, err := m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Name:            "tenant-a",
		Purpose:         keymgmt.PurposeKeyWrapping,
		Algorithm:       keymgmt.AlgorithmAES256GCM,
		ProtectionLevel: keymgmt.ProtectionKMS,
		Metadata:        map[string]string{"tenant": "a"},
	})
	assert.NoError(t, err)
	assert.Equal(t, "k-1", desc.ID)
	assert.Equal(t, BackendName, desc.Backend)
	assert.Equal(t, keymgmt.KeyClassSymmetricWrapping, desc.Class)
	assert.Equal(t, keymgmt.AlgorithmAES256GCM, desc.Algorithm)
	assert.Equal(t, keymgmt.SecurityLevelCloudClassic, desc.SecurityLevel)
	assert.Equal(t, "a", desc.Metadata["tenant"])
	assert.Contains(t, desc.Reference.URI, "region=fr-par")

	loaded, err := m.GetKey(context.Background(), desc.Reference)
	assert.NoError(t, err)
	assert.Equal(t, "1", loaded.Reference.Version)

	rotated, err := m.RotateKey(context.Background(), desc.Reference, keymgmt.RotateKeyRequest{SuccessorName: "ignored-native"})
	assert.NoError(t, err)
	assert.Equal(t, "2", rotated.Reference.Version)

	assert.NoError(t, m.DeleteKey(context.Background(), desc.Reference))
}

func TestManagerErrorMappingAndUnsupportedRequests(t *testing.T) {
	api := &mockAPI{}
	api.createFn = func(_ context.Context, _ *keymanager.CreateKeyRequest) (*keymanager.Key, error) {
		return nil, &scw.InvalidArgumentsError{Details: []scw.InvalidArgumentsErrorDetail{{ArgumentName: "project_id", Reason: "required"}}}
	}
	api.getFn = func(_ context.Context, _ *keymanager.GetKeyRequest) (*keymanager.Key, error) {
		return nil, &scw.ResourceNotFoundError{Resource: "key", ResourceID: "missing"}
	}

	m := managerForTest(t, api, "fr-par", "")
	var err error

	_, err = m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Purpose:         keymgmt.PurposeKeyWrapping,
		Algorithm:       keymgmt.AlgorithmAES256GCM,
		ProtectionLevel: keymgmt.ProtectionKMS,
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = m.GetKey(context.Background(), BuildReference("missing", scw.RegionFrPar, "", ""))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrKeyNotFound))

	_, err = m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Purpose:         keymgmt.PurposeKeyEncapsulation,
		Algorithm:       keymgmt.AlgorithmAES256GCM,
		ProtectionLevel: keymgmt.ProtectionKMS,
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedCapability))

	_, err = m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Purpose:         keymgmt.PurposeKeyWrapping,
		Algorithm:       keymgmt.AlgorithmMLKEM768,
		ProtectionLevel: keymgmt.ProtectionKMS,
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrKeyAlgorithmMismatch))

	_, err = m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Purpose:         keymgmt.PurposeKeyWrapping,
		Algorithm:       keymgmt.AlgorithmAES256GCM,
		ProtectionLevel: keymgmt.ProtectionHSM,
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedCapability))

	_, err = m.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
		Purpose:         keymgmt.PurposeKeyWrapping,
		Algorithm:       keymgmt.AlgorithmAES256GCM,
		ProtectionLevel: keymgmt.ProtectionKMS,
		Exportable:      true,
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedCapability))
}

func TestAlgorithmUsageMapping(t *testing.T) {
	usage, class, err := usageForAlgorithm(keymgmt.AlgorithmRSAOAEP3072SHA256)
	assert.NoError(t, err)
	if assert.NotNil(t, usage.AsymmetricEncryption) {
		assert.Equal(t, keymanager.KeyAlgorithmAsymmetricEncryptionRsaOaep3072Sha256, *usage.AsymmetricEncryption)
	}
	assert.Equal(t, keymgmt.KeyClassAsymmetricEncryption, class)

	alg, outClass, err := algorithmAndClassFromUsage(&keymanager.KeyUsage{AsymmetricEncryption: usage.AsymmetricEncryption})
	assert.NoError(t, err)
	assert.Equal(t, keymgmt.AlgorithmRSAOAEP3072SHA256, alg)
	assert.Equal(t, keymgmt.KeyClassAsymmetricEncryption, outClass)

	_, _, err = usageForAlgorithm(keymgmt.KeyAlgorithm("unknown"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))

	_, _, err = algorithmAndClassFromUsage(nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))
}
