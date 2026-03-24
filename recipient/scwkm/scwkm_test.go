package scwkm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/internal/scwkmapi"
	"github.com/hyperscale-stack/enigma/keymgmt"
	keymgmtscwkm "github.com/hyperscale-stack/enigma/keymgmt/scwkm"
	"github.com/hyperscale-stack/enigma/recipient"
	keymanager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/stretchr/testify/assert"
)

type mockRuntimeAPI struct {
	encryptFn func(ctx context.Context, req *keymanager.EncryptRequest) (*keymanager.EncryptResponse, error)
	decryptFn func(ctx context.Context, req *keymanager.DecryptRequest) (*keymanager.DecryptResponse, error)
}

func recipientForTest(t *testing.T, api scwkmapi.Client, region, keyID, keyRef, projectID string) *Recipient {
	t.Helper()
	parsedRegion, err := scw.ParseRegion(region)
	assert.NoError(t, err)
	if keyRef == "" {
		keyRef = keymgmtscwkm.BuildReference(keyID, parsedRegion, projectID, "").URI
	}
	return &Recipient{api: api, region: parsedRegion, keyID: keyID, keyRef: keyRef, projectID: projectID}
}

func (m *mockRuntimeAPI) CreateKey(context.Context, *keymanager.CreateKeyRequest) (*keymanager.Key, error) {
	return nil, fmt.Errorf("unexpected CreateKey")
}

func (m *mockRuntimeAPI) GetKey(context.Context, *keymanager.GetKeyRequest) (*keymanager.Key, error) {
	return nil, fmt.Errorf("unexpected GetKey")
}

func (m *mockRuntimeAPI) RotateKey(context.Context, *keymanager.RotateKeyRequest) (*keymanager.Key, error) {
	return nil, fmt.Errorf("unexpected RotateKey")
}

func (m *mockRuntimeAPI) DeleteKey(context.Context, *keymanager.DeleteKeyRequest) error {
	return fmt.Errorf("unexpected DeleteKey")
}

func (m *mockRuntimeAPI) Encrypt(ctx context.Context, req *keymanager.EncryptRequest) (*keymanager.EncryptResponse, error) {
	if m.encryptFn == nil {
		return nil, fmt.Errorf("unexpected Encrypt")
	}
	return m.encryptFn(ctx, req)
}

func (m *mockRuntimeAPI) Decrypt(ctx context.Context, req *keymanager.DecryptRequest) (*keymanager.DecryptResponse, error) {
	if m.decryptFn == nil {
		return nil, fmt.Errorf("unexpected Decrypt")
	}
	return m.decryptFn(ctx, req)
}

func TestNewAndNewFromReferenceValidation(t *testing.T) {
	_, err := New(Config{}, "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = New(Config{Region: "invalid"}, "key-1")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = NewFromReference(Config{Region: "fr-par"}, keymgmt.KeyReference{})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))

	ref := keymgmtscwkm.BuildReference("key-1", scw.RegionNlAms, "", "")
	_, err = NewFromReference(Config{Region: "fr-par"}, ref)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidKeyReference))
}

func TestWrapUnwrapRoundTripWithMockAPI(t *testing.T) {
	api := &mockRuntimeAPI{}
	api.encryptFn = func(_ context.Context, req *keymanager.EncryptRequest) (*keymanager.EncryptResponse, error) {
		assert.Equal(t, scw.RegionFrPar, req.Region)
		assert.Equal(t, "kms-key-1", req.KeyID)
		return &keymanager.EncryptResponse{Ciphertext: append([]byte("ct:"), req.Plaintext...)}, nil
	}
	api.decryptFn = func(_ context.Context, req *keymanager.DecryptRequest) (*keymanager.DecryptResponse, error) {
		assert.Equal(t, scw.RegionFrPar, req.Region)
		assert.Equal(t, "kms-key-1", req.KeyID)
		if !strings.HasPrefix(string(req.Ciphertext), "ct:") {
			return nil, fmt.Errorf("bad ciphertext")
		}
		pt := []byte(strings.TrimPrefix(string(req.Ciphertext), "ct:"))
		return &keymanager.DecryptResponse{Plaintext: pt}, nil
	}

	r := recipientForTest(t, api, "fr-par", "kms-key-1", "", "project-a")

	wk, err := r.WrapKey(context.Background(), []byte("dek-32bytes-value-1234567890"))
	assert.NoError(t, err)
	assert.Equal(t, recipient.TypeSCWKM, wk.RecipientType)
	assert.Equal(t, recipient.CapabilityCloudClassical, wk.Capability)
	assert.Equal(t, WrapAlgorithmEncryptV1, wk.WrapAlgorithm)
	assert.Contains(t, wk.KeyRef, "region=fr-par")
	assert.Equal(t, "kms-key-1", wk.Metadata["key_id"])

	dek, err := r.UnwrapKey(context.Background(), wk)
	assert.NoError(t, err)
	assert.Equal(t, "dek-32bytes-value-1234567890", string(dek))

	d := r.Descriptor()
	assert.Equal(t, recipient.TypeSCWKM, d.Type)
	assert.Equal(t, recipient.CapabilityCloudClassical, d.Capability)
	assert.True(t, d.RewrapCompatible)
	assert.Equal(t, "kms-key-1", d.Metadata["key_id"])
}

func TestWrapAndUnwrapErrorPaths(t *testing.T) {
	r := recipientForTest(t, &mockRuntimeAPI{}, "fr-par", "kms-key-1", "ref-1", "")
	var err error

	_, err = r.WrapKey(context.Background(), nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = r.UnwrapKey(context.Background(), nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = r.UnwrapKey(context.Background(), &recipient.WrappedKey{RecipientType: recipient.TypeAWSKMS, WrapAlgorithm: WrapAlgorithmEncryptV1, Ciphertext: []byte("x")})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrRecipientNotFound))

	_, err = r.UnwrapKey(context.Background(), &recipient.WrappedKey{RecipientType: recipient.TypeSCWKM, WrapAlgorithm: "unknown", Ciphertext: []byte("x")})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrUnsupportedAlgorithm))

	_, err = r.UnwrapKey(context.Background(), &recipient.WrappedKey{RecipientType: recipient.TypeSCWKM, WrapAlgorithm: WrapAlgorithmEncryptV1, KeyRef: "different", Ciphertext: []byte("x")})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrRecipientNotFound))

	_, err = r.UnwrapKey(context.Background(), &recipient.WrappedKey{RecipientType: recipient.TypeSCWKM, WrapAlgorithm: WrapAlgorithmEncryptV1, KeyRef: "ref-1"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))
}

func TestSDKErrorMapping(t *testing.T) {
	api := &mockRuntimeAPI{}
	api.encryptFn = func(_ context.Context, _ *keymanager.EncryptRequest) (*keymanager.EncryptResponse, error) {
		return nil, &scw.InvalidArgumentsError{Details: []scw.InvalidArgumentsErrorDetail{{ArgumentName: "plaintext", Reason: "required"}}}
	}
	api.decryptFn = func(_ context.Context, _ *keymanager.DecryptRequest) (*keymanager.DecryptResponse, error) {
		return nil, &scw.ResourceNotFoundError{Resource: "key", ResourceID: "missing"}
	}

	r := recipientForTest(t, api, "fr-par", "kms-key-1", "ref-1", "")
	var err error

	_, err = r.WrapKey(context.Background(), []byte("dek"))
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrInvalidArgument))

	_, err = r.UnwrapKey(context.Background(), &recipient.WrappedKey{RecipientType: recipient.TypeSCWKM, WrapAlgorithm: WrapAlgorithmEncryptV1, KeyRef: "ref-1", Ciphertext: []byte("ct")})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, enigma.ErrRecipientNotFound))
}
