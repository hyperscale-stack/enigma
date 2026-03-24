package scwkmapi

import (
	"context"
	"fmt"

	keymanager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

const (
	BackendName = "scaleway_kms"
)

type Config struct {
	Region    string
	AccessKey string //nolint:gosec // credential identifier used for SDK authentication wiring
	SecretKey string //nolint:gosec // credential value passed to SDK, never persisted by this package
	APIURL    string
	ProjectID string
}

type Client interface {
	CreateKey(ctx context.Context, req *keymanager.CreateKeyRequest) (*keymanager.Key, error)
	GetKey(ctx context.Context, req *keymanager.GetKeyRequest) (*keymanager.Key, error)
	RotateKey(ctx context.Context, req *keymanager.RotateKeyRequest) (*keymanager.Key, error)
	DeleteKey(ctx context.Context, req *keymanager.DeleteKeyRequest) error
	Encrypt(ctx context.Context, req *keymanager.EncryptRequest) (*keymanager.EncryptResponse, error)
	Decrypt(ctx context.Context, req *keymanager.DecryptRequest) (*keymanager.DecryptResponse, error)
}

type SDKClient struct {
	api *keymanager.API
}

func New(cfg Config) (*SDKClient, scw.Region, error) {
	if cfg.Region == "" {
		return nil, "", fmt.Errorf("missing region")
	}
	region, err := scw.ParseRegion(cfg.Region)
	if err != nil {
		return nil, "", fmt.Errorf("invalid region %q: %w", cfg.Region, err)
	}
	if (cfg.AccessKey == "") != (cfg.SecretKey == "") {
		return nil, "", fmt.Errorf("both access key and secret key must be set together")
	}

	opts := []scw.ClientOption{
		scw.WithDefaultRegion(region),
	}
	if cfg.ProjectID != "" {
		opts = append(opts, scw.WithDefaultProjectID(cfg.ProjectID))
	}
	if cfg.APIURL != "" {
		opts = append(opts, scw.WithAPIURL(cfg.APIURL))
	}
	if cfg.AccessKey != "" {
		opts = append(opts, scw.WithAuth(cfg.AccessKey, cfg.SecretKey))
	} else {
		opts = append(opts, scw.WithEnv())
	}

	client, err := scw.NewClient(opts...)
	if err != nil {
		return nil, "", err
	}
	return &SDKClient{api: keymanager.NewAPI(client)}, region, nil
}

func (c *SDKClient) CreateKey(ctx context.Context, req *keymanager.CreateKeyRequest) (*keymanager.Key, error) {
	return c.api.CreateKey(req, scw.WithContext(ctx))
}

func (c *SDKClient) GetKey(ctx context.Context, req *keymanager.GetKeyRequest) (*keymanager.Key, error) {
	return c.api.GetKey(req, scw.WithContext(ctx))
}

func (c *SDKClient) RotateKey(ctx context.Context, req *keymanager.RotateKeyRequest) (*keymanager.Key, error) {
	return c.api.RotateKey(req, scw.WithContext(ctx))
}

func (c *SDKClient) DeleteKey(ctx context.Context, req *keymanager.DeleteKeyRequest) error {
	return c.api.DeleteKey(req, scw.WithContext(ctx))
}

func (c *SDKClient) Encrypt(ctx context.Context, req *keymanager.EncryptRequest) (*keymanager.EncryptResponse, error) {
	return c.api.Encrypt(req, scw.WithContext(ctx))
}

func (c *SDKClient) Decrypt(ctx context.Context, req *keymanager.DecryptRequest) (*keymanager.DecryptResponse, error) {
	return c.api.Decrypt(req, scw.WithContext(ctx))
}
