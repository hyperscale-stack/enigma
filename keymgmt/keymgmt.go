package keymgmt

import "context"

type KeyManager interface {
	CreateKey(ctx context.Context, req CreateKeyRequest) (*KeyDescriptor, error)
	GetKey(ctx context.Context, ref KeyReference) (*KeyDescriptor, error)
	RotateKey(ctx context.Context, ref KeyReference, req RotateKeyRequest) (*KeyDescriptor, error)
	DeleteKey(ctx context.Context, ref KeyReference) error
	Capabilities(ctx context.Context) CapabilitySet
}

type KeyClass string

const (
	KeyClassAsymmetricKEM        KeyClass = "asymmetric_kem"
	KeyClassAsymmetricEncryption KeyClass = "asymmetric_encryption"
	KeyClassSymmetricWrapping    KeyClass = "symmetric_wrapping"
)

type KeyPurpose string

const (
	PurposeKeyEncapsulation KeyPurpose = "key_encapsulation"
	PurposeKeyWrapping      KeyPurpose = "key_wrapping"
	PurposeRecipientDecrypt KeyPurpose = "recipient_decrypt"
)

type KeyAlgorithm string

const (
	AlgorithmMLKEM768          KeyAlgorithm = "ml-kem-768"
	AlgorithmMLKEM1024         KeyAlgorithm = "ml-kem-1024"
	AlgorithmRSAOAEP3072SHA256 KeyAlgorithm = "rsa-oaep-3072-sha256"
	AlgorithmAES256GCM         KeyAlgorithm = "aes-256-gcm"
)

type ProtectionLevel string

const (
	ProtectionSoftware ProtectionLevel = "software"
	ProtectionHSM      ProtectionLevel = "hsm"
	ProtectionKMS      ProtectionLevel = "kms"
)

type SecurityLevel string

const (
	SecurityLevelLocalPQ       SecurityLevel = "local_pq"
	SecurityLevelCloudPQNative SecurityLevel = "cloud_pq_native"
	SecurityLevelCloudClassic  SecurityLevel = "cloud_classical"
)

type CreateKeyRequest struct {
	Name            string            `json:"name"`
	Purpose         KeyPurpose        `json:"purpose"`
	Algorithm       KeyAlgorithm      `json:"algorithm"`
	ProtectionLevel ProtectionLevel   `json:"protection_level"`
	Exportable      bool              `json:"exportable"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type RotateKeyRequest struct {
	SuccessorName string            `json:"successor_name"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type KeyReference struct {
	Backend string `json:"backend"`
	URI     string `json:"uri"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

type PublicKeyInfo struct {
	Algorithm KeyAlgorithm `json:"algorithm"`
	Data      []byte       `json:"data"`
}

type KeyDescriptor struct {
	ID            string            `json:"id"`
	Backend       string            `json:"backend"`
	Class         KeyClass          `json:"class"`
	Purpose       KeyPurpose        `json:"purpose"`
	Algorithm     KeyAlgorithm      `json:"algorithm"`
	SecurityLevel SecurityLevel     `json:"security_level"`
	Reference     KeyReference      `json:"reference"`
	PublicInfo    *PublicKeyInfo    `json:"public_info,omitempty"`
	Capabilities  CapabilitySet     `json:"capabilities"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type CapabilitySet struct {
	CanCreateKeys             bool `json:"can_create_keys"`
	CanDeleteKeys             bool `json:"can_delete_keys"`
	CanRotateProviderNative   bool `json:"can_rotate_provider_native"`
	CanExportPublicKey        bool `json:"can_export_public_key"`
	CanResolveRecipient       bool `json:"can_resolve_recipient"`
	SupportsPQNatively        bool `json:"supports_pq_natively"`
	SupportsClassicalWrapping bool `json:"supports_classical_wrapping"`
	SupportsRewrapWorkflow    bool `json:"supports_rewrap_workflow"`
}

func CloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
