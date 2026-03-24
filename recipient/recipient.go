package recipient

import "context"

type RecipientType string

const (
	TypeLocalMLKEM RecipientType = "local-mlkem"
	TypeGCPKMS     RecipientType = "gcp-kms"
	TypeAWSKMS     RecipientType = "aws-kms"
	TypeAzureKV    RecipientType = "azure-key-vault"
	TypeSCWKM      RecipientType = "scaleway-km"
)

type CapabilityLevel string

const (
	CapabilityLocalPQ        CapabilityLevel = "local-pq"
	CapabilityCloudClassical CapabilityLevel = "cloud-classical"
	CapabilityCloudPQNative  CapabilityLevel = "cloud-pq-native"
)

// Recipient can wrap and unwrap a DEK.
type Recipient interface {
	WrapKey(ctx context.Context, dek []byte) (*WrappedKey, error)
	UnwrapKey(ctx context.Context, wk *WrappedKey) ([]byte, error)
	Descriptor() Descriptor
}

type Descriptor struct {
	Type             RecipientType
	Capability       CapabilityLevel
	KeyRef           string
	RewrapCompatible bool
	Metadata         map[string]string
}

type WrappedKey struct {
	RecipientType   RecipientType
	Capability      CapabilityLevel
	WrapAlgorithm   string
	KeyRef          string
	EncapsulatedKey []byte
	Nonce           []byte
	Ciphertext      []byte
	Metadata        map[string]string
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
