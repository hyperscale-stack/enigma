package awskms

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
)

type Recipient struct {
	keyRef string
}

func New(keyRef string) *Recipient {
	return &Recipient{keyRef: keyRef}
}

func (r *Recipient) WrapKey(ctx context.Context, dek []byte) (*recipient.WrappedKey, error) {
	_ = ctx
	_ = dek
	return nil, enigma.WrapError("awskms.WrapKey", enigma.ErrNotImplemented, fmt.Errorf("cloud integration is deferred in v1"))
}

func (r *Recipient) UnwrapKey(ctx context.Context, wk *recipient.WrappedKey) ([]byte, error) {
	_ = ctx
	_ = wk
	return nil, enigma.WrapError("awskms.UnwrapKey", enigma.ErrNotImplemented, fmt.Errorf("cloud integration is deferred in v1"))
}

func (r *Recipient) Descriptor() recipient.Descriptor {
	return recipient.Descriptor{
		Type:             recipient.TypeAWSKMS,
		Capability:       recipient.CapabilityCloudClassical,
		KeyRef:           r.keyRef,
		RewrapCompatible: true,
	}
}
