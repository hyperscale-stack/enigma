package gcpkms

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
)

type Mode string

const (
	ModeClassical Mode = "classical"
	ModePQNative  Mode = "pq-native"
)

type Recipient struct {
	keyRef string
	mode   Mode
}

func New(keyRef string, mode Mode) *Recipient {
	if mode == "" {
		mode = ModeClassical
	}
	return &Recipient{keyRef: keyRef, mode: mode}
}

func (r *Recipient) WrapKey(ctx context.Context, dek []byte) (*recipient.WrappedKey, error) {
	_ = ctx
	_ = dek
	return nil, enigma.WrapError("gcpkms.WrapKey", enigma.ErrNotImplemented, fmt.Errorf("cloud integration is deferred in v1"))
}

func (r *Recipient) UnwrapKey(ctx context.Context, wk *recipient.WrappedKey) ([]byte, error) {
	_ = ctx
	_ = wk
	return nil, enigma.WrapError("gcpkms.UnwrapKey", enigma.ErrNotImplemented, fmt.Errorf("cloud integration is deferred in v1"))
}

func (r *Recipient) Descriptor() recipient.Descriptor {
	capability := recipient.CapabilityCloudClassical
	if r.mode == ModePQNative {
		capability = recipient.CapabilityCloudPQNative
	}
	return recipient.Descriptor{
		Type:             recipient.TypeGCPKMS,
		Capability:       capability,
		KeyRef:           r.keyRef,
		RewrapCompatible: true,
		Metadata: map[string]string{
			"mode": string(r.mode),
		},
	}
}
