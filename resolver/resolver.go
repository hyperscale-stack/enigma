package resolver

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/keymgmt"
	"github.com/hyperscale-stack/enigma/recipient"
)

type RecipientResolver interface {
	ResolveRecipient(ctx context.Context, ref keymgmt.KeyReference) (recipient.Recipient, error)
}

type Registry struct {
	backends map[string]RecipientResolver
}

func NewRegistry() *Registry {
	return &Registry{backends: make(map[string]RecipientResolver)}
}

func (r *Registry) RegisterBackend(backend string, rr RecipientResolver) error {
	if backend == "" {
		return enigma.WrapError("resolver.Registry.RegisterBackend", enigma.ErrInvalidArgument, fmt.Errorf("empty backend"))
	}
	if rr == nil {
		return enigma.WrapError("resolver.Registry.RegisterBackend", enigma.ErrInvalidArgument, fmt.Errorf("nil resolver"))
	}
	r.backends[backend] = rr
	return nil
}

func (r *Registry) ResolveRecipient(ctx context.Context, ref keymgmt.KeyReference) (recipient.Recipient, error) {
	if ref.Backend == "" {
		return nil, enigma.WrapError("resolver.Registry.ResolveRecipient", enigma.ErrInvalidKeyReference, fmt.Errorf("missing backend"))
	}
	rr, ok := r.backends[ref.Backend]
	if !ok {
		return nil, enigma.WrapError("resolver.Registry.ResolveRecipient", enigma.ErrResolveRecipientFailed, fmt.Errorf("unknown backend %q", ref.Backend))
	}
	rcp, err := rr.ResolveRecipient(ctx, ref)
	if err != nil {
		return nil, enigma.WrapError("resolver.Registry.ResolveRecipient", enigma.ErrResolveRecipientFailed, err)
	}
	return rcp, nil
}
