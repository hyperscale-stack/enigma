package scwkm

import (
	"context"
	"errors"
	"fmt"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/keymgmt"
	"github.com/hyperscale-stack/enigma/recipient"
	recipientscwkm "github.com/hyperscale-stack/enigma/recipient/scwkm"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

type Config = recipientscwkm.Config

type recipientFactory func(cfg Config, ref keymgmt.KeyReference) (recipient.Recipient, error)

type Resolver struct {
	cfg     Config
	factory recipientFactory
}

func New(cfg Config) (*Resolver, error) {
	if cfg.Region == "" {
		return nil, enigma.WrapError("resolver/scwkm.New", enigma.ErrInvalidArgument, fmt.Errorf("missing region"))
	}
	if _, err := scw.ParseRegion(cfg.Region); err != nil {
		return nil, enigma.WrapError("resolver/scwkm.New", enigma.ErrInvalidArgument, err)
	}
	if (cfg.AccessKey == "") != (cfg.SecretKey == "") {
		return nil, enigma.WrapError("resolver/scwkm.New", enigma.ErrInvalidArgument, fmt.Errorf("both access key and secret key must be set together"))
	}
	return &Resolver{
		cfg: cfg,
		factory: func(cfg Config, ref keymgmt.KeyReference) (recipient.Recipient, error) {
			return recipientscwkm.NewFromReference(cfg, ref)
		},
	}, nil
}

func (r *Resolver) ResolveRecipient(ctx context.Context, ref keymgmt.KeyReference) (recipient.Recipient, error) {
	_ = ctx
	rcp, err := r.factory(r.cfg, ref)
	if err == nil {
		return rcp, nil
	}
	if errors.Is(err, enigma.ErrInvalidArgument) || errors.Is(err, enigma.ErrInvalidKeyReference) || errors.Is(err, enigma.ErrKeyNotFound) {
		return nil, err
	}
	return nil, enigma.WrapError("resolver/scwkm.ResolveRecipient", enigma.ErrResolveRecipientFailed, err)
}
