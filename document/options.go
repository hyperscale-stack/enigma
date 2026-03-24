package document

import (
	"fmt"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
)

const (
	DefaultChunkSize = 64 * 1024
)

type Option func(*config) error

type config struct {
	recipients         []recipient.Recipient
	newRecipients      []recipient.Recipient
	removeRecipientRef map[string]struct{}
	replaceRecipients  bool

	profile   enigma.Profile
	suite     *enigma.AEADSuite
	chunkSize int
	metadata  map[string]string
}

func defaultConfig() *config {
	return &config{
		profile:            enigma.ProfileLocalPQ,
		chunkSize:          DefaultChunkSize,
		removeRecipientRef: make(map[string]struct{}),
	}
}

func WithRecipient(r recipient.Recipient) Option {
	return func(c *config) error {
		if r == nil {
			return enigma.WrapError("document.WithRecipient", enigma.ErrInvalidArgument, fmt.Errorf("recipient is nil"))
		}
		c.recipients = append(c.recipients, r)
		return nil
	}
}

func WithNewRecipient(r recipient.Recipient) Option {
	return func(c *config) error {
		if r == nil {
			return enigma.WrapError("document.WithNewRecipient", enigma.ErrInvalidArgument, fmt.Errorf("recipient is nil"))
		}
		c.newRecipients = append(c.newRecipients, r)
		return nil
	}
}

func WithRemoveRecipientKeyRef(keyRef string) Option {
	return func(c *config) error {
		if keyRef == "" {
			return enigma.WrapError("document.WithRemoveRecipientKeyRef", enigma.ErrInvalidArgument, fmt.Errorf("empty key ref"))
		}
		c.removeRecipientRef[keyRef] = struct{}{}
		return nil
	}
}

func WithReplaceRecipients() Option {
	return func(c *config) error {
		c.replaceRecipients = true
		return nil
	}
}

func WithDefaultProfile(p enigma.Profile) Option {
	return func(c *config) error {
		switch p {
		case enigma.ProfileLocalPQ, enigma.ProfileCloudBalanced, enigma.ProfileCompliance:
			c.profile = p
			return nil
		default:
			return enigma.WrapError("document.WithDefaultProfile", enigma.ErrInvalidArgument, fmt.Errorf("unknown profile %q", p))
		}
	}
}

func WithAEADSuite(suite enigma.AEADSuite) Option {
	return func(c *config) error {
		if _, err := enigma.ParseAEADSuite(uint16(suite)); err != nil {
			return err
		}
		c.suite = &suite
		return nil
	}
}

func WithChunkSize(size int) Option {
	return func(c *config) error {
		if size < 1024 || size > 8*1024*1024 {
			return enigma.WrapError("document.WithChunkSize", enigma.ErrInvalidArgument, fmt.Errorf("chunk size must be in [1024, 8388608]"))
		}
		c.chunkSize = size
		return nil
	}
}

func WithMetadata(metadata map[string]string) Option {
	return func(c *config) error {
		if len(metadata) == 0 {
			c.metadata = nil
			return nil
		}
		c.metadata = make(map[string]string, len(metadata))
		for k, v := range metadata {
			c.metadata[k] = v
		}
		return nil
	}
}

func buildConfig(opts ...Option) (*config, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func (c *config) resolvedSuite() enigma.AEADSuite {
	if c.suite != nil {
		return *c.suite
	}

	switch c.profile {
	case enigma.ProfileCompliance:
		return enigma.SuiteAES256GCM
	case enigma.ProfileLocalPQ, enigma.ProfileCloudBalanced:
		return enigma.SuiteXChaCha20Poly1305
	default:
		return enigma.SuiteXChaCha20Poly1305
	}
}

func validateEncryptConfig(cfg *config) error {
	if len(cfg.recipients) == 0 {
		return enigma.WrapError("document.validateEncryptConfig", enigma.ErrNoRecipients, nil)
	}
	suite := cfg.resolvedSuite()
	if _, err := enigma.ParseAEADSuite(uint16(suite)); err != nil {
		return err
	}
	if cfg.profile == enigma.ProfileLocalPQ {
		for _, r := range cfg.recipients {
			d := r.Descriptor()
			if d.Capability != recipient.CapabilityLocalPQ {
				return enigma.WrapError("document.validateEncryptConfig", enigma.ErrCapabilityMismatch, fmt.Errorf("profile %q requires local-pq recipients, got %q", cfg.profile, d.Capability))
			}
		}
	}
	return nil
}
