package field

import (
	"fmt"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient"
)

type Option func(*config) error

type config struct {
	recipients []recipient.Recipient
	profile    enigma.Profile
	suite      *enigma.AEADSuite
	metadata   map[string]string
}

func defaultConfig() *config {
	return &config{profile: enigma.ProfileLocalPQ}
}

func WithRecipient(r recipient.Recipient) Option {
	return func(c *config) error {
		if r == nil {
			return enigma.WrapError("field.WithRecipient", enigma.ErrInvalidArgument, fmt.Errorf("recipient is nil"))
		}
		c.recipients = append(c.recipients, r)
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
			return enigma.WrapError("field.WithDefaultProfile", enigma.ErrInvalidArgument, fmt.Errorf("unknown profile %q", p))
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

func WithMetadata(metadata map[string]string) Option {
	return func(c *config) error {
		if len(metadata) == 0 {
			c.metadata = nil
			return nil
		}
		out := make(map[string]string, len(metadata))
		for k, v := range metadata {
			out[k] = v
		}
		c.metadata = out
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
	if c.profile == enigma.ProfileCompliance {
		return enigma.SuiteAES256GCM
	}
	return enigma.SuiteXChaCha20Poly1305
}

func validateEncryptConfig(cfg *config) error {
	if len(cfg.recipients) == 0 {
		return enigma.WrapError("field.validateEncryptConfig", enigma.ErrNoRecipients, nil)
	}
	if cfg.profile == enigma.ProfileLocalPQ {
		for _, r := range cfg.recipients {
			if r.Descriptor().Capability != recipient.CapabilityLocalPQ {
				return enigma.WrapError("field.validateEncryptConfig", enigma.ErrCapabilityMismatch, fmt.Errorf("profile %q requires local-pq recipients", cfg.profile))
			}
		}
	}
	return nil
}
