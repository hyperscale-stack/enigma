package aeadsuite

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/hyperscale-stack/enigma"
	"golang.org/x/crypto/chacha20poly1305"
)

func KeySize(suite enigma.AEADSuite) (int, error) {
	switch suite {
	case enigma.SuiteXChaCha20Poly1305, enigma.SuiteAES256GCM:
		return 32, nil
	default:
		return 0, enigma.WrapError("aeadsuite.KeySize", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("suite %v", suite))
	}
}

func NonceSize(suite enigma.AEADSuite) (int, error) {
	switch suite {
	case enigma.SuiteXChaCha20Poly1305:
		return chacha20poly1305.NonceSizeX, nil
	case enigma.SuiteAES256GCM:
		return 12, nil
	default:
		return 0, enigma.WrapError("aeadsuite.NonceSize", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("suite %v", suite))
	}
}

func New(suite enigma.AEADSuite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case enigma.SuiteXChaCha20Poly1305:
		if len(key) != 32 {
			return nil, enigma.WrapError("aeadsuite.New", enigma.ErrInvalidArgument, fmt.Errorf("invalid key length %d", len(key)))
		}
		return chacha20poly1305.NewX(key)
	case enigma.SuiteAES256GCM:
		if len(key) != 32 {
			return nil, enigma.WrapError("aeadsuite.New", enigma.ErrInvalidArgument, fmt.Errorf("invalid key length %d", len(key)))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, enigma.WrapError("aeadsuite.New", enigma.ErrInvalidArgument, err)
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			return nil, enigma.WrapError("aeadsuite.New", enigma.ErrInvalidArgument, err)
		}
		return a, nil
	default:
		return nil, enigma.WrapError("aeadsuite.New", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("suite %v", suite))
	}
}
