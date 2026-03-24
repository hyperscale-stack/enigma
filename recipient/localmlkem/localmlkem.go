package localmlkem

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/mem"
	"github.com/hyperscale-stack/enigma/recipient"
)

type ParameterSet string

const (
	MLKEM768  ParameterSet = "ml-kem-768"
	MLKEM1024 ParameterSet = "ml-kem-1024"
)

const (
	WrapAlgorithmMLKEM768AESGCM  = "mlkem-768+aes256gcm"
	WrapAlgorithmMLKEM1024AESGCM = "mlkem-1024+aes256gcm"
)

type Recipient struct {
	set    ParameterSet
	keyRef string

	ek768 *mlkem.EncapsulationKey768
	dk768 *mlkem.DecapsulationKey768

	ek1024 *mlkem.EncapsulationKey1024
	dk1024 *mlkem.DecapsulationKey1024
}

func Generate(set ParameterSet, keyRef string) (*Recipient, error) {
	switch set {
	case MLKEM768:
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, enigma.WrapError("localmlkem.Generate", enigma.ErrInvalidArgument, err)
		}

		return &Recipient{set: set, keyRef: keyRef, dk768: dk, ek768: dk.EncapsulationKey()}, nil
	case MLKEM1024:
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, enigma.WrapError("localmlkem.Generate", enigma.ErrInvalidArgument, err)
		}

		return &Recipient{set: set, keyRef: keyRef, dk1024: dk, ek1024: dk.EncapsulationKey()}, nil
	default:
		return nil, enigma.WrapError("localmlkem.Generate", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unknown set %q", set))
	}
}

func NewFromSeed(set ParameterSet, seed []byte, keyRef string) (*Recipient, error) {
	if len(seed) != mlkem.SeedSize {
		return nil, enigma.WrapError("localmlkem.NewFromSeed", enigma.ErrInvalidArgument, fmt.Errorf("seed must be %d bytes", mlkem.SeedSize))
	}

	switch set {
	case MLKEM768:
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, enigma.WrapError("localmlkem.NewFromSeed", enigma.ErrInvalidArgument, err)
		}

		return &Recipient{set: set, keyRef: keyRef, dk768: dk, ek768: dk.EncapsulationKey()}, nil
	case MLKEM1024:
		dk, err := mlkem.NewDecapsulationKey1024(seed)
		if err != nil {
			return nil, enigma.WrapError("localmlkem.NewFromSeed", enigma.ErrInvalidArgument, err)
		}

		return &Recipient{set: set, keyRef: keyRef, dk1024: dk, ek1024: dk.EncapsulationKey()}, nil
	default:
		return nil, enigma.WrapError("localmlkem.NewFromSeed", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unknown set %q", set))
	}
}

func NewFromPublicKey(set ParameterSet, publicKey []byte, keyRef string) (*Recipient, error) {
	switch set {
	case MLKEM768:
		ek, err := mlkem.NewEncapsulationKey768(publicKey)
		if err != nil {
			return nil, enigma.WrapError("localmlkem.NewFromPublicKey", enigma.ErrInvalidArgument, err)
		}

		return &Recipient{set: set, keyRef: keyRef, ek768: ek}, nil
	case MLKEM1024:
		ek, err := mlkem.NewEncapsulationKey1024(publicKey)
		if err != nil {
			return nil, enigma.WrapError("localmlkem.NewFromPublicKey", enigma.ErrInvalidArgument, err)
		}

		return &Recipient{set: set, keyRef: keyRef, ek1024: ek}, nil
	default:
		return nil, enigma.WrapError("localmlkem.NewFromPublicKey", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unknown set %q", set))
	}
}

func (r *Recipient) Seed() []byte {
	if r == nil {
		return nil
	}

	switch r.set {
	case MLKEM768:
		if r.dk768 == nil {
			return nil
		}

		return r.dk768.Bytes()
	case MLKEM1024:
		if r.dk1024 == nil {
			return nil
		}

		return r.dk1024.Bytes()
	default:
		return nil
	}
}

func (r *Recipient) PublicKey() []byte {
	if r == nil {
		return nil
	}

	switch r.set {
	case MLKEM768:
		if r.ek768 == nil {
			return nil
		}

		return r.ek768.Bytes()
	case MLKEM1024:
		if r.ek1024 == nil {
			return nil
		}

		return r.ek1024.Bytes()
	default:
		return nil
	}
}

func (r *Recipient) Descriptor() recipient.Descriptor {
	return recipient.Descriptor{
		Type:             recipient.TypeLocalMLKEM,
		Capability:       recipient.CapabilityLocalPQ,
		KeyRef:           r.keyRef,
		RewrapCompatible: true,
		Metadata: map[string]string{
			"parameter_set": string(r.set),
		},
	}
}

func (r *Recipient) WrapKey(ctx context.Context, dek []byte) (*recipient.WrappedKey, error) {
	_ = ctx

	if len(dek) == 0 {
		return nil, enigma.WrapError("localmlkem.WrapKey", enigma.ErrInvalidArgument, fmt.Errorf("empty dek"))
	}

	var (
		sharedSecret  []byte
		kemCiphertext []byte
		wrapAlg       string
	)

	switch r.set {
	case MLKEM768:
		if r.ek768 == nil {
			return nil, enigma.WrapError("localmlkem.WrapKey", enigma.ErrWrapFailed, fmt.Errorf("missing encapsulation key"))
		}

		sharedSecret, kemCiphertext = r.ek768.Encapsulate()
		wrapAlg = WrapAlgorithmMLKEM768AESGCM
	case MLKEM1024:
		if r.ek1024 == nil {
			return nil, enigma.WrapError("localmlkem.WrapKey", enigma.ErrWrapFailed, fmt.Errorf("missing encapsulation key"))
		}

		sharedSecret, kemCiphertext = r.ek1024.Encapsulate()
		wrapAlg = WrapAlgorithmMLKEM1024AESGCM
	default:
		return nil, enigma.WrapError("localmlkem.WrapKey", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("unknown set %q", r.set))
	}
	defer mem.Zero(sharedSecret)

	kek, err := deriveKEK(sharedSecret, r.set)
	if err != nil {
		return nil, enigma.WrapError("localmlkem.WrapKey", enigma.ErrWrapFailed, err)
	}
	defer mem.Zero(kek)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, enigma.WrapError("localmlkem.WrapKey", enigma.ErrWrapFailed, err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, enigma.WrapError("localmlkem.WrapKey", enigma.ErrWrapFailed, err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, enigma.WrapError("localmlkem.WrapKey", enigma.ErrWrapFailed, err)
	}

	aad := []byte(fmt.Sprintf("enigma/wrap/%s/%s", r.set, r.keyRef))
	ct := aead.Seal(nil, nonce, dek, aad)

	return &recipient.WrappedKey{
		RecipientType:   recipient.TypeLocalMLKEM,
		Capability:      recipient.CapabilityLocalPQ,
		WrapAlgorithm:   wrapAlg,
		KeyRef:          r.keyRef,
		EncapsulatedKey: kemCiphertext,
		Nonce:           nonce,
		Ciphertext:      ct,
		Metadata: map[string]string{
			"parameter_set": string(r.set),
		},
	}, nil
}

func (r *Recipient) UnwrapKey(ctx context.Context, wk *recipient.WrappedKey) ([]byte, error) {
	_ = ctx
	if wk == nil {
		return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrInvalidArgument, fmt.Errorf("nil wrapped key"))
	}

	if wk.RecipientType != recipient.TypeLocalMLKEM {
		return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrRecipientNotFound, fmt.Errorf("recipient type %q", wk.RecipientType))
	}

	if r.keyRef != "" && wk.KeyRef != "" && r.keyRef != wk.KeyRef {
		return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrRecipientNotFound, fmt.Errorf("key ref mismatch"))
	}

	var (
		sharedSecret []byte
		err          error
	)

	switch wk.WrapAlgorithm {
	case WrapAlgorithmMLKEM768AESGCM:
		if r.dk768 == nil {
			return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrUnwrapFailed, fmt.Errorf("missing decapsulation key"))
		}
		sharedSecret, err = r.dk768.Decapsulate(wk.EncapsulatedKey)
	case WrapAlgorithmMLKEM1024AESGCM:
		if r.dk1024 == nil {
			return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrUnwrapFailed, fmt.Errorf("missing decapsulation key"))
		}
		sharedSecret, err = r.dk1024.Decapsulate(wk.EncapsulatedKey)
	default:
		return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("wrap algorithm %q", wk.WrapAlgorithm))
	}

	if err != nil {
		return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrUnwrapFailed, err)
	}
	defer mem.Zero(sharedSecret)

	kek, err := deriveKEK(sharedSecret, setForWrapAlgorithm(wk.WrapAlgorithm))
	if err != nil {
		return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrUnwrapFailed, err)
	}
	defer mem.Zero(kek)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrUnwrapFailed, err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrUnwrapFailed, err)
	}

	aad := []byte(fmt.Sprintf("enigma/wrap/%s/%s", setForWrapAlgorithm(wk.WrapAlgorithm), wk.KeyRef))

	dek, err := aead.Open(nil, wk.Nonce, wk.Ciphertext, aad)
	if err != nil {
		return nil, enigma.WrapError("localmlkem.UnwrapKey", enigma.ErrUnwrapFailed, err)
	}

	return dek, nil
}

func deriveKEK(sharedSecret []byte, set ParameterSet) ([]byte, error) {
	kek, err := hkdf.Key(sha256.New, sharedSecret, nil, "enigma/localmlkem/kek/"+string(set), 32)
	if err != nil {
		return nil, enigma.WrapError("localmlkem.deriveKEK", enigma.ErrInvalidArgument, err)
	}

	return kek, nil
}

func setForWrapAlgorithm(wrapAlg string) ParameterSet {
	switch wrapAlg {
	case WrapAlgorithmMLKEM1024AESGCM:
		return MLKEM1024
	default:
		return MLKEM768
	}
}
