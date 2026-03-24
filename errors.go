package enigma

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidArgument        = errors.New("enigma: invalid argument")
	ErrInvalidContainer       = errors.New("enigma: invalid container")
	ErrUnsupportedVersion     = errors.New("enigma: unsupported version")
	ErrUnsupportedAlgorithm   = errors.New("enigma: unsupported algorithm")
	ErrNoRecipients           = errors.New("enigma: no recipients configured")
	ErrWrapFailed             = errors.New("enigma: key wrap failed")
	ErrUnwrapFailed           = errors.New("enigma: key unwrap failed")
	ErrDecryptFailed          = errors.New("enigma: decrypt failed")
	ErrIntegrity              = errors.New("enigma: integrity check failed")
	ErrNotImplemented         = errors.New("enigma: not implemented")
	ErrCapabilityMismatch     = errors.New("enigma: capability mismatch")
	ErrRecipientNotFound      = errors.New("enigma: recipient not found")
	ErrUnsupportedCapability  = errors.New("enigma: unsupported capability")
	ErrInvalidKeyReference    = errors.New("enigma: invalid key reference")
	ErrKeyNotFound            = errors.New("enigma: key not found")
	ErrKeyAlgorithmMismatch   = errors.New("enigma: key algorithm mismatch")
	ErrResolveRecipientFailed = errors.New("enigma: recipient resolver failed")
	ErrCreateKeyFailed        = errors.New("enigma: create key failed")
	ErrDeleteKeyFailed        = errors.New("enigma: delete key failed")
	ErrRotateKeyFailed        = errors.New("enigma: rotate key failed")
)

// OpError stores operation context while preserving typed errors via errors.Is/errors.As.
type OpError struct {
	Op   string
	Kind error
	Err  error
}

func (e *OpError) Error() string {
	if e == nil {
		return "<nil>"
	}

	if e.Op == "" {
		if e.Err != nil {
			return e.Err.Error()
		}

		if e.Kind != nil {
			return e.Kind.Error()
		}

		return "enigma: error"
	}

	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}

	if e.Kind != nil {
		return fmt.Sprintf("%s: %v", e.Op, e.Kind)
	}

	return fmt.Sprintf("%s: enigma error", e.Op)
}

func (e *OpError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

func (e *OpError) Is(target error) bool {
	if e == nil {
		return false
	}

	if e.Kind != nil && target == e.Kind {
		return true
	}

	return errors.Is(e.Err, target)
}

func WrapError(op string, kind error, err error) error {
	if err == nil && kind == nil {
		return nil
	}

	return &OpError{Op: op, Kind: kind, Err: err}
}
