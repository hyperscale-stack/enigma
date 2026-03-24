package enigma

import "fmt"

type AEADSuite uint16

const (
	SuiteXChaCha20Poly1305 AEADSuite = 0x0001
	SuiteAES256GCM         AEADSuite = 0x0002
)

func (s AEADSuite) String() string {
	switch s {
	case SuiteXChaCha20Poly1305:
		return "xchacha20-poly1305"
	case SuiteAES256GCM:
		return "aes-256-gcm"
	default:
		return fmt.Sprintf("unknown-suite(%d)", s)
	}
}

func ParseAEADSuite(v uint16) (AEADSuite, error) {
	s := AEADSuite(v)
	switch s {
	case SuiteXChaCha20Poly1305, SuiteAES256GCM:
		return s, nil
	default:
		return 0, WrapError("enigma.ParseAEADSuite", ErrUnsupportedAlgorithm, fmt.Errorf("suite id %d", v))
	}
}

type Profile string

const (
	ProfileLocalPQ       Profile = "local-pq"
	ProfileCloudBalanced Profile = "cloud-balanced"
	ProfileCompliance    Profile = "compliance"
)

const (
	ContainerMagic   = "ENGM"
	ContainerVersion = 1
)
