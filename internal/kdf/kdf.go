package kdf

import (
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/hyperscale-stack/enigma"
)

type Material struct {
	ContentKey    []byte
	HeaderAuthKey []byte
	NonceSalt     []byte
	Reserved      []byte
}

func Derive(dek, nonceContext []byte, suite enigma.AEADSuite) (*Material, error) {
	keyLen := 32
	total := keyLen * 4
	okm, err := hkdf.Key(sha256.New, dek, nonceContext, "enigma/v1/"+suite.String(), total)
	if err != nil {
		return nil, enigma.WrapError("kdf.Derive", enigma.ErrInvalidArgument, err)
	}
	m := &Material{
		ContentKey:    append([]byte(nil), okm[0:keyLen]...),
		HeaderAuthKey: append([]byte(nil), okm[keyLen:2*keyLen]...),
		NonceSalt:     append([]byte(nil), okm[2*keyLen:3*keyLen]...),
		Reserved:      append([]byte(nil), okm[3*keyLen:4*keyLen]...),
	}
	return m, nil
}
