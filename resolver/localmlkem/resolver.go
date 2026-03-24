package localmlkem

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/keymgmt"
	keymgmtlocal "github.com/hyperscale-stack/enigma/keymgmt/localmlkem"
	"github.com/hyperscale-stack/enigma/mem"
	"github.com/hyperscale-stack/enigma/recipient"
	recipientlocalmlkem "github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

type Resolver struct {
	root string
}

type keyRecordV1 struct {
	SchemaVersion int                  `json:"schema_version"`
	ID            string               `json:"id"`
	Version       string               `json:"version"`
	Algorithm     keymgmt.KeyAlgorithm `json:"algorithm"`
	KeyRef        string               `json:"key_ref"`
	Seed          []byte               `json:"seed"`
}

func New(root string) (*Resolver, error) {
	if root == "" {
		return nil, enigma.WrapError("resolver/localmlkem.New", enigma.ErrInvalidArgument, fmt.Errorf("empty root path"))
	}
	return &Resolver{root: root}, nil
}

func (r *Resolver) ResolveRecipient(ctx context.Context, ref keymgmt.KeyReference) (recipient.Recipient, error) {
	_ = ctx
	norm, err := normalizeReference(ref)
	if err != nil {
		return nil, err
	}
	record, err := r.readRecord(norm)
	if err != nil {
		return nil, err
	}
	defer mem.Zero(record.Seed)
	set, err := setForAlgorithm(record.Algorithm)
	if err != nil {
		return nil, err
	}
	rcp, err := recipientlocalmlkem.NewFromSeed(set, record.Seed, record.KeyRef)
	if err != nil {
		return nil, enigma.WrapError("resolver/localmlkem.ResolveRecipient", enigma.ErrResolveRecipientFailed, err)
	}
	return rcp, nil
}

func (r *Resolver) baseDir() string {
	return filepath.Join(r.root, keymgmtlocal.BackendName, "v1")
}

func (r *Resolver) recordPath(id, version string) string {
	return filepath.Join(r.baseDir(), id, version+".json")
}

func (r *Resolver) readRecord(ref keymgmt.KeyReference) (keyRecordV1, error) {
	path := r.recordPath(ref.ID, ref.Version)
	blob, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return keyRecordV1{}, enigma.WrapError("resolver/localmlkem.readRecord", enigma.ErrKeyNotFound, err)
		}
		return keyRecordV1{}, enigma.WrapError("resolver/localmlkem.readRecord", enigma.ErrResolveRecipientFailed, err)
	}
	var record keyRecordV1
	if err := json.Unmarshal(blob, &record); err != nil {
		return keyRecordV1{}, enigma.WrapError("resolver/localmlkem.readRecord", enigma.ErrInvalidContainer, err)
	}
	if record.SchemaVersion != 1 {
		return keyRecordV1{}, enigma.WrapError("resolver/localmlkem.readRecord", enigma.ErrUnsupportedVersion, fmt.Errorf("schema version %d", record.SchemaVersion))
	}
	if len(record.Seed) == 0 {
		return keyRecordV1{}, enigma.WrapError("resolver/localmlkem.readRecord", enigma.ErrInvalidContainer, fmt.Errorf("missing seed"))
	}
	if record.KeyRef == "" {
		record.KeyRef = fmt.Sprintf("%s:%s", keymgmtlocal.BackendName, ref.ID)
	}
	return record, nil
}

func normalizeReference(ref keymgmt.KeyReference) (keymgmt.KeyReference, error) {
	if ref.Backend == "" {
		return keymgmt.KeyReference{}, enigma.WrapError("resolver/localmlkem.normalizeReference", enigma.ErrInvalidKeyReference, fmt.Errorf("missing backend"))
	}
	if ref.Backend != keymgmtlocal.BackendName {
		return keymgmt.KeyReference{}, enigma.WrapError("resolver/localmlkem.normalizeReference", enigma.ErrInvalidKeyReference, fmt.Errorf("backend %q", ref.Backend))
	}
	if ref.ID == "" {
		return keymgmt.KeyReference{}, enigma.WrapError("resolver/localmlkem.normalizeReference", enigma.ErrInvalidKeyReference, fmt.Errorf("missing key id"))
	}
	if ref.Version == "" {
		ref.Version = "1"
	}
	return ref, nil
}

func setForAlgorithm(alg keymgmt.KeyAlgorithm) (recipientlocalmlkem.ParameterSet, error) {
	switch alg {
	case keymgmt.AlgorithmMLKEM768:
		return recipientlocalmlkem.MLKEM768, nil
	case keymgmt.AlgorithmMLKEM1024:
		return recipientlocalmlkem.MLKEM1024, nil
	case keymgmt.AlgorithmRSAOAEP3072SHA256, keymgmt.AlgorithmAES256GCM:
		return "", enigma.WrapError("resolver/localmlkem.setForAlgorithm", enigma.ErrKeyAlgorithmMismatch, fmt.Errorf("algorithm %q cannot be resolved as local ML-KEM recipient", alg))
	default:
		return "", enigma.WrapError("resolver/localmlkem.setForAlgorithm", enigma.ErrKeyAlgorithmMismatch, fmt.Errorf("algorithm %q cannot be resolved as local ML-KEM recipient", alg))
	}
}
