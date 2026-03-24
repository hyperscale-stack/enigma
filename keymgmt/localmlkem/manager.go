package localmlkem

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/keymgmt"
	"github.com/hyperscale-stack/enigma/mem"
	recipientlocalmlkem "github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

const (
	BackendName    = "localmlkem"
	schemaVersion  = 1
	defaultVersion = "1"
)

type Manager struct {
	root string
}

type keyRecordV1 struct {
	SchemaVersion int                     `json:"schema_version"`
	ID            string                  `json:"id"`
	Version       string                  `json:"version"`
	Name          string                  `json:"name,omitempty"`
	Purpose       keymgmt.KeyPurpose      `json:"purpose"`
	Algorithm     keymgmt.KeyAlgorithm    `json:"algorithm"`
	Protection    keymgmt.ProtectionLevel `json:"protection_level"`
	Exportable    bool                    `json:"exportable"`
	KeyRef        string                  `json:"key_ref"`
	Seed          []byte                  `json:"seed"`
	PublicKey     []byte                  `json:"public_key"`
	Metadata      map[string]string       `json:"metadata,omitempty"`
	CreatedUnix   int64                   `json:"created_unix"`
}

func NewManager(root string) (*Manager, error) {
	if root == "" {
		return nil, enigma.WrapError("keymgmt/localmlkem.NewManager", enigma.ErrInvalidArgument, fmt.Errorf("empty root path"))
	}
	m := &Manager{root: root}
	if err := os.MkdirAll(m.baseDir(), 0o700); err != nil {
		return nil, enigma.WrapError("keymgmt/localmlkem.NewManager", enigma.ErrInvalidArgument, err)
	}
	return m, nil
}

func (m *Manager) CreateKey(ctx context.Context, req keymgmt.CreateKeyRequest) (*keymgmt.KeyDescriptor, error) {
	_ = ctx
	if req.Purpose == "" {
		return nil, enigma.WrapError("keymgmt/localmlkem.CreateKey", enigma.ErrInvalidArgument, fmt.Errorf("missing key purpose"))
	}
	switch req.Purpose {
	case keymgmt.PurposeKeyEncapsulation, keymgmt.PurposeKeyWrapping, keymgmt.PurposeRecipientDecrypt:
	default:
		return nil, enigma.WrapError("keymgmt/localmlkem.CreateKey", enigma.ErrInvalidArgument, fmt.Errorf("unsupported key purpose %q", req.Purpose))
	}
	if req.Algorithm == "" {
		return nil, enigma.WrapError("keymgmt/localmlkem.CreateKey", enigma.ErrInvalidArgument, fmt.Errorf("missing key algorithm"))
	}
	if req.ProtectionLevel != "" && req.ProtectionLevel != keymgmt.ProtectionSoftware {
		return nil, enigma.WrapError("keymgmt/localmlkem.CreateKey", enigma.ErrUnsupportedCapability, fmt.Errorf("protection level %q is not supported by local backend", req.ProtectionLevel))
	}
	set, err := setForAlgorithm(req.Algorithm)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, enigma.WrapError("keymgmt/localmlkem.CreateKey", enigma.ErrCreateKeyFailed, err)
	}
	keyRef := fmt.Sprintf("%s:%s", BackendName, id)
	recipient, err := recipientlocalmlkem.Generate(set, keyRef)
	if err != nil {
		return nil, enigma.WrapError("keymgmt/localmlkem.CreateKey", enigma.ErrCreateKeyFailed, err)
	}
	record := keyRecordV1{
		SchemaVersion: schemaVersion,
		ID:            id,
		Version:       defaultVersion,
		Name:          req.Name,
		Purpose:       req.Purpose,
		Algorithm:     req.Algorithm,
		Protection:    keymgmt.ProtectionSoftware,
		Exportable:    req.Exportable,
		KeyRef:        keyRef,
		Seed:          recipient.Seed(),
		PublicKey:     recipient.PublicKey(),
		Metadata:      keymgmt.CloneMap(req.Metadata),
		CreatedUnix:   time.Now().Unix(),
	}
	if err := m.writeRecord(record); err != nil {
		return nil, enigma.WrapError("keymgmt/localmlkem.CreateKey", enigma.ErrCreateKeyFailed, err)
	}
	desc := descriptorFromRecord(record)
	mem.Zero(record.Seed)
	return desc, nil
}

func (m *Manager) GetKey(ctx context.Context, ref keymgmt.KeyReference) (*keymgmt.KeyDescriptor, error) {
	_ = ctx
	norm, err := normalizeReference(ref)
	if err != nil {
		return nil, err
	}
	record, err := m.readRecord(norm)
	if err != nil {
		return nil, err
	}
	desc := descriptorFromRecord(record)
	mem.Zero(record.Seed)
	return desc, nil
}

func (m *Manager) RotateKey(ctx context.Context, ref keymgmt.KeyReference, req keymgmt.RotateKeyRequest) (*keymgmt.KeyDescriptor, error) {
	current, err := m.GetKey(ctx, ref)
	if err != nil {
		return nil, enigma.WrapError("keymgmt/localmlkem.RotateKey", enigma.ErrRotateKeyFailed, err)
	}
	createReq := keymgmt.CreateKeyRequest{
		Name:            req.SuccessorName,
		Purpose:         current.Purpose,
		Algorithm:       current.Algorithm,
		ProtectionLevel: keymgmt.ProtectionSoftware,
		Exportable:      false,
		Metadata:        keymgmt.CloneMap(req.Metadata),
	}
	successor, err := m.CreateKey(ctx, createReq)
	if err != nil {
		return nil, enigma.WrapError("keymgmt/localmlkem.RotateKey", enigma.ErrRotateKeyFailed, err)
	}

	norm, err := normalizeReference(ref)
	if err != nil {
		return nil, enigma.WrapError("keymgmt/localmlkem.RotateKey", enigma.ErrRotateKeyFailed, err)
	}
	record, err := m.readRecord(norm)
	if err != nil {
		return nil, enigma.WrapError("keymgmt/localmlkem.RotateKey", enigma.ErrRotateKeyFailed, err)
	}
	if record.Metadata == nil {
		record.Metadata = make(map[string]string)
	}
	record.Metadata["successor_uri"] = successor.Reference.URI
	if err := m.writeRecord(record); err != nil {
		return nil, enigma.WrapError("keymgmt/localmlkem.RotateKey", enigma.ErrRotateKeyFailed, err)
	}
	mem.Zero(record.Seed)
	return successor, nil
}

func (m *Manager) DeleteKey(ctx context.Context, ref keymgmt.KeyReference) error {
	_ = ctx
	norm, err := normalizeReference(ref)
	if err != nil {
		return err
	}
	keyDir := filepath.Join(m.baseDir(), norm.ID)
	if _, err := os.Stat(keyDir); err != nil {
		if os.IsNotExist(err) {
			return enigma.WrapError("keymgmt/localmlkem.DeleteKey", enigma.ErrKeyNotFound, err)
		}
		return enigma.WrapError("keymgmt/localmlkem.DeleteKey", enigma.ErrDeleteKeyFailed, err)
	}
	if err := os.RemoveAll(keyDir); err != nil {
		return enigma.WrapError("keymgmt/localmlkem.DeleteKey", enigma.ErrDeleteKeyFailed, err)
	}
	return nil
}

func (m *Manager) Capabilities(ctx context.Context) keymgmt.CapabilitySet {
	_ = ctx
	return keymgmt.CapabilitySet{
		CanCreateKeys:             true,
		CanDeleteKeys:             true,
		CanRotateProviderNative:   false,
		CanExportPublicKey:        true,
		CanResolveRecipient:       true,
		SupportsPQNatively:        true,
		SupportsClassicalWrapping: false,
		SupportsRewrapWorkflow:    true,
	}
}

func descriptorFromRecord(r keyRecordV1) *keymgmt.KeyDescriptor {
	ref := keymgmt.KeyReference{
		Backend: BackendName,
		URI:     buildURI(r.ID, r.Version),
		ID:      r.ID,
		Version: r.Version,
	}
	return &keymgmt.KeyDescriptor{
		ID:            r.ID,
		Backend:       BackendName,
		Class:         keymgmt.KeyClassAsymmetricKEM,
		Purpose:       r.Purpose,
		Algorithm:     r.Algorithm,
		SecurityLevel: keymgmt.SecurityLevelLocalPQ,
		Reference:     ref,
		PublicInfo: &keymgmt.PublicKeyInfo{
			Algorithm: r.Algorithm,
			Data:      append([]byte(nil), r.PublicKey...),
		},
		Capabilities: capabilitySet(),
		Metadata:     keymgmt.CloneMap(r.Metadata),
	}
}

func capabilitySet() keymgmt.CapabilitySet {
	return keymgmt.CapabilitySet{
		CanCreateKeys:             true,
		CanDeleteKeys:             true,
		CanRotateProviderNative:   false,
		CanExportPublicKey:        true,
		CanResolveRecipient:       true,
		SupportsPQNatively:        true,
		SupportsClassicalWrapping: false,
		SupportsRewrapWorkflow:    true,
	}
}

func (m *Manager) baseDir() string {
	return filepath.Join(m.root, BackendName, fmt.Sprintf("v%d", schemaVersion))
}

func (m *Manager) recordPath(id, version string) string {
	return filepath.Join(m.baseDir(), id, version+".json")
}

func (m *Manager) writeRecord(r keyRecordV1) error {
	path := m.recordPath(r.ID, r.Version)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o600)
}

func (m *Manager) readRecord(ref keymgmt.KeyReference) (keyRecordV1, error) {
	path := m.recordPath(ref.ID, ref.Version)
	blob, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return keyRecordV1{}, enigma.WrapError("keymgmt/localmlkem.readRecord", enigma.ErrKeyNotFound, err)
		}
		return keyRecordV1{}, enigma.WrapError("keymgmt/localmlkem.readRecord", enigma.ErrInvalidArgument, err)
	}
	var record keyRecordV1
	if err := json.Unmarshal(blob, &record); err != nil {
		return keyRecordV1{}, enigma.WrapError("keymgmt/localmlkem.readRecord", enigma.ErrInvalidContainer, err)
	}
	if record.SchemaVersion != schemaVersion {
		return keyRecordV1{}, enigma.WrapError("keymgmt/localmlkem.readRecord", enigma.ErrUnsupportedVersion, fmt.Errorf("schema version %d", record.SchemaVersion))
	}
	if record.ID == "" || record.Version == "" {
		return keyRecordV1{}, enigma.WrapError("keymgmt/localmlkem.readRecord", enigma.ErrInvalidContainer, fmt.Errorf("malformed key record"))
	}
	return record, nil
}

func normalizeReference(ref keymgmt.KeyReference) (keymgmt.KeyReference, error) {
	if ref.Backend == "" {
		return keymgmt.KeyReference{}, enigma.WrapError("keymgmt/localmlkem.normalizeReference", enigma.ErrInvalidKeyReference, fmt.Errorf("missing backend"))
	}
	if ref.Backend != BackendName {
		return keymgmt.KeyReference{}, enigma.WrapError("keymgmt/localmlkem.normalizeReference", enigma.ErrInvalidKeyReference, fmt.Errorf("backend %q", ref.Backend))
	}
	if ref.ID == "" {
		return keymgmt.KeyReference{}, enigma.WrapError("keymgmt/localmlkem.normalizeReference", enigma.ErrInvalidKeyReference, fmt.Errorf("missing key id"))
	}
	if ref.Version == "" {
		ref.Version = defaultVersion
	}
	if ref.URI == "" {
		ref.URI = buildURI(ref.ID, ref.Version)
	}
	return ref, nil
}

func buildURI(id, version string) string {
	return fmt.Sprintf("enigma-localmlkem://v%d/%s/%s", schemaVersion, id, version)
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func setForAlgorithm(alg keymgmt.KeyAlgorithm) (recipientlocalmlkem.ParameterSet, error) {
	switch alg {
	case keymgmt.AlgorithmMLKEM768:
		return recipientlocalmlkem.MLKEM768, nil
	case keymgmt.AlgorithmMLKEM1024:
		return recipientlocalmlkem.MLKEM1024, nil
	case keymgmt.AlgorithmAES256GCM, keymgmt.AlgorithmRSAOAEP3072SHA256:
		return "", enigma.WrapError("keymgmt/localmlkem.setForAlgorithm", enigma.ErrKeyAlgorithmMismatch, fmt.Errorf("algorithm %q is not supported by local ML-KEM backend", alg))
	default:
		return "", enigma.WrapError("keymgmt/localmlkem.setForAlgorithm", enigma.ErrUnsupportedAlgorithm, fmt.Errorf("algorithm %q", alg))
	}
}
