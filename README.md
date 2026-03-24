# Enigma

Enigma is a pure Go library for high-level document and field encryption using modern cryptographic primitives and explicit recipient-based key wrapping.

## Status

`v1` foundation implemented:
- Hybrid encryption with one random DEK per object.
- Chunked authenticated encryption for documents/blobs.
- Versioned binary container format with authenticated header sections.
- Multi-recipient DEK wrapping and decrypt-by-any-recipient semantics.
- Rewrap support without content re-encryption when a valid recipient can unwrap the DEK.
- Separate compact field/value encryption API.
- Local post-quantum recipient implementation using `crypto/mlkem` (ML-KEM-768 default, ML-KEM-1024 optional).
- Scaleway Key Manager backend for key lifecycle, recipient resolution, and runtime DEK wrap/unwrap using the official Scaleway SDK.
- GCP/AWS/Azure provider packages present as explicit capability-aware stubs (no fake crypto behavior).

## Installation

```bash
go get github.com/hyperscale-stack/enigma
```

## Packages

- `document`: file/stream/blob encryption with chunked framing.
- `field`: compact value encryption for DB/application fields.
- `container`: strict parser/serializer for the binary envelope format.
- `recipient`: recipient abstractions and capability model.
- `recipient/localmlkem`: fully implemented local PQ recipient.
- `recipient/scwkm`: Scaleway Key Manager runtime recipient (classical cloud wrapping).
- `recipient/{gcpkms,awskms,azurekv}`: explicit cloud stubs for v1.
- `keymgmt`: key lifecycle interfaces and domain types.
- `keymgmt/localmlkem`: local ML-KEM key manager with filesystem-backed metadata persistence.
- `keymgmt/scwkm`: Scaleway Key Manager lifecycle backend.
- `resolver`: recipient resolver interfaces and backend registry.
- `resolver/localmlkem`: resolves local key references into runtime recipients.
- `resolver/scwkm`: resolves Scaleway key references into runtime recipients.
- `mem`: best-effort memory hygiene helpers.

## Quick Start

### Document encryption/decryption

```go
package main

import (
    "context"

    "github.com/hyperscale-stack/enigma/document"
    "github.com/hyperscale-stack/enigma/recipient/localmlkem"
)

func main() {
    r, _ := localmlkem.Generate(localmlkem.MLKEM768, "local-key-1")

    _ = document.EncryptFile(context.Background(), "plain.txt", "plain.txt.enc",
        document.WithRecipient(r),
        document.WithDefaultProfile("local-pq"),
    )

    _ = document.DecryptFile(context.Background(), "plain.txt.enc", "plain.dec.txt",
        document.WithRecipient(r),
    )
}
```

### Rewrap without content re-encryption

```go
_ = document.Rewrap(context.Background(), "plain.txt.enc", "plain.rewrapped.enc",
    document.WithRecipient(oldRecipient),      // unwrap existing DEK
    document.WithNewRecipient(newRecipient),   // add/replace recipients
    document.WithReplaceRecipients(),
)
```

### Field encryption

```go
ciphertext, _ := field.EncryptValue(context.Background(), []byte("sensitive-value"),
    field.WithRecipient(r),
)
plaintext, _ := field.DecryptValue(context.Background(), ciphertext,
    field.WithRecipient(r),
)
```

### Key lifecycle and recipient resolution

```go
km, _ := keymgmtlocalmlkem.NewManager("/var/lib/enigma-keys")
desc, _ := km.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
    Name:            "tenant-a-primary",
    Purpose:         keymgmt.PurposeRecipientDecrypt,
    Algorithm:       keymgmt.AlgorithmMLKEM768,
    ProtectionLevel: keymgmt.ProtectionSoftware,
})

res, _ := resolverlocalmlkem.New("/var/lib/enigma-keys")
runtimeRecipient, _ := res.ResolveRecipient(context.Background(), desc.Reference)

_ = document.EncryptFile(context.Background(), "plain.txt", "plain.txt.enc",
    document.WithRecipient(runtimeRecipient),
)
```

### Scaleway KMS (classical cloud backend)

```go
km, _ := keymgmtscwkm.NewManager(keymgmtscwkm.Config{
    Region:    "fr-par",
    ProjectID: "<project-id>",
})

desc, _ := km.CreateKey(context.Background(), keymgmt.CreateKeyRequest{
    Name:            "org-primary",
    Purpose:         keymgmt.PurposeKeyWrapping,
    Algorithm:       keymgmt.AlgorithmAES256GCM,
    ProtectionLevel: keymgmt.ProtectionKMS,
})

res, _ := resolverscwkm.New(resolverscwkm.Config{
    Region:    "fr-par",
    ProjectID: "<project-id>",
})
runtimeRecipient, _ := res.ResolveRecipient(context.Background(), desc.Reference)
_ = document.EncryptFile(context.Background(), "plain.txt", "plain.txt.enc", document.WithRecipient(runtimeRecipient))
```

## Security Properties (Implemented)

- Confidentiality and authenticity of encrypted content when recipients and primitives are used correctly.
- Header integrity verification via DEK-derived header authentication.
- Per-chunk authenticated encryption with deterministic nonce derivation from envelope context and chunk index.
- Multi-recipient wrapping: any valid recipient can unwrap DEK and decrypt content.
- Rewrap updates recipient section and header authentication tag while preserving encrypted chunk stream bytes.

## Important Limitations

- Go memory is not fully controllable; key wiping is best-effort only.
- Scaleway backend is classical cloud wrapping only and does not provide PQ-native guarantees.
- GCP/AWS/Azure backend packages are still stubs and return `ErrNotImplemented` for wrapping/unwrapping.
- Key lifecycle mapping (for example one key per tenant or organization) is application-owned.
- Recipient metadata (type/key references/capability labels) is inspectable by design and not encrypted.
- No signatures in v1 (footer/signature area is an extension point only).
- No deterministic/searchable field encryption in v1.
- No identity platform, policy engine, or remote API service.

## Lifecycle versus Runtime

- `KeyManager` provisions, inspects, rotates, and deletes keys.
- `Recipient` only wraps and unwraps DEKs at runtime.
- `RecipientResolver` resolves a stored `KeyReference` back to a runtime `Recipient`.
- Key rotation and document rewrap are distinct operations. Rotation creates successor keys; rewrap updates recipient entries in existing encrypted containers.

## Capability Model

- `local-pq`: local ML-KEM recipient.
- `cloud-classical`: cloud-backed classical wrapping path.
- `cloud-pq-native`: cloud-backed native PQ path.

The active capability is explicit in recipient descriptors and metadata.

For Scaleway-specific details, see [`docs/backends/scaleway-kms.md`](docs/backends/scaleway-kms.md).

## Development

```bash
go test ./...
```

See:
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/key-management.md`](docs/key-management.md)
- [`docs/container-format.md`](docs/container-format.md)
- [`docs/threat-model.md`](docs/threat-model.md)
- [`SECURITY.md`](SECURITY.md)
- [`docs/roadmap.md`](docs/roadmap.md)
