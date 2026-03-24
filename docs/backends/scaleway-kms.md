# Scaleway Key Manager Backend

## Scope

Enigma provides a production-grade Scaleway backend in three separate layers:

- `keymgmt/scwkm`: key lifecycle (`CreateKey`, `GetKey`, `RotateKey`, `DeleteKey`, `Capabilities`).
- `recipient/scwkm`: runtime DEK wrap/unwrap (`WrapKey`, `UnwrapKey`).
- `resolver/scwkm`: resolve a stored `KeyReference` to a runtime recipient.

This backend uses the official Scaleway Go SDK:

- `github.com/scaleway/scaleway-sdk-go`

## Security Model

- Scaleway Key Manager is used as a root of trust for envelope encryption key custody.
- Enigma still encrypts document/field plaintext locally with AEAD.
- Enigma wraps and unwraps DEKs through Scaleway Key Manager operations.
- Wrapped DEKs are stored by the application in Enigma containers/value blobs.
- DEKs are not stored by Scaleway Key Manager for the application lifecycle.

This backend is classical cloud cryptography:

- `SecurityLevel`: `cloud_classical`
- `SupportsPQNatively`: `false`
- No post-quantum guarantee is provided by this backend.

## Supported Algorithms

Current lifecycle/runtime mapping:

- `aes-256-gcm` -> Scaleway key usage `symmetric_encryption/aes_256_gcm`
- `rsa-oaep-3072-sha256` -> Scaleway key usage `asymmetric_encryption/rsa_oaep_3072_sha256`

Not supported in this backend:

- `ml-kem-768`
- `ml-kem-1024`

Use `localmlkem` backend for local PQ workflows.

## Configuration

Shared config shape:

```go
type Config struct {
    Region    string
    AccessKey string
    SecretKey string
    APIURL    string
    ProjectID string
}
```

Notes:

- `Region` is required for deterministic key reference resolution.
- If `AccessKey`/`SecretKey` are omitted, SDK environment/profile resolution is used.
- `APIURL` is optional (useful for controlled environments/tests).
- `ProjectID` is used for key creation context.

## KeyReference Format

Scaleway references are serialized as generic Enigma `KeyReference` values:

- `Backend`: `scaleway_kms`
- `ID`: Scaleway key ID
- `Version`: key rotation count string
- `URI`: `enigma-scwkm://key/<key-id>?region=<region>&project_id=<project-id>&version=<n>`

`KeyReference` never stores credentials or private key material.

## Usage Pattern

### 1) Create key and persist reference

```go
km, _ := keymgmtscwkm.NewManager(keymgmtscwkm.Config{Region: "fr-par", ProjectID: "<project-id>"})
desc, _ := km.CreateKey(ctx, keymgmt.CreateKeyRequest{
    Name:            "org-a-primary",
    Purpose:         keymgmt.PurposeKeyWrapping,
    Algorithm:       keymgmt.AlgorithmAES256GCM,
    ProtectionLevel: keymgmt.ProtectionKMS,
})

// Store desc.Reference in your application database.
_ = desc.Reference
```

### 2) Resolve recipient at runtime

```go
res, _ := resolverscwkm.New(resolverscwkm.Config{Region: "fr-par", ProjectID: "<project-id>"})
runtimeRecipient, _ := res.ResolveRecipient(ctx, storedRef)
```

### 3) Encrypt/decrypt with existing document/field APIs

```go
_ = document.EncryptFile(ctx, "plain.txt", "plain.txt.enc", document.WithRecipient(runtimeRecipient))
_ = document.DecryptFile(ctx, "plain.txt.enc", "plain.dec.txt", document.WithRecipient(runtimeRecipient))
```

## Rotation vs Rewrap

- `KeyManager.RotateKey` rotates backend key material/provider version.
- `document.Rewrap` updates recipient entries in existing encrypted containers.

These are distinct operations and must be orchestrated explicitly by the application.

## Capability Set

Scaleway backend reports:

- `CanCreateKeys = true`
- `CanDeleteKeys = true`
- `CanRotateProviderNative = true`
- `CanExportPublicKey = true` (backend capability)
- `CanResolveRecipient = true`
- `SupportsPQNatively = false`
- `SupportsClassicalWrapping = true`
- `SupportsRewrapWorkflow = true`

## Current Limitations

- No PQ-native wrapping.
- Only explicitly mapped algorithms are accepted.
- Live cloud integration tests are optional and not required for standard CI runs.
