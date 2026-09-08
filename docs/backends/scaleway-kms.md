# Scaleway Key Manager Backend

## Scope

Enigma provides a production-grade Scaleway backend in three separate layers:

- `keymgmt/scwkm`: key lifecycle (`CreateKey`, `GetKey`, `RotateKey`, `DeleteKey`, `Capabilities`).
- `recipient/scwkm`: runtime DEK wrap/unwrap (`WrapKey`, `UnwrapKey`).
- `resolver/scwkm`: resolve a stored `KeyReference` to a runtime recipient.

This backend uses the official Scaleway Go SDK:

- `github.com/scaleway/scaleway-sdk-go`

ML-KEM support (`usage.key_encapsulation` plus the `WrapKey`/`UnwrapKey` endpoints) landed on
the SDK main branch after `v1.0.0-beta.37` was tagged, so `go.mod` currently pins a
pseudo-version of that branch. Switch back to a released tag once `v1.0.0-beta.38` ships.

## Security Model

- Scaleway Key Manager is used as a root of trust for envelope encryption key custody.
- Enigma still encrypts document/field plaintext locally with AEAD.
- Enigma wraps and unwraps DEKs through Scaleway Key Manager operations.
- Wrapped DEKs are stored by the application in Enigma containers/value blobs.
- DEKs are not stored by Scaleway Key Manager for the application lifecycle.

The delivered guarantee depends on the key algorithm, and is reported per key rather than
assumed for the whole backend:

- ML-KEM keys: `SecurityLevel` = `cloud_pq_native`, recipient capability `cloud-pq-native`.
- AES/RSA keys: `SecurityLevel` = `cloud_classical`, recipient capability `cloud-classical`.

Post-quantum wrapping is performed by Scaleway Key Manager itself. Enigma never sees the
ML-KEM private key material.

## Supported Algorithms

Current lifecycle/runtime mapping:

| Enigma algorithm | Scaleway key usage | Runtime endpoints | Security level |
|---|---|---|---|
| `ml-kem-1024` (**default**) | `key_encapsulation/ml_kem_1024` | `WrapKey` / `UnwrapKey` | `cloud_pq_native` |
| `ml-kem-768` | `key_encapsulation/ml_kem_768` | `WrapKey` / `UnwrapKey` | `cloud_pq_native` |
| `aes-256-gcm` | `symmetric_encryption/aes_256_gcm` | `Encrypt` / `Decrypt` | `cloud_classical` |
| `rsa-oaep-3072-sha256` | `asymmetric_encryption/rsa_oaep_3072_sha256` | `Encrypt` / `Decrypt` | `cloud_classical` |

`CreateKey` defaults to `ml-kem-1024` when `CreateKeyRequest.Algorithm` is empty
(`scwkm.DefaultAlgorithm`). Any other algorithm is rejected with `ErrUnsupportedAlgorithm`.

`PurposeKeyEncapsulation` is accepted only for ML-KEM algorithms; combining it with a
classical algorithm returns `ErrUnsupportedCapability`.

Scaleway caps the wrap endpoint at 2 KB of plaintext and the unwrap endpoint at 4 KB of
ciphertext. Enigma DEKs are 32 bytes, so these limits are never reached in practice.

Use the `localmlkem` backend when the PQ private key must stay local instead of in the KMS.

## Wrap Algorithm Identifiers

The identifier stored in each container recipient entry selects the unwrap path, which keeps
existing containers readable after this backend gained ML-KEM support:

- `scwkm+encrypt-v1` -> classical `Encrypt`/`Decrypt`
- `scwkm+mlkem-768-wrap-v1` -> native `WrapKey`/`UnwrapKey`
- `scwkm+mlkem-1024-wrap-v1` -> native `WrapKey`/`UnwrapKey`

## Profile Interaction

The `local-pq` profile (the default in `document` and `field`) requires `local-pq` recipients
and rejects `cloud-pq-native` ones: the profile asserts that the private key never leaves the
host, which a KMS-held ML-KEM key does not satisfy.

Use `WithDefaultProfile(enigma.ProfileCloudBalanced)` with Scaleway ML-KEM recipients.

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
- `URI`: `enigma-scwkm://key/<key-id>?alg=<algorithm>&region=<region>&project_id=<project-id>&version=<n>`

The `alg` parameter lets a resolved recipient pick the wrapping path without an extra
Key Manager round trip. References produced before this parameter existed stay valid and
resolve to the classical path. Persist the `KeyReference` returned by the manager rather than
rebuilding it by hand, so the algorithm stays attached to the key.

`KeyReference` never stores credentials or private key material.

## Usage Pattern

### 1) Create key and persist reference

```go
km, _ := keymgmtscwkm.NewManager(keymgmtscwkm.Config{Region: "fr-par", ProjectID: "<project-id>"})
desc, _ := km.CreateKey(ctx, keymgmt.CreateKeyRequest{
    Name:            "org-a-primary",
    Purpose:         keymgmt.PurposeKeyWrapping,
    ProtectionLevel: keymgmt.ProtectionKMS,
    // Algorithm omitted: defaults to keymgmt.AlgorithmMLKEM1024.
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
_ = document.EncryptFile(ctx, "plain.txt", "plain.txt.enc",
    document.WithRecipient(runtimeRecipient),
    document.WithDefaultProfile(enigma.ProfileCloudBalanced),
)
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
- `SupportsPQNatively = true`
- `SupportsClassicalWrapping = true`
- `SupportsRewrapWorkflow = true`

## Current Limitations

- PQ-native wrapping relies on Scaleway holding the ML-KEM private key; use `localmlkem` when
  the key must stay on the host.
- Only explicitly mapped algorithms are accepted.
- ML-KEM support requires an SDK build newer than `v1.0.0-beta.37`.
- Live cloud integration tests are optional and not required for standard CI runs.
