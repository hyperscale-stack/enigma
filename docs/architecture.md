# Architecture

## Overview

Enigma is structured into five layers:

1. Key lifecycle and resolution layer
- `keymgmt`: key lifecycle interfaces and domain types.
- `keymgmt/localmlkem`: local ML-KEM key manager implementation.
- `resolver`: recipient resolution interfaces and registry.
- `resolver/localmlkem`: resolves stored local key references into runtime recipients.
- Separates key provisioning from runtime wrapping semantics.

2. Recipient / key wrapping layer
- Defines recipient interface.
- Wraps and unwraps a random DEK.
- Supports local PQ recipient (ML-KEM) and cloud-provider stubs with explicit capabilities.

3. Symmetric encryption layer
- Uses one DEK per encrypted object.
- Derives separated subkeys with HKDF-SHA256.
- Encrypts content using AEAD suites:
  - default: XChaCha20-Poly1305
  - optional: AES-256-GCM
- Uses chunked authenticated framing for document/blob workloads.

4. Container format layer
- Implements strict binary envelope parser/serializer.
- Header split:
  - immutable section (content-bound)
  - recipient section (rewrap-mutable)
- Header authentication tag is derived from DEK material.

5. High-level API layer
- `document` package:
  - `EncryptFile`, `DecryptFile`
  - `NewEncryptWriter`, `NewDecryptReader`
  - `Inspect`, `Rewrap`, `RewrapFile`
- `field` package:
  - `EncryptValue`, `DecryptValue`

## Key Model

- Generate random DEK (32 bytes) per object.
- Wrap DEK for each recipient.
- Derive subkeys from DEK using HKDF-SHA256 and nonce context:
  - content key
  - header authentication key
  - nonce salt
  - reserved material

## Key Lifecycle Model

- `KeyManager` provisions and manages key lifecycle.
- `Recipient` only performs runtime `WrapKey`/`UnwrapKey`.
- `RecipientResolver` converts stored `KeyReference` records into runtime `recipient.Recipient` instances.
- `KeyReference` is stable, serializable metadata that never includes private key material.
- Application key ownership mapping (for example per tenant or per organization) is handled by the application, not by Enigma.

### Rotation versus Rewrap

- Rotation creates or selects successor keys at lifecycle level.
- Rewrap updates recipient entries in encrypted documents.
- Rotation does not automatically re-encrypt existing payloads.
- Rewrap does not create or rotate backend keys.

## Rewrap Model

Rewrap attempts to unwrap DEK with supplied recipient(s), then rewrites only:
- recipient section
- header authentication tag

Encrypted chunk stream bytes are copied as-is.

## Capability Model

Recipient descriptors expose capability level:
- `local-pq`
- `cloud-classical`
- `cloud-pq-native`

Capability is explicit to avoid silent security assumptions.

## Memory Hygiene

`mem` package provides best-effort slice zeroing and clone minimization.
Go runtime behavior may still retain copies in unmanaged locations.
