# Architecture

## Overview

Enigma is structured into four layers:

1. Recipient / key wrapping layer
- Defines recipient interface.
- Wraps and unwraps a random DEK.
- Supports local PQ recipient (ML-KEM) and cloud-provider stubs with explicit capabilities.

2. Symmetric encryption layer
- Uses one DEK per encrypted object.
- Derives separated subkeys with HKDF-SHA256.
- Encrypts content using AEAD suites:
  - default: XChaCha20-Poly1305
  - optional: AES-256-GCM
- Uses chunked authenticated framing for document/blob workloads.

3. Container format layer
- Implements strict binary envelope parser/serializer.
- Header split:
  - immutable section (content-bound)
  - recipient section (rewrap-mutable)
- Header authentication tag is derived from DEK material.

4. High-level API layer
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
