# Key Management

## Purpose

Enigma separates key lifecycle management from runtime wrapping and unwrapping.

This split avoids mixing concerns:
- lifecycle APIs (`KeyManager`) provision and manage keys
- runtime recipient APIs (`recipient.Recipient`) wrap and unwrap DEKs
- resolver APIs (`RecipientResolver`) rebuild runtime recipients from stored key references

## Core Concepts

### KeyManager

`KeyManager` is responsible for key lifecycle operations:
- create key
- inspect key
- rotate key (native or successor workflow)
- delete key
- report capability set

### KeyReference

`KeyReference` is a stable, serializable key pointer suitable for storage in an application database.

A valid key reference must not include private key material.

### RecipientResolver

`RecipientResolver` turns a `KeyReference` back into a runtime `recipient.Recipient`.

Applications can persist `KeyReference` records and resolve recipients on demand for encryption/decryption operations.

## Local ML-KEM Backend

The local backend is implemented in:
- `keymgmt/localmlkem`
- `resolver/localmlkem`

### Storage model

- records are stored under `<root>/localmlkem/v1/<key-id>/<version>.json`
- files are written with mode `0600`
- directories are created with mode `0700`
- references include backend, id, version, and URI
- private key material is persisted in backend storage, not in `KeyReference`

### Filesystem trust assumptions

- local backend security depends on host filesystem access controls
- protect the configured root path with strict OS permissions
- if host compromise is in scope, local software key storage may be insufficient

## Rotation and Rewrap

Rotation and rewrap are intentionally distinct operations:

- `KeyManager.RotateKey` creates a successor key descriptor
- `document.Rewrap` updates recipient entries in encrypted containers

Rotation does not automatically rewrite historical ciphertext.
Applications should perform rewrap workflows explicitly when policy requires migration to successor keys.

## Application Ownership Mapping

Enigma does not map keys to tenants, organizations, or environments.

That mapping belongs to the application.

Typical pattern:
1. application creates a key with `KeyManager`
2. application stores `KeyReference` in its own data model
3. application resolves a runtime recipient with `RecipientResolver`
4. application encrypts/decrypts via `document` or `field` packages

## Capability Reporting

`CapabilitySet` provides explicit backend capabilities, including:
- creation/deletion support
- native rotation support versus successor workflow
- recipient resolution support
- PQ-native support versus classical wrapping support
- rewrap workflow compatibility

Capability reporting is descriptive and should be checked by the application before selecting a workflow.
