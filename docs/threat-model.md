# Threat Model

## Goals

Protect confidentiality and integrity of encrypted content at rest and in transit between trusted application components.

## Trust Boundaries

Trusted:
- application process memory (best-effort secret handling)
- configured recipient private material/KMS permissions

Untrusted or partially trusted:
- storage backend (files, object stores, DB ciphertext columns)
- transport path carrying encrypted blobs
- attackers able to read/modify container bytes

## In-Scope Attacker Capabilities

- read encrypted files/values at rest
- tamper with container header or chunk bytes
- replay/replace truncated payload segments
- gain storage access without automatically gaining recipient private keys/KMS permissions

## Security Outcomes

- Content confidentiality holds unless DEK can be unwrapped.
- Integrity verification fails on modified header/chunk bytes.
- Chunk corruption is detected at decryption time.
- Any valid recipient can decrypt; invalid recipients fail unwrap.

## Metadata Exposure

Recipient descriptors and key references are inspectable by design.
This is a usability trade-off and not encrypted metadata secrecy.

## Key Compromise Boundaries

- DEK compromise exposes that object/value content.
- Recipient private key/KMS permission compromise may expose any DEKs wrapped for that recipient.
- Compromise of one object DEK does not directly expose other object DEKs.

## Developer Misuse Risks

- configuring local-pq profile with non-local recipients
- ignoring capability labels and assuming PQ guarantees everywhere
- weak key/secret lifecycle handling in higher application layers

## Out of Scope (v1)

- identity and access-management platform concerns
- remote SaaS sharing workflows
- deterministic searchable encryption
- digital signatures and signer identity assertions
- protection against fully compromised host/runtime
