# Container Format (v1)

## Design Goals

- Strict binary, versioned, deterministic encoding.
- Stream-friendly chunk framing.
- Authenticated header with rewrap-compatible recipient section updates.
- Explicit algorithm and recipient metadata.

## High-Level Layout

All integers are big-endian.

```
+----------------------+-------------------------------------------+
| Field                | Description                               |
+----------------------+-------------------------------------------+
| magic (4 bytes)      | ASCII "ENGM"                              |
| version (1 byte)     | format version (1)                        |
| flags (1 byte)       | reserved for future use                   |
| immutable_len (u32)  | length of immutable header section        |
| recipients_len (u32) | length of recipient section               |
| auth_tag_len (u16)   | length of header auth tag                 |
| immutable bytes      | suite/chunk/profile/metadata section      |
| recipient bytes      | wrapped DEK entries                        |
| auth tag bytes       | HMAC over context+immutable+recipient     |
| chunk stream         | one or more chunk frames                  |
| footer_len (u32)     | optional footer length                    |
| footer bytes         | optional extension data                   |
+----------------------+-------------------------------------------+
```

## Immutable Header Section

Contains:
- AEAD suite identifier
- chunk size
- nonce context
- creation timestamp
- profile
- metadata map

This section is cryptographically bound to chunk AAD.

## Recipient Section

Contains one or more wrapped DEK entries with:
- recipient type
- capability level
- wrap algorithm identifier
- key reference
- encapsulated key material (if used)
- nonce
- wrapped DEK ciphertext
- metadata map

Recipient section can be replaced during rewrap.

## Header Authentication

`header_auth_tag = HMAC-SHA256(header_auth_key, domain || version || flags || immutable_raw || recipients_raw)`

`header_auth_key` is DEK-derived material (HKDF-separated).

## Chunk Frame

Each chunk frame:
- type (`0x01` data, `0x02` final)
- chunk index (u64)
- plaintext length (u32)
- ciphertext length (u32)
- ciphertext bytes

Per-chunk nonce is deterministically derived from `nonce_salt`, `nonce_context`, and `chunk_index`.
Chunk AAD binds immutable header bytes and chunk metadata.

## Parsing Rules

- reject unknown version
- reject empty required sections
- enforce section size limits
- reject malformed lengths/truncation
- reject unknown chunk type
- require final chunk marker
- reject trailing bytes after footer
