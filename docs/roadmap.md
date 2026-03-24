# Roadmap

## Completed in v1 Foundation

- Layered architecture (`recipient`, `container`, `document`, `field`)
- Local ML-KEM recipient implementation
- Key lifecycle abstraction (`keymgmt`) and recipient resolution abstraction (`resolver`)
- Local ML-KEM key manager and resolver implementation
- Scaleway Key Manager backend:
  - `keymgmt/scwkm` lifecycle implementation
  - `recipient/scwkm` runtime DEK wrap/unwrap
  - `resolver/scwkm` key-reference resolution
- Chunked document encryption and stream APIs
- Rewrap path without content re-encryption
- Field encryption compact format
- Typed errors and capability model
- Core docs and tests/benchmarks

## Planned Next

1. Remaining provider lifecycle backends
- Add `KeyManager` and `RecipientResolver` implementations for GCP/AWS/Azure.
- Keep capability reporting explicit for native rotation versus successor workflows.
- Keep unsupported capabilities explicit; no fake cloud behavior.

2. Scaleway integration hardening
- Add opt-in live integration tests (credential-gated) for create/get/rotate/delete and wrap/unwrap flows.
- Add operational guidance for key policies and production rollout checks.

3. Stronger policy controls
- Optional stricter profile/policy validation helpers.
- Explicit compliance constraints for algorithm and recipient mixes.

4. Signature extension
- Add optional signed footer extension for authenticity provenance.

5. Advanced rewrap tooling
- CLI improvements for inspection/rewrap automation.
- Batch workflows that combine successor-key rotation and explicit rewrap execution.

6. Hardening and observability
- Additional fuzzing corpora.
- Performance profiling on large object streams.
- More fault-injection tests.
