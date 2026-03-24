# Roadmap

## Completed in v1 Foundation

- Layered architecture (`recipient`, `container`, `document`, `field`)
- Local ML-KEM recipient implementation
- Chunked document encryption and stream APIs
- Rewrap path without content re-encryption
- Field encryption compact format
- Typed errors and capability model
- Core docs and tests/benchmarks

## Planned Next

1. Cloud backend implementations
- Replace provider stubs with production integrations.
- Add live integration test matrix behind opt-in configuration.

2. Stronger policy controls
- Optional stricter profile/policy validation helpers.
- Explicit compliance constraints for algorithm and recipient mixes.

3. Signature extension
- Add optional signed footer extension for authenticity provenance.

4. Advanced rewrap tooling
- CLI improvements for inspection/rewrap automation.
- Batch rewrap workflows.

5. Hardening and observability
- Additional fuzzing corpora.
- Performance profiling on large object streams.
- More fault-injection tests.
