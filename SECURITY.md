# Security Policy

## Supported Branch

This repository currently supports the latest `main` branch for security fixes.

## Reporting a Vulnerability

Please open a private security report through your preferred responsible disclosure channel.
Include:
- affected version/commit
- reproduction steps
- security impact assessment
- potential fix direction if available

Do not publish exploit details before a fix is available.

## Security Notes

This library is a cryptographic wrapper around established primitives and key-management backends.
It does not claim to provide absolute protection against all runtime, host, or supply-chain threats.

Key points:
- Uses modern authenticated encryption primitives.
- Uses ML-KEM for local PQ key encapsulation.
- Uses explicit capability labeling for backend transparency.
- Uses best-effort secret wiping only.

See `docs/threat-model.md` for assumptions, trust boundaries, and out-of-scope threats.
