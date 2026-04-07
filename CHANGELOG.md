# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0-beta.3] - 2026-04-08

### Fixed

- CLI bin script moved to `bin/clg-verify.js` wrapper — resolves npm stripping bin entries
- `npx clg-verify` now works as expected

## [1.0.0-beta.2] - 2026-04-08

### Fixed

- CLI bin script shebang added (npm still stripped bin entry due to path validation)

## [1.0.0-beta.1] - 2026-04-07

### Added

- `verifyReceipt()` — verify a single CLG decision receipt (hash + signature)
- `verifyChain()` — verify an ordered chain of receipts (links + individual receipts)
- `httpResolver()` — fetch public keys from CLG platform API
- `jwksResolver()` — fetch from JWKS-like well-known endpoint
- `staticResolver()` — use a pre-loaded PEM key
- `fileResolver()` — read PEM from filesystem
- `canonicalize()` — deterministic canonicalization matching CLG SDK
- `sha256()`, `verifySignature()` — low-level crypto utilities
- CLI: `clg-verify receipt <file>` and `clg-verify chain <file>`
- CLI options: `--public-key`, `--jwks`, `--offline`, `--pretty`
- Zero runtime dependencies (node:crypto only)
- Business Source License 1.1
