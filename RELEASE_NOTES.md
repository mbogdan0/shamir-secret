# Release Notes

## v0.3.5 (2026-05-02)

### Artifact Integrity

- Artifact: `dist/index.html`
- SHA-256: `957f2af1ef8c8844c7ff7b19520d25a6f3798db1fcdfa1e6584ebdafa9d3ef8f`
- Verification command: `shasum -a 256 dist/index.html`

### Notes

- Updated the README coverage badge to the current 99.62% line coverage.
- Added crypto-boundary hardening for duplicate shares, insufficient shares, and recovery error taxonomy.
- Rebuilt the offline artifact from the hardened SLIP-0039 core.

## v0.3.4 (2026-04-29)

### Artifact Integrity

- Artifact: `dist/index.html`
- SHA-256: `5f4b1b8b6489a599495438f25cd059a03926e74660d1d69340f71bfbdd46b39c`
- Verification command: `shasum -a 256 dist/index.html`

### Notes

- Updated the README coverage badge to the current 99.70% line coverage.
- Release artifact bytes are unchanged from `v0.3.2`.

## v0.3.3 (2026-04-29)

### Artifact Integrity

- Artifact: `dist/index.html`
- SHA-256: `5f4b1b8b6489a599495438f25cd059a03926e74660d1d69340f71bfbdd46b39c`
- Verification command: `shasum -a 256 dist/index.html`

### Notes

- Added extensive deterministic text-to-shares coverage for SLIP-0039 text envelopes.
- Covered threshold subsets, share metadata, negative recovery cases, malformed envelopes, and official vector non-text detection.
- Raised overall coverage near 100%; release artifact bytes are unchanged from `v0.3.2`.

## v0.3.2 (2026-04-28)

### Artifact Integrity

- Artifact: `dist/index.html`
- SHA-256: `5f4b1b8b6489a599495438f25cd059a03926e74660d1d69340f71bfbdd46b39c`
- Verification command: `shasum -a 256 dist/index.html`

### Notes

- Removed the global test API from the production browser artifact.
- Added bounded flexible recovery to abort excessive input lines and candidate combinations.
- Added offline browser e2e coverage for file-based generate/recover with no network requests.
- Clarified security-review status, browser-memory limits, clipboard trust boundaries, single-group generation scope, and the app-specific text envelope.

## v0.3.1 (2026-04-27)

### Artifact Integrity

- Artifact: `dist/index.html`
- SHA-256: `8fb4bad1b09b4e81155f89206d693b7083cde8d7dc0b39b2d0b36f121df217c1`
- Verification command: `shasum -a 256 dist/index.html`

### Notes

- Raised local test coverage and added the README coverage badge.
- Release artifact bytes are unchanged from `v0.3.0`.

## v0.3.0 (2026-04-27)

### Artifact Integrity

- Artifact: `dist/index.html`
- SHA-256: `8fb4bad1b09b4e81155f89206d693b7083cde8d7dc0b39b2d0b36f121df217c1`
- Verification command: `shasum -a 256 dist/index.html`

### Notes

- Migrated runtime source, build scripts, and tests from JavaScript to TypeScript.
- Updated tooling commands and repository checks for strict TypeScript validation.
- Rebuilt the offline browser artifact from the TypeScript entrypoint.

## v0.2.0 (2026-04-27)

### Artifact Integrity

- Artifact: `dist/index.html`
- SHA-256: `251b49be4230fb0f52897cfd358dcc5a9046afc9e28c3a6da63d5d1b2ce01b1d`
- Verification command: `shasum -a 256 dist/index.html`

### Notes

- Added memory-hardening updates for internal zeroization in SLIP-0039 flows.
- Converted `SLIP39TXT v1` decorative header bytes into a verified integrity tag.
- Added property-based tests and deterministic interop snapshots for non-default SLIP-0039 modes.

## v0.1.0 (2026-04-27)

### Artifact Integrity

- Artifact: `dist/index.html`
- SHA-256: `b1ceba1c2598934066c08ae5015302589be1c8f361fec66e0bacb6341d6475b6`
- Verification command: `shasum -a 256 dist/index.html`

### Notes

- Initial public release of the offline single-file browser artifact.
