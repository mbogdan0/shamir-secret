# Release Notes

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
