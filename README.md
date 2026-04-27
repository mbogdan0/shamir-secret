# SLIP-0039 Shamir Secret

Security-focused, offline-first SLIP-0039 master-secret sharing and recovery application.

This project provides a browser UI for generating and recovering SLIP-0039 mnemonic shares while preserving a strict offline runtime model: production output is a single self-contained HTML file with inline CSS/JavaScript and no external runtime assets.

## Project Purpose

The goal is to provide a transparent, auditable, framework-free runtime implementation for SLIP-0039 workflows in a local browser context, with strong emphasis on deterministic behavior, explicit validation, and interoperability with upstream tooling.

## Features

- SLIP-0039 Final mnemonic generation for single-group `T-of-N` shares.
- SLIP-0039-compatible recovery from valid mnemonic shares.
- Optional text mode that wraps UTF-8 payloads into a reversible `SLIP39TXT` envelope before share generation.
- Strict input validation for hex payloads, share counts, threshold values, and passphrase constraints.
- Deterministic and interoperability-focused tests using vendored Trezor vectors.
- Offline production artifact (`dist/index.html`) with restrictive CSP and no external runtime dependencies.

## Explicit Non-Goals

- BIP-0039 seed phrase generation or recovery.
- Multi-group policy generation UX beyond current scope.
- Browser storage persistence for secrets, passphrases, or generated shares.
- Claims of formal third-party cryptographic certification or side-channel hardening.

## Architecture Overview

### 1. Crypto Core (`src/js/slip39`)

- Implements GF(256) arithmetic, polynomial interpolation, checksum handling, share parsing/encoding, and SLIP-0039-compatible encryption/decryption flows.
- Exposes a focused API through `src/js/slip39/index.js`.
- Keeps compatibility behavior aligned with SLIP-0039 and upstream reference vectors.

### 2. UI Layer (`src/js/ui` + `src/index.html` + `src/styles.css`)

- Handles generation/recovery flows, form validation messaging, tab navigation, and explicit copy actions.
- Uses safe DOM writes (`textContent` / controlled attributes) and avoids dynamic HTML rendering for user-provided content.

### 3. Build Pipeline (`scripts/build.js`)

- Uses Vite programmatic build orchestration to bundle runtime JavaScript and CSS.
- Inlines generated assets into `src/index.html` placeholders.
- Injects the strict production CSP into `dist/index.html` during build.
- Enforces offline artifact invariants before writing `dist/index.html`:
  - inline CSS present,
  - inline script present and exposes `__SLIP39_APP__`,
  - strict CSP meta present with offline-only directives,
  - no external runtime scripts/styles/images/URLs,
  - no unreplaced inline placeholders.

## Development Workflow

### Requirements

- Node.js `>=22` (pinned via `.nvmrc`)
- npm (bundled with Node, with `engine-strict=true` in `.npmrc`)

### Install

```sh
npm ci
```

### Commands

```sh
npm run dev          # Vite dev server for src/ (live reload)
npm run build        # Strict offline build -> dist/index.html
npm run preview      # Preview dist/ via Vite preview server
npm test             # Node test runner
npm run lint         # ESLint + Stylelint + Prettier check (warnings fail)
npm run format       # Full repository formatting pass
npm run check        # lint + test + build
```

### Local Quality Enforcement

- `husky` + `lint-staged` run on `pre-commit`.
- Staged files are formatted and linted before a commit is accepted.
- CI and local commands both treat warnings as blocking in lint steps.

## Security Model and Operational Guidance

### Security Posture

- Offline-first runtime artifact intended for local execution from file or trusted local hosting.
- Restrictive CSP (`default-src 'none'`) is enforced in the production artifact (`dist/index.html`) with explicitly limited inline script/style allowances required by single-file delivery.
- Development template (`src/index.html`) intentionally omits CSP so Vite runtime and HMR can load local dev assets.
- No runtime network fetches and no browser storage persistence for sensitive data.

### Important Limitations

- Browser memory is not a hardened secret boundary; complete zeroization is not guaranteed.
- Clipboard use transfers risk to the host OS and surrounding environment.
- SLIP-0039 cannot verify intended passphrase correctness; incorrect passphrases can still produce bytes.
- This repository is not a substitute for a formal independent cryptographic audit.

For deeper implementation and risk notes, see `SECURITY_REVIEW.md`.

## Release and Deployment Model

GitHub Pages deployment is automated by tag pushes:

- Workflow file: `.github/workflows/pages.yml`
- Trigger: `push` tags matching `v*`
- Quality gate before deployment:
  1. `npm ci`
  2. `npm run lint`
  3. `npm test`
  4. `npm run build`
- Only successful quality builds are published to GitHub Pages.

## Compatibility and Interoperability

- Recovery is compatible with valid SLIP-0039 mnemonic shares, including upstream Trezor-compatible vectors included in this repository.
- Generated shares are SLIP-0039 shares (not BIP-0039 phrases).
- Text mode remains interoperable at byte level by embedding text in `SLIP39TXT` envelope bytes before SLIP-0039 generation.

## References

- [SLIP-0039 Final Specification](https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039.md)
- [Trezor Python Reference Implementation](https://github.com/trezor/python-shamir-mnemonic)
- [SLIP-0039 Wordlist](https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039/wordlist.txt)

See also:

- `SECURITY_REVIEW.md`
- `THIRD_PARTY_NOTICES.md`
