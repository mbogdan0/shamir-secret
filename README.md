# SLIP-0039 Shamir Secret

![Test coverage: 98.16%](https://img.shields.io/badge/test%20coverage-98.16%25-brightgreen)

Security-focused, offline-first SLIP-0039 share generation and recovery for browser environments.

This project intentionally prioritizes security posture, implementation transparency, and protocol correctness over feature breadth.

**Live demo:** [mbogdan0.github.io/shamir-secret](https://mbogdan0.github.io/shamir-secret/)

## 🔒 Security-Critical Summary (Read First)

- The production artifact is a single self-contained file: `dist/index.html`.
- Runtime is designed for offline use, with no external runtime assets.
- Build enforces a strict CSP in production output:
  - `default-src 'none'`
  - `connect-src 'none'`
  - `base-uri 'none'`
  - `form-action 'none'`
  - `object-src 'none'`
- No browser persistence APIs are used for secrets (`localStorage`, `sessionStorage`, `indexedDB`, cookies).
- Cryptographic operations use Web Crypto (`getRandomValues`, `crypto.subtle`) for RNG, HMAC-SHA256, and PBKDF2.

Critical operational caveats:

- Browser memory is not a hardened secret boundary.
- Clipboard contents are outside the app trust boundary after copy operations.
- SLIP-0039 cannot confirm intended passphrase correctness.
- This repository is not a formal third-party cryptographic audit.

## 🚀 Quick Start (End User, No Build Required)

1. Download `dist/index.html` from the latest GitHub release assets.
2. Verify the published SHA-256 from [RELEASE_NOTES.md](./RELEASE_NOTES.md).
3. Open the verified file locally in a trusted browser.
4. Keep the machine offline during secret handling whenever possible.

## ⚠️ Threat Model and Trust Boundaries

### In scope

- Correctness and interoperability of SLIP-0039 processing in a local browser context.
- Protection against accidental online dependency drift in production runtime.
- Defensive rendering patterns for user-controlled content (safe DOM sinks).

### Out of scope

- Resistance to compromised hosts, malicious browser extensions, malware, or remote administration tooling.
- Formal side-channel resistance guarantees in browser runtimes.
- Hardware-wallet certification or formal cryptographic product assurance.

## ✅ Security Guarantees vs ❌ Non-Guarantees

### What this codebase is designed to guarantee

- Standard-compliant SLIP-0039 share encoding/decoding behavior for project scope.
- Deterministic validation errors for malformed inputs.
- Offline artifact constraints enforced by tests and build-time checks.
- Safe rendering strategy for user content (no dynamic HTML insertion for shares/recovery output).

### What this codebase explicitly does not guarantee

- Total in-memory zeroization of secret material.
- Protection once secrets leave the app boundary (clipboard, screenshots, system telemetry).
- Detection of wrong-but-plausible passphrase outputs beyond SLIP-0039 semantics.
- Security claims equivalent to an independent external audit.

## 🧮 Technical Foundation

### Cryptographic and protocol core (`src/ts/slip39`)

- GF(256) arithmetic and interpolation over the AES polynomial.
- RS1024 checksum encode/verify flow.
- Share metadata packing/parsing (identifier, thresholds, group/member parameters).
- SLIP-0039 encryption/decryption flow using:
  - Feistel construction,
  - PBKDF2-HMAC-SHA256,
  - iteration exponent handling.
- Validation rules for secret size, passphrase character set, and share parameters.

### Security-relevant constants and constraints

- Minimum master-secret strength: 128 bits (16 bytes).
- Master-secret byte length must be even.
- Maximum share count: 16.
- Passphrase character set: printable ASCII.
- Single-group generation policy with SLIP-0039 1-of-1 constraint when threshold is 1.

### Text envelope mode (`SLIP39TXT v1`)

`text` mode wraps UTF-8 payloads into canonical master-secret bytes before SLIP-0039 processing.

Envelope structure includes:

- Magic prefix: `SLIP39TXT`
- Version byte: `1`
- 4-byte big-endian UTF-8 length
- 16-byte integrity tag: leading bytes of `SHA-256(magic || version || lengthBE || zero(16) || payload || padding)`. The decoder zeroes the tag region, recomputes the digest, and compares with constant-time equality; mismatch means decode returns `null`.
- Optional zero padding for even byte length

Interoperability implications:

- Generated shares are still standard SLIP-0039 shares.
- External tools recover canonical master-secret bytes (typically shown as hex).
- Only this app's envelope decoder reconstructs the original text payload.

## 🏗️ Build and Artifact Integrity

Build pipeline (`scripts/build.ts`) uses Vite programmatic output and enforces production invariants:

- CSS and JS are inlined into a single HTML file.
- CSP placeholder is replaced with strict offline policy.
- Build fails if production HTML contains:
  - external scripts/styles/images,
  - `http://` or `https://` runtime references,
  - unreplaced inline placeholders.

The corresponding test suite (`test/build.test.ts`) verifies these invariants continuously.

## 🧪 Verification and Quality Gates

Core checks:

```bash
npm run check
npm run test:coverage
npm run audit
npm run audit:prod
npm run audit:signatures
npm run --silent sbom > sbom.cdx.json
```

What validation covers:

- Protocol behavior and error semantics.
- Official/vector-based interoperability checks.
- Offline artifact invariants and CSP presence.
- Native Node.js coverage thresholds for runtime source and build scripts.
- Strict TypeScript contracts for runtime source, scripts, and tests.
- Zero runtime npm dependency policy for the offline app.
- Runtime source policy checks for unsafe browser APIs and non-relative runtime imports.
- Style and formatting consistency with blocking lint policy.
- npm audit, registry signature verification, and CycloneDX SBOM generation.

Pre-commit enforcement:

- `husky` + `lint-staged` run format/lint checks on staged changes.

## 🚀 Development Workflow

### Requirements

- Node.js `>=22` (pinned via `.nvmrc`)
- npm with `engine-strict=true` (`.npmrc`)

### Setup

```bash
npm ci
```

### Commands

```bash
npm run dev          # Vite dev server for src/
npm run build        # Build strict offline artifact -> dist/index.html
npm run preview      # Preview dist/ locally
npm test             # Node test runner
npm run test:coverage # Node test runner with coverage thresholds
npm run lint         # ESLint + Stylelint + Prettier check
npm run typecheck    # Strict TypeScript validation
npm run verify:build # Verify tracked dist/index.html matches source output
npm run format       # Full repository formatting
npm run check        # lint + typecheck + build-artifact verification + tests + build
```

## 🛠️ Operational Usage Guidance

Recommended process for high-sensitivity use:

1. Build locally and verify checks pass (`npm run check`).
2. Open `dist/index.html` in a trusted local environment.
3. Keep machine offline/disconnected during secret operations when possible.
4. Avoid unnecessary copy operations; treat clipboard as exposed.
5. Close browser after use to reduce residual secret exposure window.

## 🚫 Explicit Non-Goals

- BIP-0039 seed phrase generation/recovery.
- Multi-group policy generation UX.
- Persistent secret storage features.
- Claims of certified side-channel hardening.

## 📚 References

- [SLIP-0039 Final Specification](https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039.md)
- [SLIP-0039 in SatoshiLabs SLIPs Repository](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
- [Trezor Python Reference Implementation](https://github.com/trezor/python-shamir-mnemonic)
- [Official Trezor SLIP-0039 Test Vectors](https://raw.githubusercontent.com/trezor/python-shamir-mnemonic/master/vectors.json)
- [Trezor Firmware Notes for SLIP-0039](https://docs.trezor.io/trezor-firmware/core/misc/slip0039.html)
- [SLIP-0039 Wordlist](https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039/wordlist.txt)
- [RFC 8018 (PBKDF2)](https://www.rfc-editor.org/rfc/rfc8018)

Repository documents:

- `SECURITY_REVIEW.md`
- `THIRD_PARTY_NOTICES.md`
- `RELEASE_NOTES.md`
- `LICENSE`

## 📄 License

This project is licensed under the MIT License. See `LICENSE`.
