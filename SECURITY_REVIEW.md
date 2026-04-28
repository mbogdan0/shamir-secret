# Security, Math, and Cryptography Local Review

Reviewed on 2026-04-28.

## Executive Verdict

Verdict: Pass with caveats for the reviewed project scope.

This is a local implementation review, not a formal third-party cryptographic audit. The implementation is consistent with the current project scope: an offline, framework-free SLIP-0039 Final app that generates single-group T-of-N shares and recovers compatible SLIP-0039 shares. The reviewed cryptographic math, encoding, checksum, passphrase, and browser controls are aligned with SLIP-0039 Final and covered by local tests plus upstream Trezor vectors.

Within this local review, no critical or high-severity defects were found. The remaining caveats are operational and browser-environment risks: clipboard exposure, browser memory lifetime, side-channel hardening limits, compromised local environments, and the absence of a formal external cryptography audit. For high-value secrets, prefer audited hardware-wallet or vendor flows.

## Scope

In scope:

- SLIP-0039 Final single-group generation and compatible recovery.
- GF(256) arithmetic, interpolation, digest validation, checksum handling, metadata packing, Feistel/PBKDF2 passphrase encryption, and validation limits.
- Offline browser posture, Content Security Policy, storage/network avoidance, safe DOM rendering, Web Crypto use, and clipboard behavior.
- Test evidence, dependency audit evidence, and upstream wordlist/vector equality checks.

Out of scope:

- Adding group-policy generation.
- Formal side-channel analysis, browser exploit analysis, hardware-wallet certification, or third-party audit sign-off.
- Protection from compromised operating systems, browsers, extensions, remote administration tooling, or malware.

## Verification Evidence

Commands were run from `/Users/bogdan/IdeaProjects/shamir-secret` unless noted.

| Check                                                                                                 | Result                                             |
| ----------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `npm run typecheck`                                                                                   | Passed                                             |
| `npm test`                                                                                            | 44 tests passed, 0 failed                          |
| `npm run verify:runtime-deps`                                                                         | Verified zero runtime npm dependencies             |
| `npm run verify:source-policy`                                                                        | Verified runtime source policy                     |
| `npm audit`                                                                                           | `found 0 vulnerabilities`                          |
| `npm audit --omit=dev`                                                                                | `found 0 vulnerabilities`                          |
| `npm audit signatures`                                                                                | Registry signatures and attestations verified      |
| Upstream SLIP-0039 wordlist equality                                                                  | 1024 local words, 1024 upstream words, exact match |
| Upstream Trezor vectors equality                                                                      | 45 local cases, 45 upstream cases, exact match     |
| Precise static scan for storage, network, dynamic HTML, unsafe randomness, and dynamic code execution | No matches in `src`, `scripts`, or `package.json`  |

The TypeScript test command runs with Node's built-in type stripping and verifies the generated single-file artifact through `scripts/build.ts`.

## Findings

| Severity      | Area                               | Evidence                                                                                                                                                                                                                                               | Impact                                                                                                                                                                        | Recommendation                                                                                                                                                                     |
| ------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| None          | SLIP-0039 math                     | GF(256) exp/log tables and AES polynomial reduction are in `src/ts/slip39/gf256.ts`; interpolation validates unique indices and equal value lengths. Tests cover AES-field multiplication and interpolation recovery in `test/slip39.test.ts`.         | No correctness issue found.                                                                                                                                                   | Keep upstream-vector and local arithmetic tests in the required test suite.                                                                                                        |
| None          | Secret sharing                     | The implementation stores the shared secret at x=255 and digest share at x=254 in `src/ts/slip39/secret-sharing.ts`. Digest verification uses constant-time byte comparison before returning the recovered secret.                                     | No correctness issue found.                                                                                                                                                   | Keep digest-negative tests through upstream invalid vectors.                                                                                                                       |
| None          | Passphrase encryption              | The Feistel construction uses four rounds, PBKDF2-HMAC-SHA256, the configured iteration exponent, and SLIP-0039 salt behavior in `src/ts/slip39/cipher.ts`.                                                                                            | No correctness issue found.                                                                                                                                                   | Keep deterministic-generation fixtures and official vector recovery tests.                                                                                                         |
| None          | Metadata and checksum              | Identifier, extendable flag, iteration exponent, group/member parameters, value words, and checksum are packed and parsed in `src/ts/slip39/share.ts`. RS1024 checksum creation and verification are in `src/ts/slip39/checksum.ts`.                   | No correctness issue found.                                                                                                                                                   | Keep checksum corruption and original/extendable checksum tests.                                                                                                                   |
| None          | Validation limits                  | Printable ASCII passphrases, 15-bit identifiers, 128-bit minimum master secret size, even byte length, threshold/count limits, and 1-of-1 enforcement are in `src/ts/slip39/validation.ts`.                                                            | No correctness issue found.                                                                                                                                                   | Keep rejection tests for invalid parameters and passphrases.                                                                                                                       |
| None          | Interoperability                   | Vendored Trezor vectors and deterministic generated fixtures are tested in `test/slip39.test.ts`. Upstream equality checks showed the local wordlist and vector fixture exactly match upstream.                                                        | No interoperability issue found for the reviewed scope.                                                                                                                       | Re-run upstream equality checks when updating fixtures, wordlist, or SLIP-0039 code.                                                                                               |
| Low           | Clipboard exposure                 | Shares and recovered secrets can be copied through the browser clipboard. The fallback path writes text to a temporary textarea and invokes `document.execCommand("copy")`.                                                                            | Clipboard contents are outside the app's trust boundary and may outlive the page or be observable by the OS, browser extensions, remote desktop tools, or clipboard managers. | Keep copy actions explicit. Keep UI and README warnings that clipboard contents are outside the protected boundary.                                                                |
| Low           | Browser memory lifetime            | Secrets, shares, passphrases, and recovered outputs exist in JavaScript strings and `Uint8Array` values during normal operation. Web JavaScript cannot reliably zeroize all copies, especially immutable strings and VM/internal copies.               | Browser memory is not a protected boundary. A compromised browser, extension, debugger, crash dump, or shared machine could expose secrets after use.                         | Document this limitation prominently. For high-value secrets, prefer audited hardware-wallet or vendor flows.                                                                      |
| Low           | Inline CSP exception               | The app uses a single-file/offline delivery model with inline CSS and JS. The CSP blocks network/storage-like attack surfaces but allows inline script/style through `script-src 'unsafe-inline'` and `style-src 'unsafe-inline'` in `src/index.html`. | If an HTML injection bug existed, inline-script allowance would reduce CSP's ability to block execution. Review found no dynamic HTML rendering in the app source.            | Keep using safe DOM sinks such as `textContent` in `src/ts/ui/shares.ts`. Consider a hash-based CSP only if the build flow can support it without breaking file-based offline use. |
| Informational | Wrong passphrase semantics         | The UI warns that SLIP-0039 cannot verify the intended passphrase in `src/ts/ui/recovery-output.ts`. Tests confirm wrong passphrases produce different bytes without app-specific rejection in `test/slip39.test.ts`.                                  | This is expected SLIP-0039 behavior, not a defect. Users may still mistake any recovered bytes for the intended secret if they ignore the warning.                            | Keep the warning visible. Consider stricter local UX copy around passphrase confirmation, without changing SLIP-0039 wire format or recovery semantics.                            |
| Informational | Reference implementation hardening | The Trezor Python reference implementation states that it is intended to verify correctness and does not use hardening techniques for sensitive secrets.                                                                                               | Compatibility with reference behavior does not itself prove production hardening against local compromise or side channels.                                                   | Treat this review as implementation and interoperability assurance, not a replacement for a professional external audit.                                                           |

## Traceability Matrix

| Requirement                                                                               | Local implementation                                            | Test or evidence                                                                       |
| ----------------------------------------------------------------------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Wordlist has exactly 1024 unique SLIP-0039 words                                          | `src/ts/slip39/wordlist.ts`                                     | `test/slip39.test.ts`; upstream equality check exact match                             |
| GF(256) over Rijndael polynomial                                                          | `src/ts/slip39/gf256.ts`                                        | `test/slip39.test.ts`                                                                  |
| Polynomial interpolation validates share shape                                            | `src/ts/slip39/gf256.ts`                                        | `test/slip39.test.ts`                                                                  |
| Shared secret at x=255 and digest at x=254                                                | `src/ts/slip39/secret-sharing.ts`                               | Official invalid-digest vectors in `test/slip39.test.ts`                               |
| Digest is HMAC-SHA256 truncated to four bytes                                             | `src/ts/slip39/secret-sharing.ts`; `src/ts/slip39/constants.ts` | Official vectors and deterministic fixtures                                            |
| RS1024 checksum supports original and extendable customization strings                    | `src/ts/slip39/checksum.ts`                                     | `test/slip39.test.ts`                                                                  |
| Identifier, extendable flag, iteration exponent, and share params encode/decode correctly | `src/ts/slip39/share.ts`                                        | `test/slip39.test.ts`                                                                  |
| Master secret encryption/decryption follows SLIP-0039 Feistel/PBKDF2 flow                 | `src/ts/slip39/cipher.ts`                                       | Deterministic generation fixtures and official Trezor vectors                          |
| Generation is intentionally single-group T-of-N                                           | `src/ts/slip39/mnemonics.ts`                                    | `test/slip39.test.ts`                                                                  |
| Recovery supports compatible group-policy mnemonics                                       | `src/ts/slip39/mnemonics.ts`                                    | Official Trezor group-vector coverage in `test/slip39.test.ts`                         |
| Flexible recovery accepts surplus/duplicate valid shares and rejects conflicts            | `src/ts/slip39/mnemonics.ts`                                    | `test/slip39.test.ts`                                                                  |
| Passphrases are printable ASCII only                                                      | `src/ts/slip39/validation.ts`                                   | `test/slip39.test.ts`                                                                  |
| Master secret length constraints are enforced                                             | `src/ts/slip39/validation.ts`                                   | `test/slip39.test.ts`                                                                  |
| Web Crypto is required for RNG, HMAC, and PBKDF2                                          | `src/ts/slip39/crypto.ts`                                       | `test/slip39.test.ts`                                                                  |
| Offline build blocks network/runtime assets and browser storage                           | `src/index.html`; `test/build.test.ts`                          | `test/build.test.ts`                                                                   |
| User-controlled output uses safe DOM sinks                                                | `src/ts/ui/shares.ts`; `src/ts/ui/recovery-output.ts`           | Precise static scan found no dynamic HTML sinks in `src`, `scripts`, or `package.json` |

## Residual Risks

- Browser memory is not a hardened secret-storage boundary. JavaScript cannot guarantee complete zeroization of strings, typed arrays, VM temporaries, browser autofill internals, crash dumps, or extension-visible state.
- The system clipboard is outside the application's trust boundary after a copy action.
- The implementation is not constant-time throughout all parsing, arithmetic, PBKDF2, and UI paths. Browser-based side-channel resistance is not claimed.
- Security depends on the user's local environment. Malware, malicious extensions, screen capture, compromised browsers, remote desktop tools, and shared machines can defeat the app's offline design.
- `script-src 'unsafe-inline'` is a deliberate tradeoff for a single-file offline app. The reviewed code avoids dynamic HTML injection, but the CSP is not a complete script-injection mitigation under future code changes.
- This review is a local implementation review. It is not a formal third-party cryptography audit.
- For high-value secrets, audited hardware-wallet or vendor recovery flows are a better default than a browser-based tool.

## Source References

- SLIP-0039 Final specification: https://github.com/satoshilabs/slips/blob/master/slip-0039.md
- SLIP-0039 official wordlist: https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039/wordlist.txt
- Trezor Python reference implementation: https://github.com/trezor/python-shamir-mnemonic
- Trezor official vectors: https://raw.githubusercontent.com/trezor/python-shamir-mnemonic/master/vectors.json
- Trezor firmware SLIP-39 notes: https://docs.trezor.io/trezor-firmware/core/misc/slip0039.html
