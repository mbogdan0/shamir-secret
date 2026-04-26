# SLIP-0039 Shamir Secret

Offline, framework-free SLIP-0039 master-secret sharing app. The canonical app source lives in `src/`, and the build output is a generated, validated `dist/index.html` file with all CSS and JavaScript inline.

## Commands

```sh
npm test
npm run build
```

Run `npm run build`, then open `dist/index.html`.

## Scope

- Standard SLIP-0039 mnemonic shares for raw master-secret bytes encoded as hex.
- Optional text input mode that converts text to standard master-secret bytes with a reversible `SLIP39TXT` envelope.
- Single-group `T-of-N` share generation.
- Recovery accepts valid SLIP-0039 mnemonic shares, including official Trezor-compatible shares.
- Master secrets must be at least 16 bytes and have a byte length that is a multiple of 2.
- Hex input may contain whitespace for readability; whitespace is ignored before parsing.
- The app never auto-pads odd hex or odd byte lengths. Padding would change the master secret.
- Text input is encoded as UTF-8 without trimming or normalization, then wrapped with envelope metadata before SLIP-0039 generation.
- Passphrases must contain only printable ASCII characters, as required by SLIP-0039.
- Secrets, passphrases, and shares are not written to browser storage. The offline HTML also uses a restrictive Content Security Policy with no external network connections or runtime assets.

## Recovery Contract

Generated shares include a recovery note: SLIP-0039 Final, single group, raw hex master secret or `SLIP39TXT` text envelope, printable ASCII passphrase, `ext=1`, and iteration exponent `1`.

Recover the shares with this app or any SLIP-0039-compatible tool using the same passphrase. The recovered result is the original master-secret bytes; in this app those bytes are displayed as lowercase hex. When the recovered bytes contain a supported `SLIP39TXT` envelope, this app also displays the decoded text.

SLIP-0039 cannot verify whether a passphrase is the intended one. A wrong passphrase can still produce recovered bytes, but they will not be the original master secret.

SLIP-0039 is not BIP-0039. These shares are Shamir backup mnemonics, not BIP-0039 wallet seed phrases.

The `SLIP39TXT` v1 envelope is: ASCII magic `SLIP39TXT`, version byte `0x01`, a 4-byte big-endian UTF-8 payload length, 16 random bytes, the UTF-8 payload, and one random trailing padding byte only when needed to make the total master-secret byte length even. External SLIP-0039 tools remain compatible because they recover the envelope bytes as hex; this app can decode those bytes back to text.

## Interop Check

The test suite uses a vendored snapshot of the official Trezor SLIP-0039 vectors at `test/fixtures/slip39-vectors.json`, so `npm test` is reproducible without network access.

To verify generated shares with the Trezor reference CLI:

```sh
python3 -m pip install 'shamir-mnemonic[cli]'
shamir recover
```

Enter the generated shares and the same printable ASCII passphrase. The recovered master secret should match the original lowercase hex.

## References

- [SLIP-0039 final specification](https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039.md)
- [Trezor reference implementation](https://github.com/trezor/python-shamir-mnemonic)
- [SLIP-0039 wordlist](https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0039/wordlist.txt)

See `THIRD_PARTY_NOTICES.md` for upstream license notices.
