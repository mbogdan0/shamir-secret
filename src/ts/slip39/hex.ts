import { InvalidSecretLengthError } from "./errors.ts";
import { validateMasterSecretBytes } from "./validation.ts";

const HEX_ALPHABET = "0123456789abcdef";

export function bytesToHex(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) {
    output += HEX_ALPHABET[byte >>> 4] + HEX_ALPHABET[byte & 0x0f];
  }
  return output;
}

export function compactHex(hex: string): string {
  return hex.replace(/\s+/g, "").toLowerCase();
}

export function normalizeHex(hex: string): string {
  const normalized = compactHex(hex);
  if (normalized.length === 0) {
    throw new InvalidSecretLengthError("The master secret hex is empty.");
  }
  if (/[^0-9a-f]/i.test(normalized)) {
    throw new InvalidSecretLengthError(
      "The master secret hex can contain only hex digits and whitespace."
    );
  }
  if (normalized.length % 2 !== 0) {
    throw new InvalidSecretLengthError(
      "The master secret hex has an odd number of digits. Add or remove one hex digit intentionally; this app will not auto-pad."
    );
  }
  return normalized;
}

export function hexToBytes(hex: string): Uint8Array {
  const normalized = normalizeHex(hex);
  const output = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

export function parseMasterSecretHex(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  validateMasterSecretBytes(bytes);
  return bytes;
}
