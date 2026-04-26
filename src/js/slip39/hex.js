import { Slip39Error } from "./errors.js";
import { validateMasterSecretBytes } from "./validation.js";

export function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function compactHex(hex) {
  return hex.replace(/\s+/g, "").toLowerCase();
}

export function normalizeHex(hex) {
  const normalized = compactHex(hex);
  if (normalized.length === 0) {
    throw new Slip39Error("The master secret hex is empty.");
  }
  if (/[^0-9a-f]/i.test(normalized)) {
    throw new Slip39Error("The master secret hex can contain only hex digits and whitespace.");
  }
  if (normalized.length % 2 !== 0) {
    throw new Slip39Error(
      "The master secret hex has an odd number of digits. Add or remove one hex digit intentionally; this app will not auto-pad."
    );
  }
  return normalized;
}

export function hexToBytes(hex) {
  const normalized = normalizeHex(hex);
  const output = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

export function parseMasterSecretHex(hex) {
  const bytes = hexToBytes(hex);
  validateMasterSecretBytes(bytes);
  return bytes;
}
