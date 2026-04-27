import { hex as scureHex } from "@scure/base";
import { Slip39Error } from "./errors.js";
import { validateMasterSecretBytes } from "./validation.js";

export function bytesToHex(bytes) {
  return scureHex.encode(bytes);
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
  return scureHex.decode(normalized);
}

export function parseMasterSecretHex(hex) {
  const bytes = hexToBytes(hex);
  validateMasterSecretBytes(bytes);
  return bytes;
}
