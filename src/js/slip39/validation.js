import { ID_LENGTH_BITS, MAX_SHARE_COUNT, MIN_STRENGTH_BITS } from "./constants.js";
import { Slip39Error } from "./errors.js";
import { asciiToBytes } from "./utils.js";

/**
 * @param {string} passphrase
 * @returns {Uint8Array}
 */
export function validatePassphrase(passphrase) {
  for (let index = 0; index < passphrase.length; index += 1) {
    const codePoint = passphrase.charCodeAt(index);
    if (codePoint < 32 || codePoint > 126) {
      throw new Slip39Error("The passphrase must contain only printable ASCII characters.");
    }
  }
  return asciiToBytes(passphrase);
}

/**
 * @param {number} identifier
 */
export function validateIdentifier(identifier) {
  if (!Number.isInteger(identifier) || identifier < 0 || identifier >= 1 << ID_LENGTH_BITS) {
    throw new Slip39Error("The SLIP-0039 identifier must be an integer from 0 to 32767.");
  }
}

/**
 * @param {Uint8Array} masterSecret
 */
export function validateMasterSecretBytes(masterSecret) {
  if (Object.prototype.toString.call(masterSecret) !== "[object Uint8Array]") {
    throw new Slip39Error("The master secret must be bytes.");
  }
  if (masterSecret.length * 8 < MIN_STRENGTH_BITS) {
    throw new Slip39Error("The master secret must be at least 16 bytes.");
  }
  if (masterSecret.length % 2 !== 0) {
    throw new Slip39Error(
      "The master secret byte length must be a multiple of 2. Add or remove a full byte intentionally; this app will not auto-pad."
    );
  }
}

/**
 * @param {number} threshold
 * @param {number} shareCount
 */
export function validateShareParameters(threshold, shareCount) {
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new Slip39Error("Threshold must be a positive integer.");
  }
  if (!Number.isInteger(shareCount) || shareCount < 1) {
    throw new Slip39Error("Total shares must be a positive integer.");
  }
  if (threshold > shareCount) {
    throw new Slip39Error("Threshold must not exceed total shares.");
  }
  if (shareCount > MAX_SHARE_COUNT) {
    throw new Slip39Error(`Total shares must not exceed ${MAX_SHARE_COUNT}.`);
  }
}

/**
 * @param {number} threshold
 * @param {number} shareCount
 */
export function validateSingleGroupParameters(threshold, shareCount) {
  validateShareParameters(threshold, shareCount);
  if (threshold === 1 && shareCount > 1) {
    throw new Slip39Error("SLIP-0039 requires 1-of-1 when the member threshold is 1.");
  }
}

/**
 * @param {number} iterationExponent
 */
export function validateIterationExponent(iterationExponent) {
  if (!Number.isInteger(iterationExponent) || iterationExponent < 0 || iterationExponent > 15) {
    throw new Slip39Error("Iteration exponent must be an integer from 0 to 15.");
  }
}
