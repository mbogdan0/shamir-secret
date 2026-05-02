import { ID_LENGTH_BITS, MAX_SHARE_COUNT, MIN_STRENGTH_BITS } from "./constants.ts";
import {
  InvalidSecretLengthError,
  InvalidThresholdError,
  MalformedMnemonicError,
  UnsupportedSlip39FeatureError
} from "./errors.ts";
import { asciiToBytes } from "./utils.ts";

export function validatePassphrase(passphrase: string): Uint8Array {
  for (let index = 0; index < passphrase.length; index += 1) {
    const codePoint = passphrase.charCodeAt(index);
    if (codePoint < 32 || codePoint > 126) {
      throw new MalformedMnemonicError(
        "The passphrase must contain only printable ASCII characters."
      );
    }
  }
  return asciiToBytes(passphrase);
}

export function validateIdentifier(identifier: number): void {
  if (!Number.isInteger(identifier) || identifier < 0 || identifier >= 1 << ID_LENGTH_BITS) {
    throw new InvalidThresholdError("The SLIP-0039 identifier must be an integer from 0 to 32767.");
  }
}

export function validateMasterSecretBytes(masterSecret: Uint8Array): void {
  if (Object.prototype.toString.call(masterSecret) !== "[object Uint8Array]") {
    throw new InvalidSecretLengthError("The master secret must be bytes.");
  }
  if (masterSecret.length * 8 < MIN_STRENGTH_BITS) {
    throw new InvalidSecretLengthError("The master secret must be at least 16 bytes.");
  }
  if (masterSecret.length % 2 !== 0) {
    throw new InvalidSecretLengthError(
      "The master secret byte length must be a multiple of 2. Add or remove a full byte intentionally; this app will not auto-pad."
    );
  }
}

export function validateShareParameters(threshold: number, shareCount: number): void {
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new InvalidThresholdError("Threshold must be a positive integer.");
  }
  if (!Number.isInteger(shareCount) || shareCount < 1) {
    throw new InvalidThresholdError("Total shares must be a positive integer.");
  }
  if (threshold > shareCount) {
    throw new InvalidThresholdError("Threshold must not exceed total shares.");
  }
  if (shareCount > MAX_SHARE_COUNT) {
    throw new InvalidThresholdError(`Total shares must not exceed ${MAX_SHARE_COUNT}.`);
  }
}

export function validateSingleGroupParameters(threshold: number, shareCount: number): void {
  validateShareParameters(threshold, shareCount);
  if (threshold === 1 && shareCount > 1) {
    throw new UnsupportedSlip39FeatureError(
      "SLIP-0039 requires 1-of-1 when the member threshold is 1."
    );
  }
}

export function validateIterationExponent(iterationExponent: number): void {
  if (!Number.isInteger(iterationExponent) || iterationExponent < 0 || iterationExponent > 15) {
    throw new InvalidThresholdError("Iteration exponent must be an integer from 0 to 15.");
  }
}
