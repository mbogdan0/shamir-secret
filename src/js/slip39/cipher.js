import {
  BASE_ITERATION_COUNT,
  CUSTOMIZATION_STRING_ORIG,
  ID_LENGTH_BITS,
  ROUND_COUNT
} from "./constants.js";
import { pbkdf2Sha256, randomBytes } from "./crypto.js";
import { Slip39Error } from "./errors.js";
import {
  asciiToBytes,
  bigIntToBytes,
  bitsToBytes,
  bytesToBigInt,
  concatBytes,
  xorBytes,
  zeroize
} from "./utils.js";

async function roundFunction(index, passphraseBytes, iterationExponent, salt, right) {
  return pbkdf2Sha256(
    concatBytes(new Uint8Array([index]), passphraseBytes),
    concatBytes(salt, right),
    (BASE_ITERATION_COUNT * 2 ** iterationExponent) / ROUND_COUNT,
    right.length
  );
}

function saltFor(identifier, extendable) {
  if (extendable) {
    return new Uint8Array();
  }
  const idBytes = bigIntToBytes(BigInt(identifier), bitsToBytes(ID_LENGTH_BITS));
  return concatBytes(asciiToBytes(CUSTOMIZATION_STRING_ORIG), idBytes);
}

export async function encrypt(
  masterSecret,
  passphraseBytes,
  iterationExponent,
  identifier,
  extendable
) {
  if (masterSecret.length % 2 !== 0) {
    throw new Slip39Error("The master secret byte length must be even.");
  }

  let left = masterSecret.slice(0, masterSecret.length / 2);
  let right = masterSecret.slice(masterSecret.length / 2);
  const salt = saltFor(identifier, extendable);

  try {
    for (let index = 0; index < ROUND_COUNT; index += 1) {
      const next = await roundFunction(index, passphraseBytes, iterationExponent, salt, right);
      const newRight = xorBytes(left, next);
      zeroize(left, next);
      left = right;
      right = newRight;
    }

    const output = concatBytes(right, left);
    return output;
  } finally {
    zeroize(left, right, salt);
  }
}

export async function decrypt(
  encryptedMasterSecret,
  passphraseBytes,
  iterationExponent,
  identifier,
  extendable
) {
  if (encryptedMasterSecret.length % 2 !== 0) {
    throw new Slip39Error("The encrypted master secret byte length must be even.");
  }

  let left = encryptedMasterSecret.slice(0, encryptedMasterSecret.length / 2);
  let right = encryptedMasterSecret.slice(encryptedMasterSecret.length / 2);
  const salt = saltFor(identifier, extendable);

  try {
    for (let index = ROUND_COUNT - 1; index >= 0; index -= 1) {
      const next = await roundFunction(index, passphraseBytes, iterationExponent, salt, right);
      const newRight = xorBytes(left, next);
      zeroize(left, next);
      left = right;
      right = newRight;
    }

    const output = concatBytes(right, left);
    return output;
  } finally {
    zeroize(left, right, salt);
  }
}

export function randomIdentifier() {
  return (
    Number(bytesToBigInt(randomBytes(bitsToBytes(ID_LENGTH_BITS)))) & ((1 << ID_LENGTH_BITS) - 1)
  );
}
