import {
  BASE_ITERATION_COUNT,
  CUSTOMIZATION_STRING_ORIG,
  ID_LENGTH_BITS,
  ROUND_COUNT
} from "./constants.ts";
import { pbkdf2Sha256, randomBytes } from "./crypto.ts";
import { Slip39Error } from "./errors.ts";
import {
  asciiToBytes,
  bigIntToBytes,
  bitsToBytes,
  bytesToBigInt,
  concatBytes,
  xorBytes,
  zeroize
} from "./utils.ts";

async function roundFunction(
  index: number,
  passphraseBytes: Uint8Array,
  iterationExponent: number,
  salt: Uint8Array,
  right: Uint8Array
): Promise<Uint8Array> {
  return pbkdf2Sha256(
    concatBytes(new Uint8Array([index]), passphraseBytes),
    concatBytes(salt, right),
    (BASE_ITERATION_COUNT * 2 ** iterationExponent) / ROUND_COUNT,
    right.length
  );
}

function saltFor(identifier: number, extendable: boolean): Uint8Array {
  if (extendable) {
    return new Uint8Array();
  }
  const idBytes = bigIntToBytes(BigInt(identifier), bitsToBytes(ID_LENGTH_BITS));
  return concatBytes(asciiToBytes(CUSTOMIZATION_STRING_ORIG), idBytes);
}

export async function encrypt(
  masterSecret: Uint8Array,
  passphraseBytes: Uint8Array,
  iterationExponent: number,
  identifier: number,
  extendable: boolean
): Promise<Uint8Array> {
  if (masterSecret.length % 2 !== 0) {
    throw new Slip39Error("The master secret byte length must be even.");
  }

  let left: Uint8Array = masterSecret.slice(0, masterSecret.length / 2);
  let right: Uint8Array = masterSecret.slice(masterSecret.length / 2);
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
  encryptedMasterSecret: Uint8Array,
  passphraseBytes: Uint8Array,
  iterationExponent: number,
  identifier: number,
  extendable: boolean
): Promise<Uint8Array> {
  if (encryptedMasterSecret.length % 2 !== 0) {
    throw new Slip39Error("The encrypted master secret byte length must be even.");
  }

  let left: Uint8Array = encryptedMasterSecret.slice(0, encryptedMasterSecret.length / 2);
  let right: Uint8Array = encryptedMasterSecret.slice(encryptedMasterSecret.length / 2);
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

export function randomIdentifier(): number {
  return (
    Number(bytesToBigInt(randomBytes(bitsToBytes(ID_LENGTH_BITS)))) & ((1 << ID_LENGTH_BITS) - 1)
  );
}
