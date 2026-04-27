import { RADIX_BITS } from "./constants.js";
import { Slip39Error } from "./errors.js";
import { SLIP39_WORDS, WORD_INDEX } from "./wordlist.js";

export function bitsToWords(bitLength) {
  return Math.ceil(bitLength / RADIX_BITS);
}

export function bitsToBytes(bitLength) {
  return Math.ceil(bitLength / 8);
}

export function modulo(value, divisor) {
  return ((value % divisor) + divisor) % divisor;
}

export function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) {
    diff |= a[index] ^ b[index];
  }
  return diff === 0;
}

export function xorBytes(a, b) {
  const length = Math.min(a.length, b.length);
  const output = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    output[index] = a[index] ^ b[index];
  }
  return output;
}

export function asciiToBytes(value) {
  const output = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    output[index] = value.charCodeAt(index);
  }
  return output;
}

export function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

export function bigIntToBytes(value, length) {
  const output = new Uint8Array(length);
  let current = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    output[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  if (current !== 0n) {
    throw new Slip39Error("Invalid mnemonic padding.");
  }
  return output;
}

export function intToIndices(value, length, radixBits = RADIX_BITS) {
  const output = new Array(length);
  const mask = (1n << BigInt(radixBits)) - 1n;
  let current = BigInt(value);
  for (let index = length - 1; index >= 0; index -= 1) {
    output[index] = Number(current & mask);
    current >>= BigInt(radixBits);
  }
  if (current !== 0n) {
    throw new Slip39Error("Integer does not fit in the requested word count.");
  }
  return output;
}

export function intFromIndices(indices, radixBits = RADIX_BITS) {
  let value = 0n;
  for (const index of indices) {
    if (!Number.isInteger(index) || index < 0 || index >= 1 << radixBits) {
      throw new Slip39Error("Invalid word index.");
    }
    value = (value << BigInt(radixBits)) | BigInt(index);
  }
  return value;
}

export function bytesToIndices(bytes, length) {
  return intToIndices(bytesToBigInt(bytes), length, RADIX_BITS);
}

export function indicesToWords(indices) {
  return indices.map((index) => SLIP39_WORDS[index]);
}

export function mnemonicToIndices(mnemonic) {
  const words = mnemonic.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) {
    throw new Slip39Error("The mnemonic is empty.");
  }
  return words.map((word) => {
    const index = WORD_INDEX.get(word);
    if (index === undefined) {
      throw new Slip39Error(`Unknown SLIP-0039 word: "${word}".`);
    }
    return index;
  });
}
