import { RADIX_BITS } from "./constants.ts";
import { MalformedMnemonicError } from "./errors.ts";
import { SLIP39_WORDS, WORD_INDEX } from "./wordlist.ts";

export function bitsToWords(bitLength: number): number {
  return Math.ceil(bitLength / RADIX_BITS);
}

export function bitsToBytes(bitLength: number): number {
  return Math.ceil(bitLength / 8);
}

export function modulo(value: number, divisor: number): number {
  return ((value % divisor) + divisor) % divisor;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) {
    diff |= a[index] ^ b[index];
  }
  return diff === 0;
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const length = Math.min(a.length, b.length);
  const output = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    output[index] = a[index] ^ b[index];
  }
  return output;
}

export function zeroize(...buffers: Array<Uint8Array | undefined | null>): void {
  for (const buffer of buffers) {
    if (buffer && typeof buffer.fill === "function") {
      buffer.fill(0);
    }
  }
}

export function asciiToBytes(value: string): Uint8Array {
  const output = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    output[index] = value.charCodeAt(index);
  }
  return output;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

export function bigIntToBytes(value: bigint | number, length: number): Uint8Array {
  const output = new Uint8Array(length);
  let current = BigInt(value);
  for (let index = length - 1; index >= 0; index -= 1) {
    output[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  if (current !== 0n) {
    throw new MalformedMnemonicError("Invalid mnemonic padding.");
  }
  return output;
}

export function intToIndices(
  value: bigint | number,
  length: number,
  radixBits: number = RADIX_BITS
): number[] {
  const output: number[] = new Array(length);
  const mask = (1n << BigInt(radixBits)) - 1n;
  let current = BigInt(value);
  for (let index = length - 1; index >= 0; index -= 1) {
    output[index] = Number(current & mask);
    current >>= BigInt(radixBits);
  }
  if (current !== 0n) {
    throw new MalformedMnemonicError("Integer does not fit in the requested word count.");
  }
  return output;
}

export function intFromIndices(indices: number[], radixBits: number = RADIX_BITS): bigint {
  let value = 0n;
  for (const index of indices) {
    if (!Number.isInteger(index) || index < 0 || index >= 1 << radixBits) {
      throw new MalformedMnemonicError("Invalid word index.");
    }
    value = (value << BigInt(radixBits)) | BigInt(index);
  }
  return value;
}

export function bytesToIndices(bytes: Uint8Array, length: number): number[] {
  return intToIndices(bytesToBigInt(bytes), length, RADIX_BITS);
}

export function indicesToWords(indices: number[]): string[] {
  return indices.map((index) => SLIP39_WORDS[index]);
}

export function mnemonicToIndices(mnemonic: string): number[] {
  const words = mnemonic.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) {
    throw new MalformedMnemonicError("The mnemonic is empty.");
  }
  return words.map((word) => {
    const index = WORD_INDEX.get(word);
    if (index === undefined) {
      throw new MalformedMnemonicError(`Unknown SLIP-0039 word: "${word}".`);
    }
    return index;
  });
}
