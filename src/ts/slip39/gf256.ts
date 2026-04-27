import { Slip39Error } from "./errors.ts";
import { modulo } from "./utils.ts";

export type RawShare = { x: number; data: Uint8Array };

function precomputeExpLog(): { exp: number[]; log: number[] } {
  const exp: number[] = new Array(255).fill(0);
  const log: number[] = new Array(256).fill(0);
  let poly = 1;
  for (let index = 0; index < 255; index += 1) {
    exp[index] = poly;
    log[poly] = index;
    poly = (poly << 1) ^ poly;
    if (poly & 0x100) {
      poly ^= 0x11b;
    }
  }
  return { exp, log };
}

const { exp: EXP_TABLE, log: LOG_TABLE } = precomputeExpLog();

export function gfMultiply(left: number, right: number): number {
  if (left === 0 || right === 0) {
    return 0;
  }
  return EXP_TABLE[(LOG_TABLE[left] + LOG_TABLE[right]) % 255];
}

export function interpolate(shares: RawShare[], x: number): Uint8Array {
  const seen = new Set<number>();
  const lengths = new Set<number>();
  for (const share of shares) {
    if (seen.has(share.x)) {
      throw new Slip39Error("Share indices must be unique.");
    }
    seen.add(share.x);
    lengths.add(share.data.length);
  }
  if (lengths.size !== 1) {
    throw new Slip39Error("All share values must have the same length.");
  }

  for (const share of shares) {
    if (share.x === x) {
      return new Uint8Array(share.data);
    }
  }

  const [length] = lengths;
  const logProduct = shares.reduce((sum, share) => sum + LOG_TABLE[share.x ^ x], 0);
  const result = new Uint8Array(length);

  for (const share of shares) {
    const logBasisEval = modulo(
      logProduct -
        LOG_TABLE[share.x ^ x] -
        shares.reduce((sum, other) => sum + LOG_TABLE[share.x ^ other.x], 0),
      255
    );

    for (let index = 0; index < length; index += 1) {
      const shareValue = share.data[index];
      result[index] ^=
        shareValue === 0 ? 0 : EXP_TABLE[(LOG_TABLE[shareValue] + logBasisEval) % 255];
    }
  }

  return result;
}
