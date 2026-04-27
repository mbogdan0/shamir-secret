import {
  CHECKSUM_GEN,
  CHECKSUM_LENGTH_WORDS,
  CUSTOMIZATION_STRING_EXTENDABLE,
  CUSTOMIZATION_STRING_ORIG,
  RADIX_BITS
} from "./constants.ts";
import { asciiToBytes } from "./utils.ts";

export function customizationString(extendable: boolean): string {
  return extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG;
}

export function polymod(values: number[]): number {
  let chk = 1;
  for (const value of values) {
    const b = chk >>> 20;
    chk = ((chk & 0xfffff) << RADIX_BITS) ^ value;
    for (let index = 0; index < CHECKSUM_GEN.length; index += 1) {
      if (((b >>> index) & 1) === 1) {
        chk ^= CHECKSUM_GEN[index];
      }
    }
  }
  return chk;
}

export function createChecksum(data: number[], customization: string): number[] {
  const values = [
    ...asciiToBytes(customization),
    ...data,
    ...new Array<number>(CHECKSUM_LENGTH_WORDS).fill(0)
  ];
  const checksum = polymod(values) ^ 1;
  return [2, 1, 0].map((index) => (checksum >> (RADIX_BITS * index)) & 1023);
}

export function verifyChecksum(data: number[], customization: string): boolean {
  return polymod([...asciiToBytes(customization), ...data]) === 1;
}
