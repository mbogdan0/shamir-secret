import {
  CHECKSUM_GEN,
  CHECKSUM_LENGTH_WORDS,
  CUSTOMIZATION_STRING_EXTENDABLE,
  CUSTOMIZATION_STRING_ORIG,
  RADIX_BITS
} from "./constants.js";
import { asciiToBytes } from "./utils.js";

/**
 * @param {boolean} extendable
 * @returns {string}
 */
export function customizationString(extendable) {
  return extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG;
}

/**
 * @param {number[]} values
 * @returns {number}
 */
export function polymod(values) {
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

/**
 * @param {number[]} data
 * @param {string} customization
 * @returns {number[]}
 */
export function createChecksum(data, customization) {
  const values = [
    ...asciiToBytes(customization),
    ...data,
    ...new Array(CHECKSUM_LENGTH_WORDS).fill(0)
  ];
  const checksum = polymod(values) ^ 1;
  return [2, 1, 0].map((index) => (checksum >> (RADIX_BITS * index)) & 1023);
}

/**
 * @param {number[]} data
 * @param {string} customization
 * @returns {boolean}
 */
export function verifyChecksum(data, customization) {
  return polymod([...asciiToBytes(customization), ...data]) === 1;
}
