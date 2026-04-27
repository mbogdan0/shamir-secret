import { DIGEST_INDEX, DIGEST_LENGTH_BYTES, SECRET_INDEX } from "./constants.js";
import { hmacSha256, randomBytes } from "./crypto.js";
import { Slip39Error } from "./errors.js";
import { interpolate } from "./gf256.js";
import { bytesEqual, concatBytes, zeroize } from "./utils.js";
import { validateShareParameters } from "./validation.js";

/**
 * @typedef {{ x: number, data: Uint8Array }} RawShare
 */

/**
 * @param {Uint8Array} randomPart
 * @param {Uint8Array} sharedSecret
 * @returns {Promise<Uint8Array>}
 */
export async function createDigest(randomPart, sharedSecret) {
  return (await hmacSha256(randomPart, sharedSecret)).slice(0, DIGEST_LENGTH_BYTES);
}

/**
 * @param {number} threshold
 * @param {number} shareCount
 * @param {Uint8Array} sharedSecret
 * @returns {Promise<RawShare[]>}
 */
export async function splitSecret(threshold, shareCount, sharedSecret) {
  validateShareParameters(threshold, shareCount);
  if (Object.prototype.toString.call(sharedSecret) !== "[object Uint8Array]") {
    throw new Slip39Error("Shared secret must be a Uint8Array.");
  }
  if (threshold > 1 && sharedSecret.length < DIGEST_LENGTH_BYTES + 1) {
    throw new Slip39Error(
      `Shared secret must be at least ${DIGEST_LENGTH_BYTES + 1} bytes when threshold > 1.`
    );
  }
  if (threshold === 1) {
    return Array.from({ length: shareCount }, (_, index) => ({
      x: index,
      data: new Uint8Array(sharedSecret)
    }));
  }

  const randomShareCount = threshold - 2;
  const shares = Array.from({ length: randomShareCount }, (_, index) => ({
    x: index,
    data: randomBytes(sharedSecret.length)
  }));

  const randomPart = randomBytes(sharedSecret.length - DIGEST_LENGTH_BYTES);
  const digest = await createDigest(randomPart, sharedSecret);
  const baseShares = [
    ...shares,
    { x: DIGEST_INDEX, data: concatBytes(digest, randomPart) },
    { x: SECRET_INDEX, data: new Uint8Array(sharedSecret) }
  ];

  for (let index = randomShareCount; index < shareCount; index += 1) {
    shares.push({ x: index, data: interpolate(baseShares, index) });
  }

  zeroize(randomPart, digest);
  return shares;
}

/**
 * @param {number} threshold
 * @param {RawShare[]} shares
 * @returns {Promise<Uint8Array>}
 */
export async function recoverSecret(threshold, shares) {
  if (threshold === 1) {
    return new Uint8Array(shares[0].data);
  }

  const sharedSecret = interpolate(shares, SECRET_INDEX);
  const digestShare = interpolate(shares, DIGEST_INDEX);
  const digest = digestShare.slice(0, DIGEST_LENGTH_BYTES);
  const randomPart = digestShare.slice(DIGEST_LENGTH_BYTES);

  if (!bytesEqual(digest, await createDigest(randomPart, sharedSecret))) {
    zeroize(digestShare, digest, randomPart, sharedSecret);
    throw new Slip39Error("Invalid digest of the shared secret.");
  }

  zeroize(digestShare, digest, randomPart);
  return sharedSecret;
}
