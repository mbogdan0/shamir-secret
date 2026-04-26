import { DIGEST_INDEX, DIGEST_LENGTH_BYTES, SECRET_INDEX } from "./constants.js";
import { hmacSha256, randomBytes } from "./crypto.js";
import { Slip39Error } from "./errors.js";
import { interpolate } from "./gf256.js";
import { bytesEqual, concatBytes } from "./utils.js";
import { validateShareParameters } from "./validation.js";

export async function createDigest(randomPart, sharedSecret) {
  return (await hmacSha256(randomPart, sharedSecret)).slice(0, DIGEST_LENGTH_BYTES);
}

export async function splitSecret(threshold, shareCount, sharedSecret) {
  validateShareParameters(threshold, shareCount);
  if (threshold === 1) {
    return Array.from({ length: shareCount }, (_, index) => ({ x: index, data: new Uint8Array(sharedSecret) }));
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

  return shares;
}

export async function recoverSecret(threshold, shares) {
  if (threshold === 1) {
    return new Uint8Array(shares[0].data);
  }

  const sharedSecret = interpolate(shares, SECRET_INDEX);
  const digestShare = interpolate(shares, DIGEST_INDEX);
  const digest = digestShare.slice(0, DIGEST_LENGTH_BYTES);
  const randomPart = digestShare.slice(DIGEST_LENGTH_BYTES);

  if (!bytesEqual(digest, await createDigest(randomPart, sharedSecret))) {
    throw new Slip39Error("Invalid digest of the shared secret.");
  }

  return sharedSecret;
}
