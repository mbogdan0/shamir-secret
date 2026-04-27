import { DIGEST_INDEX, DIGEST_LENGTH_BYTES, SECRET_INDEX } from "./constants.ts";
import { hmacSha256, randomBytes } from "./crypto.ts";
import { Slip39Error } from "./errors.ts";
import { interpolate, type RawShare } from "./gf256.ts";
import { bytesEqual, concatBytes, zeroize } from "./utils.ts";
import { validateShareParameters } from "./validation.ts";

export async function createDigest(
  randomPart: Uint8Array,
  sharedSecret: Uint8Array
): Promise<Uint8Array> {
  return (await hmacSha256(randomPart, sharedSecret)).slice(0, DIGEST_LENGTH_BYTES);
}

export async function splitSecret(
  threshold: number,
  shareCount: number,
  sharedSecret: Uint8Array
): Promise<RawShare[]> {
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
  const shares: RawShare[] = Array.from({ length: randomShareCount }, (_, index) => ({
    x: index,
    data: randomBytes(sharedSecret.length)
  }));

  const randomPart = randomBytes(sharedSecret.length - DIGEST_LENGTH_BYTES);
  const digest = await createDigest(randomPart, sharedSecret);
  const baseShares: RawShare[] = [
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

export async function recoverSecret(threshold: number, shares: RawShare[]): Promise<Uint8Array> {
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
