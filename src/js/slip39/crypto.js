import { Slip39Error } from "./errors.js";

export function requireWebCrypto() {
  const cryptoRef = globalThis.crypto;
  if (!cryptoRef?.subtle || typeof cryptoRef.getRandomValues !== "function") {
    throw new Slip39Error("Web Crypto API is unavailable in this environment.");
  }
  return cryptoRef;
}

export function hasRequiredCrypto() {
  return Boolean(
    globalThis.crypto?.subtle && typeof globalThis.crypto.getRandomValues === "function"
  );
}

export function randomBytes(length) {
  const cryptoRef = requireWebCrypto();
  const output = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    cryptoRef.getRandomValues(output.subarray(offset, Math.min(offset + 65536, length)));
  }
  return output;
}

export async function hmacSha256(keyBytes, messageBytes) {
  const cryptoRef = requireWebCrypto();
  const key = await cryptoRef.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await cryptoRef.subtle.sign("HMAC", key, messageBytes));
}

export async function sha256(messageBytes) {
  const cryptoRef = requireWebCrypto();
  return new Uint8Array(await cryptoRef.subtle.digest("SHA-256", messageBytes));
}

export async function pbkdf2Sha256(passwordBytes, saltBytes, iterations, byteLength) {
  const cryptoRef = requireWebCrypto();
  const key = await cryptoRef.subtle.importKey("raw", passwordBytes, "PBKDF2", false, [
    "deriveBits"
  ]);
  const bits = await cryptoRef.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations
    },
    key,
    byteLength * 8
  );
  return new Uint8Array(bits);
}
