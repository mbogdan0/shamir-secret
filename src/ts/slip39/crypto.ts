import { Slip39Error } from "./errors.ts";

function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export function requireWebCrypto(): Crypto {
  const cryptoRef = globalThis.crypto;
  if (!cryptoRef?.subtle || typeof cryptoRef.getRandomValues !== "function") {
    throw new Slip39Error("Web Crypto API is unavailable in this environment.");
  }
  return cryptoRef;
}

export function hasRequiredCrypto(): boolean {
  return Boolean(
    globalThis.crypto?.subtle && typeof globalThis.crypto.getRandomValues === "function"
  );
}

export function randomBytes(length: number): Uint8Array {
  const cryptoRef = requireWebCrypto();
  const output = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    cryptoRef.getRandomValues(output.subarray(offset, Math.min(offset + 65536, length)));
  }
  return output;
}

export async function hmacSha256(
  keyBytes: Uint8Array,
  messageBytes: Uint8Array
): Promise<Uint8Array> {
  const cryptoRef = requireWebCrypto();
  const key = await cryptoRef.subtle.importKey(
    "raw",
    asBufferSource(keyBytes),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await cryptoRef.subtle.sign("HMAC", key, asBufferSource(messageBytes)));
}

export async function sha256(messageBytes: Uint8Array): Promise<Uint8Array> {
  const cryptoRef = requireWebCrypto();
  return new Uint8Array(await cryptoRef.subtle.digest("SHA-256", asBufferSource(messageBytes)));
}

export async function pbkdf2Sha256(
  passwordBytes: Uint8Array,
  saltBytes: Uint8Array,
  iterations: number,
  byteLength: number
): Promise<Uint8Array> {
  const cryptoRef = requireWebCrypto();
  const key = await cryptoRef.subtle.importKey(
    "raw",
    asBufferSource(passwordBytes),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await cryptoRef.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: asBufferSource(saltBytes),
      iterations
    },
    key,
    byteLength * 8
  );
  return new Uint8Array(bits);
}
