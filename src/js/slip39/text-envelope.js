import { sha256 } from "./crypto.js";
import { Slip39Error } from "./errors.js";
import { bytesEqual, concatBytes } from "./utils.js";
import { validateMasterSecretBytes } from "./validation.js";

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true });
const TEXT_MASTER_SECRET_MAGIC = Uint8Array.from("SLIP39TXT", (char) => char.charCodeAt(0));
const TEXT_MASTER_SECRET_VERSION = 1;
const VERSION_OFFSET = TEXT_MASTER_SECRET_MAGIC.length;
const LENGTH_OFFSET = VERSION_OFFSET + 1;
const TAG_OFFSET = LENGTH_OFFSET + 4;
const TAG_LENGTH = 16;
const PAYLOAD_OFFSET = TAG_OFFSET + TAG_LENGTH;
const MAX_UINT32 = 0xffffffff;

function ensureText(value) {
  if (typeof value !== "string") {
    throw new Slip39Error("The text master secret must be a string.");
  }
}

function writeUint32BigEndian(output, offset, value) {
  output[offset] = (value >>> 24) & 0xff;
  output[offset + 1] = (value >>> 16) & 0xff;
  output[offset + 2] = (value >>> 8) & 0xff;
  output[offset + 3] = value & 0xff;
}

function readUint32BigEndian(input, offset) {
  return (
    input[offset] * 0x1000000 +
    (input[offset + 1] << 16) +
    (input[offset + 2] << 8) +
    input[offset + 3]
  );
}

function getPaddingLength(payloadLength) {
  return payloadLength % 2;
}

function hasMagic(bytes) {
  if (Object.prototype.toString.call(bytes) !== "[object Uint8Array]") {
    return false;
  }
  if (bytes.length < TEXT_MASTER_SECRET_MAGIC.length) {
    return false;
  }
  for (let index = 0; index < TEXT_MASTER_SECRET_MAGIC.length; index += 1) {
    if (bytes[index] !== TEXT_MASTER_SECRET_MAGIC[index]) {
      return false;
    }
  }
  return true;
}

async function computeEnvelopeTag(bytes) {
  const buffer = new Uint8Array(bytes);
  buffer.fill(0, TAG_OFFSET, TAG_OFFSET + TAG_LENGTH);
  const digest = await sha256(buffer);
  return digest.subarray(0, TAG_LENGTH);
}

async function parseTextMasterSecretEnvelope(bytes) {
  if (!hasMagic(bytes) || bytes.length < PAYLOAD_OFFSET) {
    return null;
  }
  if (bytes[VERSION_OFFSET] !== TEXT_MASTER_SECRET_VERSION) {
    return null;
  }

  const utf8ByteLength = readUint32BigEndian(bytes, LENGTH_OFFSET);
  const payloadEnd = PAYLOAD_OFFSET + utf8ByteLength;
  if (!Number.isSafeInteger(payloadEnd) || payloadEnd > bytes.length) {
    return null;
  }

  const paddingByteLength = bytes.length - payloadEnd;
  if (paddingByteLength !== getPaddingLength(utf8ByteLength)) {
    return null;
  }

  const expectedTag = await computeEnvelopeTag(bytes);
  const actualTag = bytes.subarray(TAG_OFFSET, TAG_OFFSET + TAG_LENGTH);
  if (!bytesEqual(expectedTag, actualTag)) {
    return null;
  }

  try {
    return {
      text: TEXT_DECODER.decode(bytes.subarray(PAYLOAD_OFFSET, payloadEnd)),
      utf8ByteLength,
      masterSecretByteLength: bytes.length,
      paddingByteLength
    };
  } catch {
    return null;
  }
}

export function describeTextMasterSecret(text) {
  ensureText(text);
  const utf8ByteLength = TEXT_ENCODER.encode(text).length;
  if (utf8ByteLength > MAX_UINT32) {
    throw new Slip39Error("The text is too large for the SLIP39TXT v1 envelope.");
  }
  const paddingByteLength = getPaddingLength(utf8ByteLength);
  return {
    utf8ByteLength,
    masterSecretByteLength: PAYLOAD_OFFSET + utf8ByteLength + paddingByteLength,
    paddingByteLength
  };
}

export async function encodeTextMasterSecret(text) {
  ensureText(text);
  const payload = TEXT_ENCODER.encode(text);
  if (payload.length > MAX_UINT32) {
    throw new Slip39Error("The text is too large for the SLIP39TXT v1 envelope.");
  }

  const header = new Uint8Array(PAYLOAD_OFFSET);
  header.set(TEXT_MASTER_SECRET_MAGIC);
  header[VERSION_OFFSET] = TEXT_MASTER_SECRET_VERSION;
  writeUint32BigEndian(header, LENGTH_OFFSET, payload.length);

  const paddingByteLength = getPaddingLength(payload.length);
  const padding = paddingByteLength === 0 ? new Uint8Array() : new Uint8Array(paddingByteLength);
  const output = concatBytes(header, payload, padding);
  const tag = await computeEnvelopeTag(output);
  output.set(tag, TAG_OFFSET);
  validateMasterSecretBytes(output);
  return output;
}

export async function decodeTextMasterSecret(bytes) {
  return (await parseTextMasterSecretEnvelope(bytes))?.text ?? null;
}

export async function isTextMasterSecretEnvelope(bytes) {
  return (await parseTextMasterSecretEnvelope(bytes)) !== null;
}
