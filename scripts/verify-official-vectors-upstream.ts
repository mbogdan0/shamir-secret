import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const UPSTREAM_VECTOR_URL =
  "https://raw.githubusercontent.com/trezor/python-shamir-mnemonic/master/vectors.json";
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const vectorPath = resolve(projectRoot, "test", "fixtures", "slip39-vectors.json");
const localBytes = await readFile(vectorPath);
const localVectors = JSON.parse(localBytes.toString("utf8"));
const localCanonical = JSON.stringify(localVectors);
const localHash = createHash("sha256").update(localCanonical).digest("hex");
const response = await fetch(UPSTREAM_VECTOR_URL);

assert.equal(
  response.ok,
  true,
  `Unable to fetch upstream Trezor SLIP-0039 vectors: ${response.status} ${response.statusText}`
);

const upstreamBytes = new Uint8Array(await response.arrayBuffer());
const upstreamVectors = JSON.parse(new TextDecoder().decode(upstreamBytes));
const upstreamCanonical = JSON.stringify(upstreamVectors);
const upstreamHash = createHash("sha256").update(upstreamCanonical).digest("hex");

assert.equal(
  upstreamCanonical,
  localCanonical,
  `Upstream Trezor SLIP-0039 vectors changed. Fixture update required.\nLocal: ${localHash}\nUpstream: ${upstreamHash}\nSource: ${UPSTREAM_VECTOR_URL}`
);

console.log(`Upstream Trezor SLIP-0039 vectors match local canonical hash ${localHash}.`);
