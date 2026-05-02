import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const vectorPath = resolve(projectRoot, "test", "fixtures", "slip39-vectors.json");
const hashPath = resolve(projectRoot, "test", "fixtures", "slip39-vectors.sha256");

const vectorBytes = await readFile(vectorPath);
const expectedHashLine = (await readFile(hashPath, "utf8")).trim();
const [expectedHash, expectedName] = expectedHashLine.split(/\s+/);
const actualHash = createHash("sha256").update(vectorBytes).digest("hex");
const vectors = JSON.parse(vectorBytes.toString("utf8")) as Array<
  [string, string[], string, string]
>;

assert.equal(expectedName, "slip39-vectors.json");
assert.equal(
  actualHash,
  expectedHash,
  "Official SLIP-0039 vector fixture hash changed. Update slip39-vectors.sha256 intentionally."
);
assert.equal(vectors.length, 45, "Checked-in Trezor vector fixture count changed unexpectedly.");
assert.equal(
  vectors.filter(([, , secretHex]) => secretHex).length,
  15,
  "Checked-in Trezor vector valid-case count changed unexpectedly."
);

console.log(`Verified official SLIP-0039 vector fixture hash ${actualHash}.`);
