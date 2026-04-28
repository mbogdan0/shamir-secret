import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TEXT_ENVELOPE_WARNING =
  "Text mode uses an app-specific envelope; hex/bytes are the canonical portable form.";

async function readProjectFile(path: string): Promise<string> {
  return readFile(resolve(projectRoot, path), "utf8");
}

function flexibleTextPattern(text: string): RegExp {
  const escapedWords = text.split(/\s+/).map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return new RegExp(escapedWords.join("\\s+"));
}

test("release notes, package metadata, and artifact hash stay in sync", async () => {
  const packageJson = JSON.parse(await readProjectFile("package.json"));
  const packageLock = JSON.parse(await readProjectFile("package-lock.json"));
  const releaseNotes = await readProjectFile("RELEASE_NOTES.md");
  const distHtml = await readProjectFile("dist/index.html");

  const latestHeading = releaseNotes.match(/^## v(\d+\.\d+\.\d+) \(/m);
  assert.ok(latestHeading, "RELEASE_NOTES.md must start with a versioned release section");
  assert.equal(latestHeading[1], packageJson.version);
  assert.equal(packageLock.packages[""].version, packageJson.version);

  const latestSectionStart = latestHeading.index ?? 0;
  const nextSectionStart = releaseNotes.indexOf("\n## v", latestSectionStart + 1);
  const latestSection = releaseNotes.slice(
    latestSectionStart,
    nextSectionStart === -1 ? undefined : nextSectionStart
  );
  const digest = createHash("sha256").update(distHtml).digest("hex");
  assert.match(latestSection, new RegExp(`SHA-256: \`${digest}\``));
});

test("security, scope, and text-envelope warnings are visible in docs and UI", async () => {
  const readme = await readProjectFile("README.md");
  const securityReview = await readProjectFile("SECURITY_REVIEW.md");
  const sourceHtml = await readProjectFile("src/index.html");

  for (const text of [readme, sourceHtml]) {
    assert.match(text, flexibleTextPattern(TEXT_ENVELOPE_WARNING));
  }

  assert.match(readme, /single-group T-of-N/i);
  assert.match(readme, /two-level group\/member scheme/i);
  assert.match(sourceHtml, /Use for real secrets\?/);
  assert.match(sourceHtml, /formal third-party cryptographic audit/);
  assert.match(sourceHtml, /high-value secrets/);

  for (const text of [readme, securityReview]) {
    assert.match(text, /not a formal third-party cryptographic audit/i);
    assert.match(text, /clipboard.*trust boundary/i);
    assert.match(text, /compromised (?:operating systems|OS|browser)/i);
    assert.match(text, /hardware-wallet or vendor/i);
  }
});
