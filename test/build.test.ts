import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const execFileAsync = promisify(execFile);
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const strictCspPolicy =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

test("source template stays dev-friendly and keeps build CSP placeholder", async () => {
  const template = await readFile(resolve(projectRoot, "src/index.html"), "utf8");

  assert.match(template, /<!--\s*__INLINE_CSP__\s*-->/);
  assert.doesNotMatch(template, /http-equiv=["']Content-Security-Policy["']/i);
  assert.doesNotMatch(template, /default-src 'none'/);
});

test("build creates a single offline HTML file", async () => {
  await execFileAsync("node", ["--experimental-strip-types", "scripts/build.ts"], {
    cwd: projectRoot
  });
  const html = await readFile(resolve(projectRoot, "dist/index.html"), "utf8");

  assert.match(html, /<style>[\s\S]*<\/style>/);
  assert.match(
    html,
    /<script\b[^>]*id=["']app-source["'][^>]*>[\s\S]*__SLIP39_APP__[\s\S]*<\/script>/
  );
  assert.match(html, /http-equiv=["']Content-Security-Policy["']/i);
  assert.match(html, new RegExp(strictCspPolicy.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(html, /default-src 'none'/);
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /base-uri 'none'/);
  assert.match(html, /form-action 'none'/);
  assert.doesNotMatch(html, /<script[^>]+\ssrc=/i);
  assert.doesNotMatch(html, /<script[^>]+\stype=["']module["']/i);
  assert.doesNotMatch(html, /<link[^>]+rel=["']stylesheet["']/i);
  assert.doesNotMatch(html, /https?:\/\//i);
  assert.doesNotMatch(html, /data-inline-(?:style|script)|__INLINE_/i);
  assert.doesNotMatch(html, /\b(?:localStorage|sessionStorage|indexedDB)\b|document\.cookie/);
  assert.doesNotMatch(html, /autocomplete=["'](?:current-password|new-password)["']/i);
  assert.equal(new URL(`file://${resolve(projectRoot, "dist/index.html")}`).protocol, "file:");
});
