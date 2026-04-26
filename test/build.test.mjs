import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const execFileAsync = promisify(execFile);
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("build creates a single offline HTML file", async () => {
  await execFileAsync("node", ["scripts/build.js"], { cwd: projectRoot });
  const html = await readFile(resolve(projectRoot, "dist/index.html"), "utf8");

  assert.match(html, /<style>[\s\S]*<\/style>/);
  assert.match(html, /<script\b[^>]*id=["']app-source["'][^>]*>[\s\S]*__SLIP39_APP__[\s\S]*<\/script>/);
  assert.match(html, /http-equiv=["']Content-Security-Policy["']/i);
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
