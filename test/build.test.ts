import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { renderInlineHtml, runBuildCli, strictCspPolicy, verifyHtml } from "../scripts/build.ts";

const execFileAsync = promisify(execFile);
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const VALID_TEMPLATE = `
<!doctype html>
<html>
  <head>
    <!-- __INLINE_CSP__ -->
    <link rel="stylesheet" href="./styles.css" data-inline-style />
  </head>
  <body>
    <script data-inline-script></script>
  </body>
</html>`;
const VALID_OUTPUTS = [
  {
    type: "chunk",
    isEntry: true,
    code: "globalThis.__SLIP39_APP__ = { marker: '</script>' };"
  },
  {
    type: "asset",
    fileName: "style.css",
    source: "body::before { content: '</style>'; }"
  }
] as unknown as Parameters<typeof renderInlineHtml>[1];

function validBuiltHtml(): string {
  return renderInlineHtml(VALID_TEMPLATE, [...VALID_OUTPUTS]);
}

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

test("build check mode verifies the committed artifact", async () => {
  await runBuildCli(["node", "scripts/build.ts", "--check"]);
});

test("build write mode writes the offline artifact through the CLI helper", async () => {
  await runBuildCli(["node", "scripts/build.ts"]);
  const html = await readFile(resolve(projectRoot, "dist/index.html"), "utf8");

  assert.match(html, /<script\b[^>]*id=["']app-source["'][^>]*>/);
});

test("inline HTML rendering escapes closing inline tags", () => {
  const html = validBuiltHtml();

  assert.match(html, /<style>[\s\S]*<\\\/style>[\s\S]*<\/style>/);
  assert.match(html, /<script id="app-source">[\s\S]*<\\\/script>[\s\S]*<\/script>/);
  assert.match(html, new RegExp(strictCspPolicy.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("inline HTML rendering requires build outputs and source placeholders", () => {
  assert.throws(
    () =>
      renderInlineHtml(
        VALID_TEMPLATE,
        VALID_OUTPUTS.filter((item) => item.type !== "chunk")
      ),
    /missing the entry JavaScript chunk/
  );
  assert.throws(
    () =>
      renderInlineHtml(
        VALID_TEMPLATE,
        VALID_OUTPUTS.filter((item) => item.type !== "asset")
      ),
    /missing the CSS asset/
  );
  assert.throws(
    () => renderInlineHtml(VALID_TEMPLATE.replace("data-inline-style", ""), [...VALID_OUTPUTS]),
    /data-inline-style/
  );
  assert.throws(
    () => renderInlineHtml(VALID_TEMPLATE.replace("data-inline-script", ""), [...VALID_OUTPUTS]),
    /data-inline-script/
  );
  assert.throws(
    () =>
      renderInlineHtml(VALID_TEMPLATE.replace("<!-- __INLINE_CSP__ -->", ""), [...VALID_OUTPUTS]),
    /__INLINE_CSP__/
  );
});

test("offline HTML verification rejects missing or external runtime content", () => {
  const html = validBuiltHtml();
  const cases: Array<[string, RegExp]> = [
    [html.replace(/<style>[\s\S]*?<\/style>/, ""), /inline CSS/],
    [html.replace(/<script id="app-source">[\s\S]*?<\/script>/, ""), /inline app script/],
    [
      html.replace(/http-equiv="Content-Security-Policy"/, 'name="not-csp"'),
      /Content-Security-Policy/
    ],
    [html.replace(strictCspPolicy, "default-src 'self'"), /strict offline CSP/],
    [html.replace("</head>", '<script src="app.js"></script></head>'), /external runtime asset/],
    [
      html.replace("</head>", '<link rel="stylesheet" href="style.css"></head>'),
      /external runtime asset/
    ],
    [html.replace("</body>", '<img src="logo.png"></body>'), /external runtime asset/],
    [
      html.replace("</body>", '<a href="https://example.invalid">x</a></body>'),
      /external runtime asset/
    ],
    [html.replace("</body>", "<!-- __INLINE_CSP__ --></body>"), /unreplaced build placeholder/]
  ];

  for (const [invalidHtml, expectedMessage] of cases) {
    assert.throws(() => verifyHtml(invalidHtml), expectedMessage);
  }
});
