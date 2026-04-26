import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const templatePath = resolve(projectRoot, "src/index.html");
const stylesPath = resolve(projectRoot, "src/styles.css");
const appEntryPath = resolve(projectRoot, "src/js/app.js");

const [template, styles, bundle] = await Promise.all([
  readFile(templatePath, "utf8"),
  readFile(stylesPath, "utf8"),
  esbuild.build({
    entryPoints: [appEntryPath],
    bundle: true,
    charset: "utf8",
    format: "iife",
    legalComments: "none",
    minify: false,
    platform: "browser",
    sourcemap: false,
    target: "es2022",
    write: false
  })
]);

const script = bundle.outputFiles[0].text
  .replaceAll("</script", "<\\/script")
  .trimEnd();
const css = styles
  .replaceAll("</style", "<\\/style")
  .trimEnd();

const styleTagPattern = /[ \t]*<link\b(?=[^>]*\bdata-inline-style\b)[^>]*>\s*/i;
const scriptTagPattern = /[ \t]*<script\b(?=[^>]*\bdata-inline-script\b)[^>]*>\s*<\/script>\s*/i;

if (!styleTagPattern.test(template)) {
  throw new Error("src/index.html must contain a data-inline-style stylesheet tag.");
}

if (!scriptTagPattern.test(template)) {
  throw new Error("src/index.html must contain a data-inline-script app tag.");
}

const html = template
  .replace(styleTagPattern, `    <style>\n${css}\n</style>\n`)
  .replace(scriptTagPattern, `    <script id="app-source">\n${script}\n</script>\n`);

const externalAssetPatterns = [
  /<script\b[^>]*\bsrc\s*=/i,
  /<link\b[^>]*\brel=["']?stylesheet["']?[^>]*>/i,
  /<img\b[^>]*\bsrc\s*=/i,
  /https?:\/\//i
];

if (!/<style\b[^>]*>[\s\S]*<\/style>/i.test(html)) {
  throw new Error("dist/index.html must contain inline CSS.");
}

if (!/<script\b[^>]*>[\s\S]*__SLIP39_APP__[\s\S]*<\/script>/i.test(html)) {
  throw new Error("dist/index.html must contain the inline app script.");
}

for (const pattern of externalAssetPatterns) {
  if (pattern.test(html)) {
    throw new Error(`dist/index.html contains an external runtime asset: ${pattern}`);
  }
}

if (/data-inline-(?:style|script)|__INLINE_/i.test(html)) {
  throw new Error("dist/index.html contains an unreplaced build placeholder.");
}

const outputPath = resolve(projectRoot, "dist/index.html");
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, html);

console.log(`Built ${outputPath}`);
