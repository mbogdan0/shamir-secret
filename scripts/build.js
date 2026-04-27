import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build as viteBuild } from "vite";

/**
 * @typedef {{ type: "chunk", isEntry?: boolean, code: string, fileName?: string }} BuildChunk
 * @typedef {{ type: "asset", fileName?: string, source: string | Uint8Array }} BuildAsset
 * @typedef {BuildChunk | BuildAsset} BuildOutputItem
 */

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const templatePath = resolve(projectRoot, "src/index.html");
const viteEntryPath = resolve(projectRoot, "scripts/vite-entry.js");
const outputPath = resolve(projectRoot, "dist/index.html");
const checkMode = process.argv.includes("--check");
const cspPlaceholderPattern = /^([ \t]*)<!--\s*__INLINE_CSP__\s*-->/m;
const strictCspPolicy =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

async function buildHtml() {
  const template = await readFile(templatePath, "utf8");
  const bundleOutput = await viteBuild({
    configFile: false,
    root: projectRoot,
    publicDir: false,
    logLevel: "silent",
    build: {
      write: false,
      target: "es2022",
      minify: false,
      cssMinify: false,
      sourcemap: false,
      cssCodeSplit: false,
      lib: {
        entry: viteEntryPath,
        formats: ["iife"],
        name: "SLIP39AppBundle",
        fileName: () => "app.js"
      }
    }
  });

  const buildOutputs = /** @type {{ output?: BuildOutputItem[] }[]} */ (
    /** @type {unknown} */ (Array.isArray(bundleOutput) ? bundleOutput : [bundleOutput])
  );
  const outputs = buildOutputs.flatMap((item) => item.output ?? []);

  const scriptChunk = outputs.find((item) => item.type === "chunk" && item.isEntry);
  const styleAsset = outputs.find(
    (item) =>
      item.type === "asset" && typeof item.fileName === "string" && item.fileName.endsWith(".css")
  );

  if (!scriptChunk || scriptChunk.type !== "chunk") {
    throw new Error("Vite build output is missing the entry JavaScript chunk.");
  }

  if (!styleAsset || styleAsset.type !== "asset") {
    throw new Error("Vite build output is missing the CSS asset.");
  }

  const script = scriptChunk.code.replaceAll("</script", "<\\/script").trimEnd();
  const css = String(styleAsset.source).replaceAll("</style", "<\\/style").trimEnd();

  const styleTagPattern = /[ \t]*<link\b(?=[^>]*\bdata-inline-style\b)[^>]*>\s*/i;
  const scriptTagPattern = /[ \t]*<script\b(?=[^>]*\bdata-inline-script\b)[^>]*>\s*<\/script>\s*/i;

  if (!styleTagPattern.test(template)) {
    throw new Error("src/index.html must contain a data-inline-style stylesheet tag.");
  }

  if (!scriptTagPattern.test(template)) {
    throw new Error("src/index.html must contain a data-inline-script app tag.");
  }

  if (!cspPlaceholderPattern.test(template)) {
    throw new Error("src/index.html must contain the __INLINE_CSP__ placeholder comment.");
  }

  const html = template
    .replace(
      cspPlaceholderPattern,
      /**
       * @param {string} _match
       * @param {string} indent
       */
      (_match, indent) =>
        `${indent}<meta\n${indent}  http-equiv="Content-Security-Policy"\n${indent}  content="${strictCspPolicy}"\n${indent}/>`
    )
    .replace(styleTagPattern, `    <style>\n${css}\n</style>\n`)
    .replace(scriptTagPattern, `    <script id="app-source">\n${script}\n</script>\n`);

  verifyHtml(html);
  return html;
}

/**
 * @param {string} html
 */
function verifyHtml(html) {
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

  if (!/http-equiv=["']Content-Security-Policy["']/i.test(html)) {
    throw new Error("dist/index.html must contain a Content-Security-Policy meta tag.");
  }

  if (!html.includes(strictCspPolicy)) {
    throw new Error("dist/index.html must contain the strict offline CSP policy.");
  }

  for (const pattern of externalAssetPatterns) {
    if (pattern.test(html)) {
      throw new Error(`dist/index.html contains an external runtime asset: ${pattern}`);
    }
  }

  if (/data-inline-(?:style|script)|__INLINE_/i.test(html)) {
    throw new Error("dist/index.html contains an unreplaced build placeholder.");
  }
}

const html = await buildHtml();

if (checkMode) {
  const existingHtml = await readFile(outputPath, "utf8");
  if (existingHtml !== html) {
    throw new Error("dist/index.html is out of date. Run `npm run build` and commit the result.");
  }
  console.log(`Verified ${outputPath}`);
} else {
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, html);
  console.log(`Built ${outputPath}`);
}
