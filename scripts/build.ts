import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build as viteBuild, type Rollup } from "vite";

type BuildChunk = Rollup.OutputChunk;
type BuildAsset = Rollup.OutputAsset;
type BuildOutputItem = BuildChunk | BuildAsset;

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const templatePath = resolve(projectRoot, "src/index.html");
const viteEntryPath = resolve(projectRoot, "scripts/vite-entry.ts");
const outputPath = resolve(projectRoot, "dist/index.html");
const cspPlaceholderPattern = /^([ \t]*)<!--\s*__INLINE_CSP__\s*-->/m;
export const strictCspPolicy =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
export const sourceRepositoryUrl = "https://github.com/mbogdan0/shamir-secret";
const allowedExternalNavigationUrls = new Set([sourceRepositoryUrl]);

export async function buildHtml(): Promise<string> {
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

  const buildOutputs = (Array.isArray(bundleOutput) ? bundleOutput : [bundleOutput]) as Array<{
    output?: BuildOutputItem[];
  }>;
  const outputs: BuildOutputItem[] = buildOutputs.flatMap((item) => item.output ?? []);
  return renderInlineHtml(template, outputs);
}

export function renderInlineHtml(template: string, outputs: BuildOutputItem[]): string {
  const scriptChunk = outputs.find(
    (item): item is BuildChunk => item.type === "chunk" && item.isEntry
  );
  const styleAsset = outputs.find(
    (item): item is BuildAsset =>
      item.type === "asset" && typeof item.fileName === "string" && item.fileName.endsWith(".css")
  );

  if (!scriptChunk) {
    throw new Error("Vite build output is missing the entry JavaScript chunk.");
  }

  if (!styleAsset) {
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
      (_match: string, indent: string) =>
        `${indent}<meta\n${indent}  http-equiv="Content-Security-Policy"\n${indent}  content="${strictCspPolicy}"\n${indent}/>`
    )
    .replace(styleTagPattern, `    <style>\n${css}\n</style>\n`)
    .replace(scriptTagPattern, `    <script id="app-source">\n${script}\n</script>\n`);

  verifyHtml(html);
  return html;
}

export function verifyHtml(html: string): void {
  const externalAssetPatterns = [
    /<script\b[^>]*\bsrc\s*=/i,
    /<link\b[^>]*\brel=["']?stylesheet["']?[^>]*>/i,
    /<img\b[^>]*\bsrc\s*=/i
  ];

  if (!/<style\b[^>]*>[\s\S]*<\/style>/i.test(html)) {
    throw new Error("dist/index.html must contain inline CSS.");
  }

  if (!/<script\b[^>]*id=["']app-source["'][^>]*>[\s\S]*<\/script>/i.test(html)) {
    throw new Error("dist/index.html must contain the inline app script.");
  }

  if (html.includes("__SLIP39_APP__")) {
    throw new Error("dist/index.html must not expose the global test API.");
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
  verifyExternalUrls(html);

  if (/data-inline-(?:style|script)|__INLINE_/i.test(html)) {
    throw new Error("dist/index.html contains an unreplaced build placeholder.");
  }
}

function attributeValue(tag: string, name: string): string | null {
  const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*(["'])(.*?)\\1`, "i"));
  return match?.[2] ?? null;
}

function verifyExternalUrls(html: string): void {
  const allowedAnchorHrefs = new Set<string>();
  for (const match of html.matchAll(/<a\b[^>]*>/gi)) {
    const tag = match[0];
    const href = attributeValue(tag, "href");
    if (!href || !/^https?:\/\//i.test(href)) {
      continue;
    }
    if (!allowedExternalNavigationUrls.has(href)) {
      throw new Error(`dist/index.html contains an unexpected external URL: ${href}`);
    }

    const target = attributeValue(tag, "target");
    const relTokens = new Set((attributeValue(tag, "rel") ?? "").toLowerCase().split(/\s+/));
    if (target !== "_blank" || !relTokens.has("noopener") || !relTokens.has("noreferrer")) {
      throw new Error(
        `dist/index.html external navigation link is missing safe link attributes: ${href}`
      );
    }
    allowedAnchorHrefs.add(href);
  }

  for (const match of html.matchAll(/https?:\/\/[^\s"'<>]+/gi)) {
    const url = match[0];
    if (!allowedAnchorHrefs.has(url)) {
      throw new Error(`dist/index.html contains an unexpected external URL: ${url}`);
    }
  }
}

export async function runBuildCli(argv: readonly string[] = process.argv): Promise<void> {
  const html = await buildHtml();

  if (argv.includes("--check")) {
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
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runBuildCli();
}
