import { readdir, readFile } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtimeRoot = resolve(projectRoot, "src/ts");

const forbiddenPatterns: Array<{ name: string; pattern: RegExp }> = [
  { name: "dynamic HTML sink", pattern: /\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b/ },
  { name: "eval", pattern: /\beval\s*\(/ },
  { name: "Function constructor", pattern: /\bnew\s+Function\b/ },
  { name: "browser storage", pattern: /\b(?:localStorage|sessionStorage|indexedDB)\b/ },
  { name: "cookie access", pattern: /\bdocument\.cookie\b/ },
  { name: "network API", pattern: /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\b/ },
  { name: "non-cryptographic randomness", pattern: /\bMath\.random\b/ }
];

async function listTypeScriptFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        return listTypeScriptFiles(path);
      }
      return extname(entry.name) === ".ts" ? [path] : [];
    })
  );
  return files.flat();
}

function findBareRuntimeImports(text: string): string[] {
  const violations: string[] = [];
  const importPatterns = [
    /(?:^|\n)\s*import\s+(?:[^"'()]+?\s+from\s+)?["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g
  ];

  for (const pattern of importPatterns) {
    for (const match of text.matchAll(pattern)) {
      const specifier = match[1];
      if (!specifier.startsWith("./") && !specifier.startsWith("../")) {
        violations.push(specifier);
      }
    }
  }
  return violations;
}

const violations: string[] = [];
for (const file of await listTypeScriptFiles(runtimeRoot)) {
  const text = await readFile(file, "utf8");
  const displayPath = relative(projectRoot, file);

  for (const specifier of findBareRuntimeImports(text)) {
    violations.push(`${displayPath}: runtime bare import "${specifier}"`);
  }

  for (const { name, pattern } of forbiddenPatterns) {
    if (pattern.test(text)) {
      violations.push(`${displayPath}: forbidden ${name}`);
    }
  }
}

if (violations.length > 0) {
  throw new Error(
    `Source policy violations:\n${violations.map((item) => `  - ${item}`).join("\n")}`
  );
}

console.log("Verified runtime source policy.");
