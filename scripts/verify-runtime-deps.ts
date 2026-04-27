import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJsonPath = resolve(projectRoot, "package.json");
const packageLockPath = resolve(projectRoot, "package-lock.json");

async function readJson(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

const packageJson = await readJson(packageJsonPath);
const packageLock = await readJson(packageLockPath);
const dependencies = asRecord(packageJson.dependencies);
const lockRoot = asRecord(asRecord(packageLock.packages)[""]);
const lockRootDependencies = asRecord(lockRoot.dependencies);

if (Object.keys(dependencies).length > 0) {
  throw new Error(
    `Runtime dependencies are not allowed. Found in package.json: ${Object.keys(dependencies).join(", ")}`
  );
}

if (Object.keys(lockRootDependencies).length > 0) {
  throw new Error(
    `Runtime dependencies are not allowed. Found in package-lock.json root: ${Object.keys(lockRootDependencies).join(", ")}`
  );
}

console.log("Verified zero runtime npm dependencies.");
