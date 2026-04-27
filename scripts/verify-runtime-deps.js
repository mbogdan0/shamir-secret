import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJsonPath = resolve(projectRoot, "package.json");
const packageLockPath = resolve(projectRoot, "package-lock.json");

/**
 * @param {string} path
 * @returns {Promise<Record<string, unknown>>}
 */
async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

/**
 * @param {unknown} value
 * @returns {Record<string, unknown>}
 */
function asRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? /** @type {Record<string, unknown>} */ (value)
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
