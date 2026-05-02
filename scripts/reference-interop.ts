import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  bytesToHex,
  combineMnemonics,
  generateMnemonics,
  hexToBytes
} from "../src/ts/slip39/index.ts";

type InteropCase = {
  name: string;
  threshold: number;
  shareCount: number;
  secretHex: string;
  passphrase: string;
  iterationExponent: number;
  extendable: boolean;
};

type PythonGenerated = {
  mnemonics: string[];
  parsedCount: number;
  recoveredHex: string;
};

type PythonRecovered = {
  parsedCount: number;
  recoveredHex: string;
};

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pythonCommand = process.env.PYTHON ?? "python3";
const officialVectorPath = resolve(projectRoot, "test", "fixtures", "slip39-vectors.json");
const pythonGenerateScript = `
import json
import sys
from shamir_mnemonic import Share, combine_mnemonics, generate_mnemonics

data = json.load(sys.stdin)
passphrase = data["passphrase"].encode("ascii")
grouped = generate_mnemonics(
    1,
    [(data["threshold"], data["shareCount"])],
    bytes.fromhex(data["secretHex"]),
    passphrase,
    extendable=data["extendable"],
    iteration_exponent=data["iterationExponent"],
)
mnemonics = [mnemonic for group in grouped for mnemonic in group]
parsed = [Share.from_mnemonic(mnemonic) for mnemonic in mnemonics]
recovered = combine_mnemonics(mnemonics[: data["threshold"]], passphrase)
print(json.dumps({
    "mnemonics": mnemonics,
    "parsedCount": len(parsed),
    "recoveredHex": recovered.hex(),
}))
`;
const pythonRecoverScript = `
import json
import sys
from shamir_mnemonic import Share, combine_mnemonics

data = json.load(sys.stdin)
passphrase = data["passphrase"].encode("ascii")
parsed = [Share.from_mnemonic(mnemonic) for mnemonic in data["allMnemonics"]]
recovered = combine_mnemonics(data["mnemonics"], passphrase)
print(json.dumps({
    "parsedCount": len(parsed),
    "recoveredHex": recovered.hex(),
}))
`;

const cases: InteropCase[] = [
  {
    name: "1-of-1 128-bit empty passphrase",
    threshold: 1,
    shareCount: 1,
    secretHex: "000102030405060708090a0b0c0d0e0f",
    passphrase: "",
    iterationExponent: 0,
    extendable: true
  },
  {
    name: "2-of-3 128-bit ASCII passphrase",
    threshold: 2,
    shareCount: 3,
    secretHex: "f0e0d0c0b0a090807060504030201000",
    passphrase: "printable ASCII passphrase",
    iterationExponent: 0,
    extendable: true
  },
  {
    name: "3-of-5 256-bit empty passphrase",
    threshold: 3,
    shareCount: 5,
    secretHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    passphrase: "",
    iterationExponent: 0,
    extendable: false
  },
  {
    name: "16-of-16 256-bit ASCII passphrase",
    threshold: 16,
    shareCount: 16,
    secretHex: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f",
    passphrase: "spaces and symbols !@#",
    iterationExponent: 0,
    extendable: true
  }
];

Object.defineProperty(globalThis, "crypto", {
  configurable: true,
  value: webcrypto
});

function runPython<T>(script: string, input: unknown): Promise<T> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(pythonCommand, ["-c", script], {
      cwd: projectRoot,
      stdio: ["pipe", "pipe", "pipe"]
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];

    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      const stderrText = Buffer.concat(stderr).toString("utf8");
      const stdoutText = Buffer.concat(stdout).toString("utf8");
      if (code !== 0) {
        reject(
          new Error(
            `Python reference command failed with exit code ${code}.\n` +
              `Install requirements with: python3 -m pip install -r requirements-dev.txt\n` +
              stderrText
          )
        );
        return;
      }
      try {
        resolvePromise(JSON.parse(stdoutText) as T);
      } catch (error) {
        reject(
          new Error(`Python reference returned invalid JSON.\n${stdoutText}\n${String(error)}`)
        );
      }
    });

    child.stdin.end(JSON.stringify(input));
  });
}

async function verifyLocalToReference(testCase: InteropCase): Promise<void> {
  const mnemonics = await generateMnemonics(
    testCase.threshold,
    testCase.shareCount,
    hexToBytes(testCase.secretHex),
    testCase.passphrase,
    {
      extendable: testCase.extendable,
      iterationExponent: testCase.iterationExponent
    }
  );
  const recovered = await runPython<PythonRecovered>(pythonRecoverScript, {
    allMnemonics: mnemonics,
    mnemonics: mnemonics.slice(0, testCase.threshold),
    passphrase: testCase.passphrase
  });

  assert.equal(recovered.parsedCount, testCase.shareCount, testCase.name);
  assert.equal(recovered.recoveredHex, testCase.secretHex, testCase.name);
}

async function verifyReferenceToLocal(testCase: InteropCase): Promise<void> {
  const generated = await runPython<PythonGenerated>(pythonGenerateScript, testCase);
  assert.equal(generated.parsedCount, testCase.shareCount, testCase.name);
  assert.equal(generated.recoveredHex, testCase.secretHex, testCase.name);

  const recovered = await combineMnemonics(
    generated.mnemonics.slice(0, testCase.threshold),
    testCase.passphrase
  );
  assert.equal(bytesToHex(recovered), testCase.secretHex, testCase.name);
}

async function verifyOfficialVectorsWithReference(): Promise<void> {
  const vectors = JSON.parse(await readFile(officialVectorPath, "utf8")) as Array<
    [string, string[], string, string]
  >;
  let validVectorCount = 0;
  for (const [description, mnemonics, secretHex] of vectors) {
    if (!secretHex) {
      continue;
    }
    const recovered = await runPython<PythonRecovered>(pythonRecoverScript, {
      allMnemonics: mnemonics,
      mnemonics,
      passphrase: "TREZOR"
    });
    assert.equal(recovered.recoveredHex, secretHex, description);
    assert.equal(bytesToHex(await combineMnemonics(mnemonics, "TREZOR")), secretHex, description);
    validVectorCount += 1;
  }
  assert.ok(validVectorCount > 0);
}

for (const testCase of cases) {
  await verifyLocalToReference(testCase);
  await verifyReferenceToLocal(testCase);
}
await verifyOfficialVectorsWithReference();

console.log(
  `Reference interoperability passed for ${cases.length} generated cases and official vectors.`
);
