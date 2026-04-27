import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import fc from "fast-check";
import {
  combineMnemonics as combineMnemonicsSource,
  generateMnemonics as generateMnemonicsSource
} from "../src/js/slip39/mnemonics.js";

const execFileAsync = promisify(execFile);
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR_PATH = resolve(projectRoot, "test", "fixtures", "slip39-vectors.json");
const INTEROP_MATRIX_PATH = resolve(projectRoot, "test", "fixtures", "slip39-interop-matrix.json");
const SECRET_16 = Uint8Array.from({ length: 16 }, (_, index) => index);
const SECRET_32 = Uint8Array.from({ length: 32 }, (_, index) => index);
const SECRET_16_HEX = "000102030405060708090a0b0c0d0e0f";
const SECRET_32_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const INDEX_UNIVERSE = Array.from({ length: 16 }, (_, index) => index);
const PRINTABLE_ASCII_ARBITRARY = fc
  .array(fc.integer({ min: 32, max: 126 }), { minLength: 0, maxLength: 32 })
  .map((codes) => String.fromCharCode(...codes));
const INDEX_PERMUTATION_ARBITRARY = fc.shuffledSubarray(INDEX_UNIVERSE, {
  minLength: INDEX_UNIVERSE.length,
  maxLength: INDEX_UNIVERSE.length
});
const ROUND_TRIP_PARAMETERS_ARBITRARY = fc
  .tuple(fc.integer({ min: 1, max: 16 }), fc.integer({ min: 1, max: 16 }))
  .filter(
    ([threshold, shareCount]) => shareCount >= threshold && !(threshold === 1 && shareCount > 1)
  );
const THRESHOLD_PARAMETERS_ARBITRARY = fc
  .tuple(fc.integer({ min: 2, max: 16 }), fc.integer({ min: 2, max: 16 }))
  .filter(([threshold, shareCount]) => shareCount >= threshold);

const REFERENCE_FIXTURES = [
  {
    name: "128-bit 2-of-3 with empty passphrase",
    threshold: 2,
    shareCount: 3,
    secretHex: SECRET_16_HEX,
    passphrase: "",
    options: { identifier: 42 },
    mnemonics: [
      "acid fawn academic acid both silent single python romantic grownup paces beam prune geology gums salt husky album racism editor",
      "acid fawn academic agency dough quick finger mustang laundry credit problem paces year deadline modify gasoline gross quantity grasp humidity",
      "acid fawn academic always analysis dough modify weapon early work wolf cards type watch visual diagnose fragment rhyme spend lyrics"
    ]
  },
  {
    name: "256-bit 3-of-5 with TREZOR passphrase",
    threshold: 3,
    shareCount: 5,
    secretHex: SECRET_32_HEX,
    passphrase: "TREZOR",
    options: { identifier: 1234 },
    mnemonics: [
      "analysis morning academic acne academic acid adequate apart echo educate alive category method liberty apart describe teammate scandal beard entrance declare airline blue frequent legend endorse bumpy hush soldier lunar greatest oven umbrella",
      "analysis morning academic agree aluminum discuss smart shelter educate flavor pajamas scholar patrol volume timber legs webcam check obesity plains trash privacy bulb prepare best research reunion kernel teammate type browser upgrade python",
      "analysis morning academic amazing already scholar credit garden garden bucket smear glad estate erode branch playoff preach scared admit edge shame brother task premium flavor simple hazard fatigue provide crush aviation organize typical",
      "analysis morning academic arcade avoid woman tofu petition genuine avoid guilt luck jacket easel vampire carve purple chemical lyrics pajamas beaver purchase spark freshman scholar diet slap flexible legal engage income verify quick",
      "analysis morning academic axle alien explain senior crystal game treat slush dining exercise manager ladle subject together prize explain axis exchange exercise visitor nail fantasy failure group username herald raspy element practice drug"
    ]
  }
];

const appScriptPromise = (async () => {
  await execFileAsync("node", ["scripts/build.js"], { cwd: projectRoot });
  const html = await readFile(resolve(projectRoot, "dist/index.html"), "utf8");
  const scriptMatch = html.match(/<script\b[^>]*id=["']app-source["'][^>]*>([\s\S]*?)<\/script>/i);
  assert.ok(scriptMatch, "dist/index.html must contain the inline app-source script");
  return scriptMatch[1];
})();

async function loadAppCore(crypto = webcrypto) {
  const appScript = await appScriptPromise;
  const context = vm.createContext({
    crypto,
    console,
    TextDecoder,
    TextEncoder
  });
  vm.runInContext(appScript, context, { filename: "dist/index.html" });
  assert.ok(context.__SLIP39_APP__, "inline app script must expose its test API");
  return context.__SLIP39_APP__;
}

function deterministicCrypto() {
  let counter = 0;
  return {
    subtle: webcrypto.subtle,
    getRandomValues(target) {
      for (let index = 0; index < target.length; index += 1) {
        target[index] = counter & 0xff;
        counter = (counter + 1) & 0xff;
      }
      return target;
    }
  };
}

const appPromise = loadAppCore();

function asArray(bytes) {
  return [...bytes];
}

function bytesToHexLocal(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function utf8Length(value) {
  return new TextEncoder().encode(value).length;
}

test("wordlist has the required size and unique entries", async () => {
  const { SLIP39_WORDS } = await appPromise;
  assert.equal(SLIP39_WORDS.length, 1024);
  assert.equal(new Set(SLIP39_WORDS).size, 1024);
});

test("required Web Crypto APIs are available", async () => {
  const { hasRequiredCrypto } = await appPromise;
  assert.equal(hasRequiredCrypto(), true);
});

test("GF(256) multiplication matches the AES field example", async () => {
  const { gfMultiply } = await appPromise;
  assert.equal(gfMultiply(0x57, 0x83), 0xc1);
  assert.equal(gfMultiply(0, 0x83), 0);
});

test("interpolation recovers a split secret", async () => {
  const { interpolate, splitSecret } = await appPromise;
  const shares = await splitSecret(2, 3, SECRET_16);
  assert.deepEqual(asArray(interpolate(shares.slice(0, 2), 255)), asArray(SECRET_16));
});

test("RS1024 checksum round trips", async () => {
  const { createChecksum, verifyChecksum } = await appPromise;
  const data = [0, 1, 2, 3, 4, 5, 6];
  const checksum = createChecksum(data, "shamir_extendable");
  assert.equal(checksum.length, 3);
  assert.equal(verifyChecksum([...data, ...checksum], "shamir_extendable"), true);
  assert.equal(
    verifyChecksum([...data, checksum[0], checksum[1], checksum[2] ^ 1], "shamir_extendable"),
    false
  );
});

test("mnemonic encode and decode round trip", async () => {
  const { Share, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "TREZOR", { identifier: 42 });
  const parsed = Share.fromMnemonic(shares[0]);
  assert.equal(parsed.toMnemonic(), shares[0]);
  assert.equal(parsed.identifier, 42);
  assert.equal(parsed.extendable, true);
  assert.equal(parsed.iterationExponent, 1);
  assert.equal(parsed.groupThreshold, 1);
  assert.equal(parsed.groupCount, 1);
  assert.equal(parsed.memberThreshold, 2);
});

test("single-group 2-of-3 generation and recovery works", async () => {
  const { bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "TREZOR");
  assert.equal(shares.length, 3);
  assert.equal(bytesToHex(await combineMnemonics([shares[0], shares[2]], "TREZOR")), SECRET_16_HEX);
});

test("single-group 3-of-5 generation and recovery works", async () => {
  const { bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(3, 5, SECRET_32, "");
  assert.equal(shares.length, 5);
  assert.equal(
    bytesToHex(await combineMnemonics([shares[1], shares[3], shares[4]], "")),
    SECRET_32_HEX
  );
});

test("deterministic generation fixtures are recoverable by Trezor reference", async () => {
  for (const fixture of REFERENCE_FIXTURES) {
    const app = await loadAppCore(deterministicCrypto());
    const shares = await app.generateMnemonics(
      fixture.threshold,
      fixture.shareCount,
      app.hexToBytes(fixture.secretHex),
      fixture.passphrase,
      fixture.options
    );

    assert.deepEqual([...shares], fixture.mnemonics, fixture.name);
    assert.equal(
      app.bytesToHex(
        await app.combineMnemonics(shares.slice(0, fixture.threshold), fixture.passphrase)
      ),
      fixture.secretHex,
      fixture.name
    );
  }
});

test("vendored deterministic interop matrix covers iteration exponent and checksum variants", async () => {
  const fixtures = JSON.parse(await readFile(INTEROP_MATRIX_PATH, "utf8"));
  for (const fixture of fixtures) {
    const app = await loadAppCore(deterministicCrypto());
    const shares = await app.generateMnemonics(
      fixture.threshold,
      fixture.shareCount,
      app.hexToBytes(fixture.secretHex),
      fixture.passphrase,
      {
        identifier: fixture.identifier,
        extendable: fixture.extendable,
        iterationExponent: fixture.iterationExponent
      }
    );

    assert.deepEqual([...shares], fixture.mnemonics, fixture.name);
    assert.equal(
      app.bytesToHex(
        await app.combineMnemonics(shares.slice(0, fixture.threshold), fixture.passphrase)
      ),
      fixture.secretHex,
      fixture.name
    );
  }
});

test("strict recovery still rejects surplus single-group shares", async () => {
  const { combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "");
  await assert.rejects(() => combineMnemonics(shares, ""), /Wrong number of mnemonics/);
});

test("flexible recovery accepts surplus and duplicate shares", async () => {
  const { bytesToHex, combineMnemonicsFlexible, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "");
  assert.equal(
    bytesToHex(await combineMnemonicsFlexible([shares[0], shares[1], shares[1], shares[2]], "")),
    SECRET_16_HEX
  );
});

test("flexible recovery rejects conflicting same-index shares", async () => {
  const { Share, combineMnemonicsFlexible, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "");
  const parsed = Share.fromMnemonic(shares[0]);
  const conflictingValue = new Uint8Array(parsed.value);
  conflictingValue[0] ^= 1;
  const conflictingShare = new Share(
    parsed.identifier,
    parsed.extendable,
    parsed.iterationExponent,
    parsed.groupIndex,
    parsed.groupThreshold,
    parsed.groupCount,
    parsed.index,
    parsed.memberThreshold,
    conflictingValue
  ).toMnemonic();

  await assert.rejects(
    () => combineMnemonicsFlexible([shares[0], conflictingShare, shares[1]], ""),
    /Conflicting mnemonic shares/
  );
});

test("hex helpers and master secret parsing validate pure byte input", async () => {
  const { bytesToHex, hexToBytes, normalizeHex, parseMasterSecretHex } = await appPromise;
  assert.deepEqual(asArray(hexToBytes("000102ff")), [0, 1, 2, 255]);
  assert.deepEqual(asArray(hexToBytes("00 01\n02\tff")), [0, 1, 2, 255]);
  assert.equal(bytesToHex(new Uint8Array([0, 1, 2, 255])), "000102ff");
  assert.equal(
    normalizeHex(`  ${SECRET_16_HEX.slice(0, 12).toUpperCase()}\n${SECRET_16_HEX.slice(12)}  `),
    SECRET_16_HEX
  );
  assert.equal(
    bytesToHex(parseMasterSecretHex(`  ${SECRET_16_HEX.toUpperCase()}  `)),
    SECRET_16_HEX
  );

  assert.throws(() => parseMasterSecretHex(""), /empty/);
  assert.throws(() => parseMasterSecretHex("zz"), /hex digits and whitespace/);
  assert.throws(() => parseMasterSecretHex("00_01"), /hex digits and whitespace/);
  assert.throws(() => parseMasterSecretHex("0"), /odd number of digits/);
  assert.throws(() => parseMasterSecretHex("00".repeat(15)), /at least 16 bytes/);
  assert.throws(() => parseMasterSecretHex(`${SECRET_16_HEX}0`), /odd number of digits/);
  assert.throws(() => parseMasterSecretHex("00".repeat(17)), /multiple of 2/);
});

test("hex parsing preserves exact validation error messages", async () => {
  const { parseMasterSecretHex } = await appPromise;
  const cases = [
    ["", "The master secret hex is empty."],
    ["zz", "The master secret hex can contain only hex digits and whitespace."],
    ["00_01", "The master secret hex can contain only hex digits and whitespace."],
    [
      "0",
      "The master secret hex has an odd number of digits. Add or remove one hex digit intentionally; this app will not auto-pad."
    ],
    ["00".repeat(15), "The master secret must be at least 16 bytes."],
    [
      "00".repeat(17),
      "The master secret byte length must be a multiple of 2. Add or remove a full byte intentionally; this app will not auto-pad."
    ]
  ];

  for (const [input, expectedMessage] of cases) {
    assert.throws(
      () => parseMasterSecretHex(input),
      (error) => {
        assert.equal(error.message, expectedMessage);
        return true;
      }
    );
  }
});

test("text master secret envelopes round-trip user text", async () => {
  const {
    decodeTextMasterSecret,
    describeTextMasterSecret,
    encodeTextMasterSecret,
    isTextMasterSecretEnvelope
  } = await loadAppCore(deterministicCrypto());
  const cases = [
    "plain ASCII text",
    "Unicode text: snowman \u2603 and emoji \u{1f642}",
    "  leading whitespace\nand trailing whitespace  ",
    "",
    "a",
    "ab"
  ];

  for (const text of cases) {
    const info = describeTextMasterSecret(text);
    const encoded = await encodeTextMasterSecret(text);
    assert.equal(info.utf8ByteLength, utf8Length(text));
    assert.equal(info.paddingByteLength, info.utf8ByteLength % 2);
    assert.equal(encoded.length, info.masterSecretByteLength);
    assert.equal(encoded.length % 2, 0);
    assert.ok(encoded.length >= 16);
    assert.equal(await isTextMasterSecretEnvelope(encoded), true);
    assert.equal(await decodeTextMasterSecret(encoded), text);
  }
});

test("text envelope decoder ignores unsupported or malformed bytes", async () => {
  const { decodeTextMasterSecret, encodeTextMasterSecret, isTextMasterSecretEnvelope } =
    await loadAppCore(deterministicCrypto());
  const valid = await encodeTextMasterSecret("a");
  const badVersion = new Uint8Array(valid);
  badVersion["SLIP39TXT".length] = 2;
  const badLength = new Uint8Array(valid);
  badLength["SLIP39TXT".length + 1] = 0xff;
  const missingPadding = valid.slice(0, -1);
  const invalidUtf8 = new Uint8Array(32);
  invalidUtf8.set(Uint8Array.from("SLIP39TXT", (char) => char.charCodeAt(0)));
  invalidUtf8["SLIP39TXT".length] = 1;
  invalidUtf8["SLIP39TXT".length + 4] = 1;
  invalidUtf8[30] = 0xff;

  for (const bytes of [SECRET_16, badVersion, badLength, missingPadding, invalidUtf8]) {
    assert.equal(await isTextMasterSecretEnvelope(bytes), false);
    assert.equal(await decodeTextMasterSecret(bytes), null);
  }
});

test("text envelope tag detects payload tampering", async () => {
  const { decodeTextMasterSecret, encodeTextMasterSecret, isTextMasterSecretEnvelope } =
    await loadAppCore(deterministicCrypto());
  const encoded = await encodeTextMasterSecret("hello world");
  const PAYLOAD_OFFSET = "SLIP39TXT".length + 1 + 4 + 16;
  const tampered = new Uint8Array(encoded);
  tampered[PAYLOAD_OFFSET] ^= 1;
  assert.equal(await isTextMasterSecretEnvelope(tampered), false);
  assert.equal(await decodeTextMasterSecret(tampered), null);

  const tamperedTag = new Uint8Array(encoded);
  tamperedTag["SLIP39TXT".length + 1 + 4] ^= 1;
  assert.equal(await decodeTextMasterSecret(tamperedTag), null);
});

test("text envelopes remain standard SLIP-0039 master-secret bytes", async () => {
  const app = await loadAppCore(deterministicCrypto());
  const encoded = await app.encodeTextMasterSecret("recover me\nexactly");
  const shares = await app.generateMnemonics(2, 3, encoded, "");
  const recovered = await app.combineMnemonics([shares[0], shares[1]], "");
  assert.deepEqual(asArray(recovered), asArray(encoded));
  assert.equal(await app.decodeTextMasterSecret(recovered), "recover me\nexactly");
});

test("standard validation rejects invalid generation parameters", async () => {
  const { generateMnemonics } = await appPromise;
  await assert.rejects(() => generateMnemonics(2, 17, SECRET_16, ""), /must not exceed 16/);
  await assert.rejects(() => generateMnemonics(1, 2, SECRET_16, ""), /requires 1-of-1/);
  await assert.rejects(() => generateMnemonics(2, 3, SECRET_16, "bad\u2603"), /printable ASCII/);
  await assert.rejects(
    () => generateMnemonics(2, 3, SECRET_16, "", { identifier: -1 }),
    /identifier/
  );
  await assert.rejects(
    () => generateMnemonics(2, 3, SECRET_16, "", { identifier: 32768 }),
    /identifier/
  );
});

test("parsed shares reject invalid checksum, duplicates, mismatches, and group index", async () => {
  const { Share, combineMnemonics, generateMnemonics } = await appPromise;
  const first = await generateMnemonics(2, 3, SECRET_16, "TREZOR");
  const second = await generateMnemonics(2, 3, SECRET_16, "TREZOR");
  const words = first[0].split(" ");
  words[words.length - 1] = words[words.length - 1] === "academic" ? "acid" : "academic";
  const invalidGroupIndex = new Share(42, true, 1, 1, 1, 1, 0, 1, SECRET_16).toMnemonic();

  await assert.rejects(() => combineMnemonics([words.join(" "), first[1]], "TREZOR"), /checksum/);
  await assert.rejects(() => combineMnemonics([first[0], first[0]], "TREZOR"), /unique/);
  await assert.rejects(() => combineMnemonics([first[0]], "TREZOR"), /Wrong number/);
  await assert.rejects(() => combineMnemonics([first[0], second[0]], "TREZOR"), /same 2 words/);
  assert.throws(() => Share.fromMnemonic(invalidGroupIndex), /Group index/);
});

test("splitSecret rejects non-Uint8Array and short shared secrets", async () => {
  const { Slip39Error, splitSecret } = await appPromise;
  await assert.rejects(
    () => splitSecret(2, 3, new Uint8Array(4)),
    (error) => error instanceof Slip39Error && /at least \d+ bytes/.test(error.message)
  );
  await assert.rejects(
    () => splitSecret(2, 3, "not bytes"),
    (error) => error instanceof Slip39Error && /Uint8Array/.test(error.message)
  );
});

test("encrypt does not mutate the caller's master secret buffer", async () => {
  const app = await loadAppCore(deterministicCrypto());
  const original = new Uint8Array(SECRET_16);
  const snapshot = new Uint8Array(SECRET_16);
  await app.generateMnemonics(2, 3, original, "TREZOR", { identifier: 7 });
  assert.deepEqual(asArray(original), asArray(snapshot));
});

test(
  "combineMnemonics zeroizes its internal passphrase buffer",
  { concurrency: false },
  async () => {
    const passphrase = "sensitive-passphrase-0123456789";
    const passphraseBytes = new TextEncoder().encode(passphrase);
    const shares = await generateMnemonicsSource(2, 3, SECRET_16, passphrase, { identifier: 99 });
    const originalFill = Uint8Array.prototype.fill;
    let observedPassphraseZeroize = false;

    Uint8Array.prototype.fill = function patchedFill(value, ...rest) {
      const before = new Uint8Array(this);
      const result = originalFill.call(this, value, ...rest);

      if (value === 0 && rest.length === 0 && before.length === passphraseBytes.length) {
        const matchesPassphrase = before.every((byte, index) => byte === passphraseBytes[index]);
        const isZeroized = this.every((byte) => byte === 0);
        if (matchesPassphrase && isZeroized) {
          observedPassphraseZeroize = true;
        }
      }

      return result;
    };

    try {
      await combineMnemonicsSource([shares[0], shares[1]], passphrase);
    } finally {
      Uint8Array.prototype.fill = originalFill;
    }

    assert.equal(observedPassphraseZeroize, true);
  }
);

test("flexible recovery aggregates mixed root causes across failed subsets", async () => {
  const { Share, Slip39Error, combineMnemonicsFlexible } = await appPromise;

  const lengthMismatchGroupFirst = new Share(
    777,
    true,
    1,
    0,
    1,
    2,
    0,
    2,
    Uint8Array.from({ length: 16 }, (_, index) => index)
  ).toMnemonic();
  const lengthMismatchGroupSecond = new Share(
    777,
    true,
    1,
    0,
    1,
    2,
    1,
    2,
    Uint8Array.from({ length: 18 }, (_, index) => (index + 1) & 0xff)
  ).toMnemonic();
  const digestFailureGroupFirst = new Share(
    777,
    true,
    1,
    1,
    1,
    2,
    0,
    2,
    Uint8Array.from({ length: 16 }, (_, index) => (index + 17) & 0xff)
  ).toMnemonic();
  const digestFailureGroupSecond = new Share(
    777,
    true,
    1,
    1,
    1,
    2,
    1,
    2,
    Uint8Array.from({ length: 16 }, (_, index) => (index + 33) & 0xff)
  ).toMnemonic();

  await assert.rejects(
    () =>
      combineMnemonicsFlexible(
        [
          lengthMismatchGroupFirst,
          lengthMismatchGroupSecond,
          digestFailureGroupFirst,
          digestFailureGroupSecond
        ],
        ""
      ),
    (error) => {
      assert.ok(error instanceof Slip39Error);
      assert.match(error.message, /No valid threshold-complete mnemonic subset was found/);
      assert.match(error.message, /Tried 2 combinations/);
      assert.match(error.message, /All share values must have the same length/);
      assert.match(error.message, /Invalid digest of the shared secret/);
      return true;
    }
  );
});

test("wrong passphrase returns different bytes without app-specific rejection", async () => {
  const { bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "TREZOR");
  const recovered = await combineMnemonics([shares[0], shares[1]], "WRONG");
  assert.equal(recovered.length, SECRET_16.length);
  assert.notEqual(bytesToHex(recovered), SECRET_16_HEX);
});

test(
  "property: generate/combine round-trip for secret length, threshold, and passphrase variants",
  { timeout: 120000 },
  async () => {
    const { bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(16, 32),
        ROUND_TRIP_PARAMETERS_ARBITRARY,
        PRINTABLE_ASCII_ARBITRARY,
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        INDEX_PERMUTATION_ARBITRARY,
        async (
          secretLength,
          [threshold, shareCount],
          passphrase,
          randomBytes,
          indexPermutation
        ) => {
          const secret = randomBytes.slice(0, secretLength);
          const mnemonics = await generateMnemonics(threshold, shareCount, secret, passphrase, {
            identifier: 1
          });
          const subset = indexPermutation
            .filter((index) => index < shareCount)
            .slice(0, threshold)
            .map((index) => mnemonics[index]);
          const recovered = await combineMnemonics(subset, passphrase);
          assert.equal(bytesToHex(recovered), bytesToHexLocal(secret));
        }
      ),
      { numRuns: 50 }
    );
  }
);

test("property: combining fewer than threshold shares never deterministically recovers the secret", async () => {
  const { Slip39Error, bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  await fc.assert(
    fc.asyncProperty(
      THRESHOLD_PARAMETERS_ARBITRARY,
      INDEX_PERMUTATION_ARBITRARY,
      async ([threshold, shareCount], indexPermutation) => {
        const mnemonics = await generateMnemonics(threshold, shareCount, SECRET_16, "", {
          identifier: 1
        });
        const insufficient = indexPermutation
          .filter((index) => index < shareCount)
          .slice(0, threshold - 1)
          .map((index) => mnemonics[index]);

        try {
          const recovered = await combineMnemonics(insufficient, "");
          assert.notEqual(bytesToHex(recovered), SECRET_16_HEX);
        } catch (error) {
          assert.ok(error instanceof Slip39Error);
        }
      }
    ),
    { numRuns: 100 }
  );
});

test("property: GF(256) multiplication obeys associative, commutative, and identity laws", async () => {
  const { gfMultiply } = await appPromise;
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 255 }),
      fc.integer({ min: 1, max: 255 }),
      fc.integer({ min: 1, max: 255 }),
      (a, b, c) => {
        assert.equal(gfMultiply(a, gfMultiply(b, c)), gfMultiply(gfMultiply(a, b), c));
        assert.equal(gfMultiply(a, b), gfMultiply(b, a));
        assert.equal(gfMultiply(a, 1), a);
      }
    ),
    { numRuns: 1000 }
  );
});

test("recovery supports original and extendable checksum variants", async () => {
  const { Share, bytesToHex, combineMnemonics, generateMnemonics } = await appPromise;
  const original = await generateMnemonics(2, 3, SECRET_16, "", {
    identifier: 42,
    extendable: false
  });
  const extendable = await generateMnemonics(2, 3, SECRET_16, "", {
    identifier: 42,
    extendable: true
  });

  assert.equal(Share.fromMnemonic(original[0]).extendable, false);
  assert.equal(Share.fromMnemonic(extendable[0]).extendable, true);
  assert.equal(bytesToHex(await combineMnemonics([original[0], original[1]], "")), SECRET_16_HEX);
  assert.equal(
    bytesToHex(await combineMnemonics([extendable[0], extendable[1]], "")),
    SECRET_16_HEX
  );
});

test("non-ASCII recovery passphrases are rejected", async () => {
  const { combineMnemonics, generateMnemonics } = await appPromise;
  const shares = await generateMnemonics(2, 3, SECRET_16, "");
  await assert.rejects(
    () => combineMnemonics([shares[0], shares[1]], "bad\u2603"),
    /printable ASCII/
  );
});

test("vendored official Trezor SLIP-0039 vectors", async () => {
  const { Slip39Error, bytesToHex, combineMnemonics } = await appPromise;
  const vectors = JSON.parse(await readFile(VECTOR_PATH, "utf8"));
  const coverage = {
    valid128: false,
    valid256: false,
    invalid128: false,
    invalid256: false
  };

  for (const [description, mnemonics, secretHex] of vectors) {
    if (secretHex) {
      const recovered = await combineMnemonics(mnemonics, "TREZOR");
      assert.equal(bytesToHex(recovered), secretHex, description);
      coverage.valid128 ||= recovered.length === 16;
      coverage.valid256 ||= recovered.length === 32;
    } else {
      await assert.rejects(() => combineMnemonics(mnemonics, ""), Slip39Error, description);
      coverage.invalid128 ||=
        description.includes("128 bits") || description.includes("insufficient length");
      coverage.invalid256 ||= description.includes("256 bits");
    }
  }

  assert.deepEqual(coverage, {
    valid128: true,
    valid256: true,
    invalid128: true,
    invalid256: true
  });
});
