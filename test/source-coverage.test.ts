import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { test } from "node:test";
import { customizationString } from "../src/ts/slip39/checksum.ts";
import { decrypt, encrypt, randomIdentifier } from "../src/ts/slip39/cipher.ts";
import {
  hasRequiredCrypto,
  hmacSha256,
  pbkdf2Sha256,
  randomBytes,
  requireWebCrypto,
  sha256
} from "../src/ts/slip39/crypto.ts";
import { Slip39Error } from "../src/ts/slip39/errors.ts";
import { gfMultiply, interpolate } from "../src/ts/slip39/gf256.ts";
import {
  combineMnemonics,
  combineMnemonicsFlexible,
  generateMnemonics
} from "../src/ts/slip39/mnemonics.ts";
import { recoverSecret, splitSecret } from "../src/ts/slip39/secret-sharing.ts";
import { Share } from "../src/ts/slip39/share.ts";
import {
  bigIntToBytes,
  bytesEqual,
  bytesToBigInt,
  bytesToIndices,
  concatBytes,
  indicesToWords,
  intFromIndices,
  intToIndices,
  mnemonicToIndices,
  modulo,
  xorBytes,
  zeroize
} from "../src/ts/slip39/utils.ts";
import {
  validateIdentifier,
  validateIterationExponent,
  validateMasterSecretBytes,
  validatePassphrase,
  validateShareParameters,
  validateSingleGroupParameters
} from "../src/ts/slip39/validation.ts";

const SECRET_16 = Uint8Array.from({ length: 16 }, (_, index) => index);
const SECRET_16_HEX = "000102030405060708090a0b0c0d0e0f";
const MULTI_GROUP_SECRET_HEX = "7c3397a292a5941682d7a4ae2d898d11";
const MULTI_GROUP_SHARES = [
  "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
  "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
  "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
  "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
  "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing"
];
const EXTRA_COMPLETE_GROUP_SHARE =
  "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice";

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function ascii(value: string): Uint8Array {
  return Uint8Array.from(value, (character) => character.charCodeAt(0));
}

async function withGlobalCrypto<T>(
  cryptoValue: unknown,
  callback: () => T | Promise<T>
): Promise<T> {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: cryptoValue
  });

  try {
    return await callback();
  } finally {
    if (descriptor) {
      Object.defineProperty(globalThis, "crypto", descriptor);
    } else {
      Reflect.deleteProperty(globalThis, "crypto");
    }
  }
}

test("source generation and recovery cover option variants", async () => {
  const defaultShares = await generateMnemonics(2, 3, SECRET_16, "TREZOR");
  assert.equal(defaultShares.length, 3);
  assert.equal(
    bytesToHex(await combineMnemonics([defaultShares[0], defaultShares[2]], "TREZOR")),
    SECRET_16_HEX
  );

  const oneOfOne = await generateMnemonics(1, 1, SECRET_16, "", {
    extendable: false,
    identifier: 7,
    iterationExponent: 0
  });
  const parsed = Share.fromMnemonic(oneOfOne[0]);
  assert.equal(parsed.extendable, false);
  assert.equal(parsed.iterationExponent, 0);
  assert.equal(parsed.identifier, 7);
  assert.equal(bytesToHex(await combineMnemonics(oneOfOne, "")), SECRET_16_HEX);
});

test("strict multi-group recovery accepts valid sets and rejects group policy errors", async () => {
  assert.equal(
    bytesToHex(await combineMnemonics(MULTI_GROUP_SHARES, "TREZOR")),
    MULTI_GROUP_SECRET_HEX
  );

  await assert.rejects(
    () => combineMnemonics([MULTI_GROUP_SHARES[0], MULTI_GROUP_SHARES[4]], "TREZOR"),
    /Insufficient number of mnemonic groups/
  );
  await assert.rejects(
    () =>
      combineMnemonics(
        [
          MULTI_GROUP_SHARES[0],
          MULTI_GROUP_SHARES[4],
          MULTI_GROUP_SHARES[1],
          MULTI_GROUP_SHARES[2]
        ],
        "TREZOR"
      ),
    /Wrong number of mnemonics/
  );
  await assert.rejects(
    () => combineMnemonics([...MULTI_GROUP_SHARES, EXTRA_COMPLETE_GROUP_SHARE], "TREZOR"),
    /Wrong number of mnemonic groups/
  );
});

test("mnemonic decoding rejects empty, mismatched, and conflicting groups", async () => {
  await assert.rejects(() => combineMnemonics([" ", "\n"], ""), /list of mnemonics is empty/);

  const first = await generateMnemonics(2, 2, SECRET_16, "", { identifier: 1 });
  const second = await generateMnemonics(2, 2, SECRET_16, "", { identifier: 2 });
  await assert.rejects(() => combineMnemonics([first[0], second[0]], ""), /same 2 words/);
  await assert.rejects(() => combineMnemonics([first[0], first[0]], ""), /unique/);

  const memberThresholdOne = new Share(10, true, 1, 0, 1, 1, 0, 1, SECRET_16).toMnemonic();
  const memberThresholdTwo = new Share(10, true, 1, 0, 1, 1, 1, 2, SECRET_16).toMnemonic();
  await assert.rejects(
    () => combineMnemonics([memberThresholdOne, memberThresholdTwo], ""),
    /Group parameters do not match/
  );
});

test("flexible recovery searches surplus groups and reports incomplete sets", async () => {
  assert.equal(
    bytesToHex(
      await combineMnemonicsFlexible(
        ["", EXTRA_COMPLETE_GROUP_SHARE, ...MULTI_GROUP_SHARES],
        "TREZOR"
      )
    ),
    MULTI_GROUP_SECRET_HEX
  );

  await assert.rejects(
    () =>
      combineMnemonicsFlexible(
        [
          MULTI_GROUP_SHARES[0],
          MULTI_GROUP_SHARES[4],
          MULTI_GROUP_SHARES[1],
          MULTI_GROUP_SHARES[2]
        ],
        "TREZOR"
      ),
    /Insufficient number of mnemonic groups/
  );

  const badLengthFirst = new Share(777, true, 1, 0, 1, 1, 0, 2, SECRET_16).toMnemonic();
  const badLengthSecond = new Share(
    777,
    true,
    1,
    0,
    1,
    1,
    1,
    2,
    Uint8Array.from({ length: 18 }, (_, index) => index)
  ).toMnemonic();
  await assert.rejects(
    () => combineMnemonicsFlexible([badLengthFirst, badLengthSecond], ""),
    /All share values must have the same length/
  );

  await assert.rejects(
    () => combineMnemonicsFlexible([" ", "\n"], ""),
    /list of mnemonics is empty/
  );

  const first = await generateMnemonics(2, 2, SECRET_16, "", { identifier: 11 });
  const second = await generateMnemonics(2, 2, SECRET_16, "", { identifier: 12 });
  await assert.rejects(() => combineMnemonicsFlexible([first[0], second[0]], ""), /same 2 words/);

  const memberThresholdOne = new Share(13, true, 1, 0, 1, 1, 0, 1, SECRET_16).toMnemonic();
  const memberThresholdTwo = new Share(13, true, 1, 0, 1, 1, 1, 2, SECRET_16).toMnemonic();
  await assert.rejects(
    () => combineMnemonicsFlexible([memberThresholdOne, memberThresholdTwo], ""),
    /Group parameters do not match/
  );

  const parsed = Share.fromMnemonic(first[0]);
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
    () => combineMnemonicsFlexible([first[0], conflictingShare, first[1]], ""),
    /Conflicting mnemonic shares/
  );

  const lengthMismatchGroupFirst = new Share(888, true, 1, 0, 1, 2, 0, 2, SECRET_16).toMnemonic();
  const lengthMismatchGroupSecond = new Share(
    888,
    true,
    1,
    0,
    1,
    2,
    1,
    2,
    Uint8Array.from({ length: 18 }, (_, index) => index)
  ).toMnemonic();
  const digestFailureGroupFirst = new Share(
    888,
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
    888,
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
    /Most common errors/
  );
});

test("validation helpers reject every public parameter boundary", () => {
  assert.deepEqual([...validatePassphrase("AZaz 09~")], [...ascii("AZaz 09~")]);
  assert.throws(() => validatePassphrase("\n"), /printable ASCII/);
  assert.throws(() => validatePassphrase("\x7f"), /printable ASCII/);

  for (const identifier of [-1, 32768, 1.5, Number.NaN]) {
    assert.throws(() => validateIdentifier(identifier), /identifier/);
  }
  assert.doesNotThrow(() => validateIdentifier(32767));

  assert.throws(() => validateMasterSecretBytes("abc" as unknown as Uint8Array), /bytes/);
  assert.throws(() => validateMasterSecretBytes(new Uint8Array(15)), /at least 16 bytes/);
  assert.throws(() => validateMasterSecretBytes(new Uint8Array(17)), /multiple of 2/);
  assert.doesNotThrow(() => validateMasterSecretBytes(SECRET_16));

  assert.throws(() => validateShareParameters(0, 1), /Threshold/);
  assert.throws(() => validateShareParameters(1.5, 2), /Threshold/);
  assert.throws(() => validateShareParameters(1, 0), /Total shares/);
  assert.throws(() => validateShareParameters(1, 1.5), /Total shares/);
  assert.throws(() => validateShareParameters(3, 2), /must not exceed/);
  assert.throws(() => validateShareParameters(1, 17), /must not exceed 16/);
  assert.throws(() => validateSingleGroupParameters(1, 2), /requires 1-of-1/);
  assert.doesNotThrow(() => validateSingleGroupParameters(2, 3));

  assert.throws(() => validateIterationExponent(-1), /Iteration exponent/);
  assert.throws(() => validateIterationExponent(16), /Iteration exponent/);
  assert.throws(() => validateIterationExponent(1.5), /Iteration exponent/);
  assert.doesNotThrow(() => validateIterationExponent(15));
});

test("crypto helpers handle Web Crypto, random chunking, and known digests", async () => {
  await withGlobalCrypto(undefined, () => {
    assert.equal(hasRequiredCrypto(), false);
    assert.throws(() => requireWebCrypto(), /unavailable/);
  });

  const chunkLengths: number[] = [];
  await withGlobalCrypto(
    {
      subtle: webcrypto.subtle,
      getRandomValues(target: Uint8Array): Uint8Array {
        chunkLengths.push(target.length);
        target.fill(0xab);
        return target;
      }
    },
    () => {
      assert.equal(hasRequiredCrypto(), true);
      assert.deepEqual([...randomBytes(70_000).slice(0, 4)], [0xab, 0xab, 0xab, 0xab]);
    }
  );
  assert.deepEqual(chunkLengths, [65_536, 4_464]);

  assert.equal(
    bytesToHex(await sha256(ascii("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
  assert.equal(
    bytesToHex(
      await hmacSha256(ascii("key"), ascii("The quick brown fox jumps over the lazy dog"))
    ),
    "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
  );
  assert.equal(
    bytesToHex(await pbkdf2Sha256(ascii("password"), ascii("salt"), 1, 32)),
    "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
  );
});

test("cipher helpers reject odd inputs and round-trip original checksum mode", async () => {
  const passphrase = ascii("TREZOR");
  await assert.rejects(() => encrypt(new Uint8Array(17), passphrase, 0, 42, true), /even/);
  await assert.rejects(() => decrypt(new Uint8Array(17), passphrase, 0, 42, true), /even/);

  const encrypted = await encrypt(SECRET_16, passphrase, 0, 42, false);
  assert.notDeepEqual([...encrypted], [...SECRET_16]);
  assert.equal(bytesToHex(await decrypt(encrypted, passphrase, 0, 42, false)), SECRET_16_HEX);

  await withGlobalCrypto(
    {
      subtle: webcrypto.subtle,
      getRandomValues(target: Uint8Array): Uint8Array {
        target.fill(0xff);
        return target;
      }
    },
    () => {
      assert.equal(randomIdentifier(), 32767);
    }
  );
});

test("GF(256) and secret sharing helpers reject malformed shares", async () => {
  assert.equal(gfMultiply(0, 0x83), 0);
  assert.equal(gfMultiply(0x57, 0x83), 0xc1);
  assert.throws(
    () =>
      interpolate(
        [
          { x: 1, data: new Uint8Array([1]) },
          { x: 1, data: new Uint8Array([2]) }
        ],
        255
      ),
    /unique/
  );
  assert.throws(
    () =>
      interpolate(
        [
          { x: 1, data: new Uint8Array([1]) },
          { x: 2, data: new Uint8Array([2, 3]) }
        ],
        255
      ),
    /same length/
  );
  assert.deepEqual([...interpolate([{ x: 7, data: new Uint8Array([9, 8]) }], 7)], [9, 8]);

  assert.deepEqual(
    (await splitSecret(1, 2, SECRET_16)).map((share) => [...share.data]),
    [[...SECRET_16], [...SECRET_16]]
  );
  const thresholdThreeShares = await splitSecret(3, 4, SECRET_16);
  assert.equal(thresholdThreeShares.length, 4);
  assert.equal(thresholdThreeShares[0].x, 0);
  assert.deepEqual([...(await recoverSecret(1, [{ x: 0, data: SECRET_16 }]))], [...SECRET_16]);

  const shares = await splitSecret(2, 3, SECRET_16);
  shares[0].data[0] ^= 1;
  await assert.rejects(() => recoverSecret(2, shares.slice(0, 2)), /Invalid digest/);
});

test("share parsing rejects invalid lengths, padding, and encoded group parameters", () => {
  assert.throws(() => Share.fromMnemonic("academic acid"), /Invalid mnemonic length/);
  assert.throws(
    () =>
      Share.fromMnemonic(
        "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness"
      ),
    /Invalid mnemonic padding/
  );
  assert.throws(
    () =>
      Share.fromMnemonic(new Share(42, true, 1, 0, 1, 1, 0, 1, new Uint8Array(17)).toMnemonic()),
    /Invalid mnemonic length/
  );
  assert.throws(
    () =>
      Share.fromMnemonic(
        "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
      ),
    /Invalid mnemonic checksum/
  );
  assert.throws(
    () => Share.fromMnemonic(new Share(42, true, 1, 0, 2, 1, 0, 1, SECRET_16).toMnemonic()),
    /Group threshold/
  );
  assert.throws(
    () => Share.fromMnemonic(new Share(42, true, 1, 1, 1, 1, 0, 1, SECRET_16).toMnemonic()),
    /Group index/
  );
});

test("utility helpers cover numeric, word, equality, and zeroization branches", () => {
  assert.equal(modulo(-1, 5), 4);
  assert.equal(bytesToBigInt(new Uint8Array([1, 2, 3])), 0x010203n);
  assert.deepEqual([...bigIntToBytes(0x010203n, 3)], [1, 2, 3]);
  assert.throws(() => bigIntToBytes(0x0100n, 1), /Invalid mnemonic padding/);
  assert.deepEqual(intToIndices(0x1234, 4, 4), [1, 2, 3, 4]);
  assert.throws(() => intToIndices(0x10000, 4, 4), /does not fit/);
  assert.equal(intFromIndices([1, 2, 3, 4], 4), 0x1234n);
  assert.throws(() => intFromIndices([16], 4), /Invalid word index/);
  assert.deepEqual(bytesToIndices(new Uint8Array([0xff]), 1), [255]);
  assert.deepEqual(indicesToWords([0, 1, 2]), ["academic", "acid", "acne"]);
  assert.deepEqual(mnemonicToIndices(" Academic   ACID "), [0, 1]);
  assert.throws(() => mnemonicToIndices(""), /empty/);
  assert.throws(() => mnemonicToIndices("notaword"), /Unknown SLIP-0039 word/);

  assert.equal(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 2])), false);
  assert.equal(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3])), false);
  assert.equal(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
  assert.deepEqual([...concatBytes(new Uint8Array([1]), new Uint8Array([2, 3]))], [1, 2, 3]);
  assert.deepEqual([...xorBytes(new Uint8Array([1, 2, 3]), new Uint8Array([3, 2]))], [2, 0]);

  const buffer = new Uint8Array([1, 2, 3]);
  zeroize(undefined, null, buffer);
  assert.deepEqual([...buffer], [0, 0, 0]);

  const error = new Slip39Error("message");
  assert.equal(error.name, "Slip39Error");
  assert.equal(customizationString(true), "shamir_extendable");
  assert.equal(customizationString(false), "shamir");
});
