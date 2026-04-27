import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePositiveInteger } from "../src/js/ui/forms.js";
import { getRecoveryOutput } from "../src/js/ui/recovery-output.js";
import {
  getSecretInputModeConfig,
  getSecretInputStatus,
  parseSecretInput,
  SECRET_INPUT_MODES
} from "../src/js/ui/secret-input.js";
import { hashForTabMode, tabModeFromHash, UI_TABS } from "../src/js/ui/tabs.js";

function makeCore() {
  return {
    MIN_STRENGTH_BITS: 128,
    bitsToBytes(bits) {
      return Math.ceil(bits / 8);
    },
    bytesToHex(bytes) {
      return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    },
    compactHex(value) {
      return value.replace(/\s+/g, "").toLowerCase();
    },
    decodeTextMasterSecret(bytes) {
      return bytes[0] === 0x54 ? "decoded text" : null;
    },
    describeTextMasterSecret(value) {
      if (value === "too large") {
        throw new Error("The text is too large for the SLIP39TXT v1 envelope.");
      }
      const utf8ByteLength = new TextEncoder().encode(value).length;
      return {
        utf8ByteLength,
        masterSecretByteLength: 30 + utf8ByteLength + (utf8ByteLength % 2),
        paddingByteLength: utf8ByteLength % 2
      };
    },
    encodeTextMasterSecret(value) {
      return `text:${value}`;
    },
    parseMasterSecretHex(value) {
      return `hex:${value}`;
    }
  };
}

test("secret input mode config exposes labels and placeholders", () => {
  assert.deepEqual(getSecretInputModeConfig(SECRET_INPUT_MODES.HEX), {
    label: "Master secret hex",
    placeholder: "At least 32 hex digits",
    helpText: "Whitespace is ignored; byte length must be even.",
    modeHint: "Hex stores raw bytes. Text wraps UTF-8.",
    recoveryNote: "Raw bytes encoded as lowercase hex"
  });
  assert.equal(getSecretInputModeConfig(SECRET_INPUT_MODES.TEXT).label, "Master secret text");
  assert.equal(
    getSecretInputModeConfig(SECRET_INPUT_MODES.TEXT).modeHint,
    "Hex stores raw bytes. Text wraps UTF-8."
  );
  assert.throws(() => getSecretInputModeConfig("unknown"), /Unsupported master secret input mode/);
});

test("hex input status preserves existing validation messages", () => {
  const core = makeCore();
  const cases = [
    ["", "0 bytes", ""],
    ["zz", "Only hex digits and whitespace", "error"],
    ["0", "Odd hex digit count; fix intentionally", "error"],
    ["00".repeat(15), "15 bytes; minimum is 16 bytes", "warning"],
    ["00".repeat(17), "17 bytes; byte length must be even; fix intentionally", "error"],
    [`  ${"00".repeat(16).toUpperCase()}  `, "16 bytes; normalized 32 hex digits", ""]
  ];

  for (const [value, text, tone] of cases) {
    const status = getSecretInputStatus(SECRET_INPUT_MODES.HEX, value, core);
    assert.equal(status.text, text);
    assert.equal(status.tone, tone);
  }
});

test("text input status shows UTF-8 to SLIP-0039 byte counts", () => {
  const core = makeCore();
  assert.equal(
    getSecretInputStatus(SECRET_INPUT_MODES.TEXT, "abc", core).text,
    "3 UTF-8 bytes -> 34 SLIP-0039 bytes"
  );
  assert.equal(
    getSecretInputStatus(SECRET_INPUT_MODES.TEXT, "a", core).text,
    "1 UTF-8 byte -> 32 SLIP-0039 bytes"
  );
  assert.deepEqual(getSecretInputStatus(SECRET_INPUT_MODES.TEXT, "too large", core), {
    text: "The text is too large for the SLIP39TXT v1 envelope.",
    tone: "error",
    helpText: getSecretInputModeConfig(SECRET_INPUT_MODES.TEXT).helpText
  });
});

test("secret input parsing dispatches by mode", () => {
  const core = makeCore();
  assert.equal(parseSecretInput(SECRET_INPUT_MODES.HEX, "abcd", core), "hex:abcd");
  assert.equal(parseSecretInput(SECRET_INPUT_MODES.TEXT, "hello", core), "text:hello");
  assert.throws(
    () => parseSecretInput("other", "hello", core),
    /Unsupported master secret input mode/
  );
});

test("parsePositiveInteger uses explicit labels", () => {
  assert.equal(parsePositiveInteger({ value: "3" }, "Threshold"), 3);
  assert.throws(
    () => parsePositiveInteger({ value: "2.5" }, "Threshold"),
    /Threshold must be an integer/
  );
  assert.throws(
    () => parsePositiveInteger({ value: "abc" }, "Total shares"),
    /Total shares must be an integer/
  );
});

test("recovery output distinguishes text envelopes from raw bytes", () => {
  const core = makeCore();
  assert.deepEqual(getRecoveryOutput(new Uint8Array([0x00, 0xff]), core), {
    hex: "00ff",
    text: "",
    hasText: false,
    hexHeading: "Recovered master secret hex",
    hexHelpText: "Recovered bytes as lowercase hex.",
    message:
      "Master secret bytes recovered. SLIP-0039 cannot verify whether the passphrase was the intended one.",
    tone: "warning"
  });
  assert.deepEqual(getRecoveryOutput(new Uint8Array([0x54, 0x01]), core), {
    hex: "5401",
    text: "decoded text",
    hasText: true,
    hexHeading: "Recovered envelope hex",
    hexHelpText: "Canonical envelope bytes for SLIP-0039 tools.",
    message:
      "Text envelope recovered. The hex remains the canonical SLIP-0039 master-secret bytes. SLIP-0039 cannot verify whether the passphrase was the intended one.",
    tone: "warning"
  });
});

test("tab hash helpers normalize generate and recover modes", () => {
  assert.equal(tabModeFromHash(""), UI_TABS.GENERATE);
  assert.equal(tabModeFromHash("#generate"), UI_TABS.GENERATE);
  assert.equal(tabModeFromHash("#recover"), UI_TABS.RECOVER);
  assert.equal(tabModeFromHash("#other"), UI_TABS.GENERATE);
  assert.equal(hashForTabMode(UI_TABS.GENERATE), "#generate");
  assert.equal(hashForTabMode(UI_TABS.RECOVER), "#recover");
  assert.equal(hashForTabMode("other"), "#generate");
});
