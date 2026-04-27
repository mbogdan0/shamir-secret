export const SECRET_INPUT_MODES = /** @type {{ readonly HEX: "hex", readonly TEXT: "text" }} */ (
  Object.freeze({
    HEX: "hex",
    TEXT: "text"
  })
);

/**
 * @typedef {"hex" | "text"} SecretInputMode
 * @typedef {{ label: string, placeholder: string, helpText: string, modeHint: string, recoveryNote: string }} SecretInputModeConfig
 * @typedef {{ utf8ByteLength: number, masterSecretByteLength: number, paddingByteLength: number }} TextMasterSecretDescription
 * @typedef {{ text: string, tone: "" | "warning" | "error", helpText: string }} SecretInputStatus
 * @typedef {{
 *   MIN_STRENGTH_BITS: number,
 *   bitsToBytes(bits: number): number,
 *   compactHex(value: string): string,
 *   describeTextMasterSecret(value: string): TextMasterSecretDescription,
 *   encodeTextMasterSecret(value: string): unknown,
 *   parseMasterSecretHex(value: string): unknown
 * }} SecretInputCore
 */

/** @type {Readonly<Record<SecretInputMode, SecretInputModeConfig>>} */
const MODE_CONFIG = Object.freeze({
  [SECRET_INPUT_MODES.HEX]: {
    label: "Master secret hex",
    placeholder: "At least 32 hex digits",
    helpText: "Whitespace is ignored; byte length must be even.",
    modeHint: "Hex stores raw bytes. Text wraps UTF-8.",
    recoveryNote: "Raw bytes encoded as lowercase hex"
  },
  [SECRET_INPUT_MODES.TEXT]: {
    label: "Master secret text",
    placeholder: "Enter text to protect",
    helpText: "Spacing and new lines are preserved.",
    modeHint: "Hex stores raw bytes. Text wraps UTF-8.",
    recoveryNote:
      "Text encoded as a SLIP39TXT v1 envelope; external tools recover envelope bytes as hex"
  }
});

/**
 * @param {unknown} mode
 * @returns {asserts mode is SecretInputMode}
 */
function assertMode(mode) {
  if (mode !== SECRET_INPUT_MODES.HEX && mode !== SECRET_INPUT_MODES.TEXT) {
    throw new Error(`Unsupported master secret input mode: ${mode}`);
  }
}

/**
 * @param {number} length
 * @returns {string}
 */
function formatByteCount(length) {
  return `${length} byte${length === 1 ? "" : "s"}`;
}

/**
 * @param {number} length
 * @param {string} label
 * @returns {string}
 */
function formatLabeledByteCount(length, label) {
  return `${length} ${label} byte${length === 1 ? "" : "s"}`;
}

/**
 * @param {unknown} mode
 * @returns {SecretInputModeConfig}
 */
export function getSecretInputModeConfig(mode) {
  assertMode(mode);
  return MODE_CONFIG[mode];
}

/**
 * @param {unknown} mode
 * @param {string} value
 * @param {SecretInputCore} core
 * @returns {SecretInputStatus}
 */
export function getSecretInputStatus(mode, value, core) {
  const config = getSecretInputModeConfig(mode);

  if (mode === SECRET_INPUT_MODES.TEXT) {
    try {
      const info = core.describeTextMasterSecret(value);
      return {
        text: [
          formatLabeledByteCount(info.utf8ByteLength, "UTF-8"),
          formatLabeledByteCount(info.masterSecretByteLength, "SLIP-0039")
        ].join(" -> "),
        tone: "",
        helpText: config.helpText
      };
    } catch (error) {
      return {
        text: error instanceof Error ? error.message : String(error),
        tone: "error",
        helpText: config.helpText
      };
    }
  }

  const hex = core.compactHex(value);
  if (hex.length === 0) {
    return { text: "0 bytes", tone: "", helpText: config.helpText };
  }
  if (/[^0-9a-f]/i.test(hex)) {
    return {
      text: "Only hex digits and whitespace",
      tone: "error",
      helpText: config.helpText
    };
  }
  if (hex.length % 2 !== 0) {
    return {
      text: "Odd hex digit count; fix intentionally",
      tone: "error",
      helpText: config.helpText
    };
  }

  const byteLength = hex.length / 2;
  if (byteLength < core.bitsToBytes(core.MIN_STRENGTH_BITS)) {
    return {
      text: `${formatByteCount(byteLength)}; minimum is 16 bytes`,
      tone: "warning",
      helpText: config.helpText
    };
  }
  if (byteLength % 2 !== 0) {
    return {
      text: `${byteLength} bytes; byte length must be even; fix intentionally`,
      tone: "error",
      helpText: config.helpText
    };
  }

  return {
    text: `${byteLength} bytes; normalized ${hex.length} hex digits`,
    tone: "",
    helpText: config.helpText
  };
}

/**
 * @param {unknown} mode
 * @param {string} value
 * @param {SecretInputCore} core
 * @returns {unknown}
 */
export function parseSecretInput(mode, value, core) {
  assertMode(mode);
  return mode === SECRET_INPUT_MODES.TEXT
    ? core.encodeTextMasterSecret(value)
    : core.parseMasterSecretHex(value);
}
