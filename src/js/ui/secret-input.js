export const SECRET_INPUT_MODES = Object.freeze({
  HEX: "hex",
  TEXT: "text"
});

const MODE_CONFIG = Object.freeze({
  [SECRET_INPUT_MODES.HEX]: {
    label: "Master secret hex",
    placeholder: "32 hex digits minimum; whitespace is ignored; byte length must be even",
    helpText: "Hex mode shares the exact bytes from lowercase-normalized hex. Whitespace is ignored.",
    recoveryNote: "Raw bytes encoded as lowercase hex"
  },
  [SECRET_INPUT_MODES.TEXT]: {
    label: "Master secret text",
    placeholder: "Enter any text; whitespace and new lines are preserved",
    helpText:
      "Text mode stores UTF-8 in a SLIP39TXT v1 envelope with original length, 16 random bytes, and one random padding byte only when needed.",
    recoveryNote: "Text encoded as a SLIP39TXT v1 envelope; external tools recover envelope bytes as hex"
  }
});

function assertMode(mode) {
  if (!Object.hasOwn(MODE_CONFIG, mode)) {
    throw new Error(`Unsupported master secret input mode: ${mode}`);
  }
}

function formatByteCount(length) {
  return `${length} byte${length === 1 ? "" : "s"}`;
}

function formatLabeledByteCount(length, label) {
  return `${length} ${label} byte${length === 1 ? "" : "s"}`;
}

export function getSecretInputModeConfig(mode) {
  assertMode(mode);
  return MODE_CONFIG[mode];
}

export function getSecretInputStatus(mode, value, core) {
  assertMode(mode);

  if (mode === SECRET_INPUT_MODES.TEXT) {
    try {
      const info = core.describeTextMasterSecret(value);
      return {
        text: [
          formatLabeledByteCount(info.utf8ByteLength, "UTF-8"),
          formatLabeledByteCount(info.masterSecretByteLength, "SLIP-0039")
        ].join(" -> "),
        tone: "",
        helpText: MODE_CONFIG[mode].helpText
      };
    } catch (error) {
      return {
        text: error.message,
        tone: "error",
        helpText: MODE_CONFIG[mode].helpText
      };
    }
  }

  const hex = core.compactHex(value);
  if (hex.length === 0) {
    return { text: "0 bytes", tone: "", helpText: MODE_CONFIG[mode].helpText };
  }
  if (/[^0-9a-f]/i.test(hex)) {
    return { text: "Only hex digits and whitespace", tone: "error", helpText: MODE_CONFIG[mode].helpText };
  }
  if (hex.length % 2 !== 0) {
    return { text: "Odd hex digit count; fix intentionally", tone: "error", helpText: MODE_CONFIG[mode].helpText };
  }

  const byteLength = hex.length / 2;
  if (byteLength < core.bitsToBytes(core.MIN_STRENGTH_BITS)) {
    return {
      text: `${formatByteCount(byteLength)}; minimum is 16 bytes`,
      tone: "warning",
      helpText: MODE_CONFIG[mode].helpText
    };
  }
  if (byteLength % 2 !== 0) {
    return {
      text: `${byteLength} bytes; byte length must be even; fix intentionally`,
      tone: "error",
      helpText: MODE_CONFIG[mode].helpText
    };
  }

  return {
    text: `${byteLength} bytes; normalized ${hex.length} hex digits`,
    tone: "",
    helpText: MODE_CONFIG[mode].helpText
  };
}

export function parseSecretInput(mode, value, core) {
  assertMode(mode);
  return mode === SECRET_INPUT_MODES.TEXT
    ? core.encodeTextMasterSecret(value)
    : core.parseMasterSecretHex(value);
}
