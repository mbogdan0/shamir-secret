export const SECRET_INPUT_MODES = Object.freeze({
  HEX: "hex",
  TEXT: "text"
} as const);

export type SecretInputMode = "hex" | "text";

export type SecretInputModeConfig = {
  label: string;
  placeholder: string;
  helpText: string;
  modeHint: string;
  recoveryNote: string;
};

export type TextMasterSecretDescription = {
  utf8ByteLength: number;
  masterSecretByteLength: number;
  paddingByteLength: number;
};

export type SecretInputStatus = {
  text: string;
  tone: "" | "warning" | "error";
  helpText: string;
};

export type SecretInputCore = {
  MIN_STRENGTH_BITS: number;
  bitsToBytes(bits: number): number;
  compactHex(value: string): string;
  describeTextMasterSecret(value: string): TextMasterSecretDescription;
  encodeTextMasterSecret(value: string): Uint8Array | Promise<Uint8Array>;
  parseMasterSecretHex(value: string): Uint8Array;
};

const MODE_CONFIG: Readonly<Record<SecretInputMode, SecretInputModeConfig>> = Object.freeze({
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

function assertMode(mode: unknown): asserts mode is SecretInputMode {
  if (mode !== SECRET_INPUT_MODES.HEX && mode !== SECRET_INPUT_MODES.TEXT) {
    throw new Error(`Unsupported master secret input mode: ${String(mode)}`);
  }
}

function formatByteCount(length: number): string {
  return `${length} byte${length === 1 ? "" : "s"}`;
}

function formatLabeledByteCount(length: number, label: string): string {
  return `${length} ${label} byte${length === 1 ? "" : "s"}`;
}

export function getSecretInputModeConfig(mode: unknown): SecretInputModeConfig {
  assertMode(mode);
  return MODE_CONFIG[mode];
}

export function getSecretInputStatus(
  mode: unknown,
  value: string,
  core: SecretInputCore
): SecretInputStatus {
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

export function parseSecretInput(
  mode: unknown,
  value: string,
  core: SecretInputCore
): Uint8Array | Promise<Uint8Array> {
  assertMode(mode);
  return mode === SECRET_INPUT_MODES.TEXT
    ? core.encodeTextMasterSecret(value)
    : core.parseMasterSecretHex(value);
}
