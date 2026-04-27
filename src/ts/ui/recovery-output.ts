import type { UiElements } from "./dom.ts";

export type RecoveryCore = {
  bytesToHex(bytes: Uint8Array): string;
  decodeTextMasterSecret(bytes: Uint8Array): string | null | Promise<string | null>;
};

export type RecoveryOutput = {
  hex: string;
  text: string;
  hasText: boolean;
  hexHeading: string;
  hexHelpText: string;
  message: string;
  tone: "warning";
};

export async function getRecoveryOutput(
  recovered: Uint8Array,
  core: RecoveryCore
): Promise<RecoveryOutput> {
  const text = await core.decodeTextMasterSecret(recovered);
  const hex = core.bytesToHex(recovered);

  if (text === null) {
    return {
      hex,
      text: "",
      hasText: false,
      hexHeading: "Recovered master secret hex",
      hexHelpText: "Recovered bytes as lowercase hex.",
      message:
        "Master secret bytes recovered. SLIP-0039 cannot verify whether the passphrase was the intended one.",
      tone: "warning"
    };
  }

  return {
    hex,
    text,
    hasText: true,
    hexHeading: "Recovered envelope hex",
    hexHelpText: "Canonical envelope bytes for SLIP-0039 tools.",
    message:
      "Text envelope recovered. The hex remains the canonical SLIP-0039 master-secret bytes. SLIP-0039 cannot verify whether the passphrase was the intended one.",
    tone: "warning"
  };
}

export async function renderRecoveryOutput(
  elements: UiElements,
  recovered: Uint8Array,
  core: RecoveryCore
): Promise<RecoveryOutput> {
  const output = await getRecoveryOutput(recovered, core);
  elements.recoveredTextBlock.hidden = !output.hasText;
  elements.recoveredText.value = output.text;
  elements.recoveredHexHeading.textContent = output.hexHeading;
  elements.recoveredHexHelp.textContent = output.hexHelpText;
  elements.recoveredHex.value = output.hex;
  elements.recoverResult.hidden = false;
  return output;
}

export function clearRecoveryOutput(elements: UiElements): void {
  elements.recoverResult.hidden = true;
  elements.recoveredTextBlock.hidden = true;
  elements.recoveredText.value = "";
  elements.recoveredHexHeading.textContent = "Recovered master secret hex";
  elements.recoveredHexHelp.textContent = "Recovered bytes as lowercase hex.";
  elements.recoveredHex.value = "";
}
