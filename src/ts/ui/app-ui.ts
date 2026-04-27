import { copyText } from "./clipboard.ts";
import { getElements, type UiElements } from "./dom.ts";
import { parsePositiveInteger, splitSharesInput } from "./forms.ts";
import { clearRecoveryOutput, renderRecoveryOutput, type RecoveryCore } from "./recovery-output.ts";
import {
  getSecretInputModeConfig,
  getSecretInputStatus,
  parseSecretInput,
  SECRET_INPUT_MODES,
  type SecretInputCore
} from "./secret-input.ts";
import { setBusy, setMessage as setElementMessage } from "./messages.ts";
import { renderShares } from "./shares.ts";
import {
  hashForTabMode,
  hrefForSecretInputMode,
  normalizeSecretInputMode,
  searchForSecretInputMode,
  secretInputModeFromSearch,
  tabModeFromHash,
  UI_TABS,
  type SecretInputMode,
  type TabMode
} from "./tabs.ts";

const COPY_FEEDBACK_MS = 1400;

export type AppCore = SecretInputCore &
  RecoveryCore & {
    combineMnemonicsFlexible(mnemonics: string[], passphrase?: string): Promise<Uint8Array>;
    generateMnemonics(
      threshold: number,
      shareCount: number,
      masterSecret: Uint8Array,
      passphrase?: string
    ): Promise<string[]>;
    hasRequiredCrypto(): boolean;
  };

type SetTabOptions = { clearMessage?: boolean; syncHash?: boolean };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function startUi(core: AppCore): void {
  const { combineMnemonicsFlexible, generateMnemonics, hasRequiredCrypto } = core;
  const elements: UiElements = getElements();
  const tabs = [elements.generateTab, elements.recoverTab];
  const copyFeedbackTimers = new WeakMap<HTMLButtonElement, ReturnType<typeof setTimeout>>();
  let currentShares: string[] = [];

  function setMessage(text: string, tone: string = ""): void {
    setElementMessage(elements, text, tone);
  }

  function selectedSecretMode(): SecretInputMode {
    return normalizeSecretInputMode(
      elements.secretInputModes.find((input) => input.checked)?.value
    );
  }

  function setSelectedSecretMode(mode: unknown): SecretInputMode {
    const normalizedMode = normalizeSecretInputMode(mode);
    for (const input of elements.secretInputModes) {
      input.checked = input.value === normalizedMode;
    }
    return normalizedMode;
  }

  function updateRecoveryNote(mode: unknown): void {
    elements.recoveryMasterSecret.textContent = getSecretInputModeConfig(mode).recoveryNote;
  }

  function syncHashToTab(mode: unknown): void {
    const nextHash = hashForTabMode(mode);
    if (globalThis.location.hash === nextHash) {
      return;
    }
    if (!globalThis.location.hash && globalThis.history?.replaceState) {
      globalThis.history.replaceState(null, "", nextHash);
      return;
    }
    globalThis.location.hash = nextHash;
  }

  function syncSearchToSecretMode(mode: unknown): void {
    const nextSearch = searchForSecretInputMode(globalThis.location.search, mode);
    if (globalThis.location.search === nextSearch || !globalThis.history?.replaceState) {
      return;
    }
    globalThis.history.replaceState(null, "", hrefForSecretInputMode(globalThis.location, mode));
  }

  function setTab(mode: TabMode | unknown, options: SetTabOptions = {}): void {
    const { clearMessage = true, syncHash = true } = options;
    const generating = mode === UI_TABS.GENERATE;
    elements.generateTab.classList.toggle("is-active", generating);
    elements.recoverTab.classList.toggle("is-active", !generating);
    elements.generateTab.setAttribute("aria-selected", String(generating));
    elements.recoverTab.setAttribute("aria-selected", String(!generating));
    elements.generatePanel.hidden = !generating;
    elements.recoverPanel.hidden = generating;
    if (syncHash) {
      syncHashToTab(generating ? UI_TABS.GENERATE : UI_TABS.RECOVER);
    }
    if (clearMessage) {
      setMessage("");
    }
  }

  function focusTab(index: number): void {
    tabs[index].focus();
    tabs[index].click();
  }

  function handleTabKeydown(event: KeyboardEvent): void {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
      return;
    }

    event.preventDefault();
    const currentIndex = tabs.indexOf(event.currentTarget as HTMLButtonElement);
    if (event.key === "Home") {
      focusTab(0);
      return;
    }
    if (event.key === "End") {
      focusTab(tabs.length - 1);
      return;
    }
    const direction = event.key === "ArrowRight" ? 1 : -1;
    focusTab((currentIndex + direction + tabs.length) % tabs.length);
  }

  function handleSecretInputModeChange(): void {
    const mode = selectedSecretMode();
    syncSearchToSecretMode(mode);
    updateRecoveryNote(mode);
    updateSecretInput();
  }

  function updateSecretInput(): void {
    const mode = selectedSecretMode();
    const config = getSecretInputModeConfig(mode);
    const status = getSecretInputStatus(mode, elements.secretHexInput.value, core);
    elements.secretInputLabel.textContent = config.label;
    elements.secretHexInput.placeholder = config.placeholder;
    elements.secretHexInput.classList.toggle("is-text-mode", mode === SECRET_INPUT_MODES.TEXT);
    elements.secretModeHint.textContent = config.modeHint;
    elements.secretBytes.textContent = status.text;
    elements.secretBytes.className = ["field-status", status.tone ? `is-${status.tone}` : ""]
      .filter(Boolean)
      .join(" ");
    elements.secretTransform.textContent = status.helpText;
  }

  function resetGenerateResult(): void {
    elements.sharesResult.hidden = true;
    elements.shareList.replaceChildren();
    currentShares = [];
  }

  async function copyWithFeedback(
    button: HTMLButtonElement,
    text: string,
    copiedLabel: string,
    statusMessage: string
  ): Promise<void> {
    const originalLabel = button.dataset.originalLabel || button.textContent || "";
    button.dataset.originalLabel = originalLabel;
    try {
      await copyText(text);
    } catch {
      setMessage("Copy failed. Check browser clipboard permissions.", "error");
      return;
    }
    setMessage(statusMessage, "ok");
    button.textContent = copiedLabel;
    button.classList.add("is-copied");
    clearTimeout(copyFeedbackTimers.get(button));
    copyFeedbackTimers.set(
      button,
      globalThis.setTimeout(() => {
        button.textContent = originalLabel;
        button.classList.remove("is-copied");
        copyFeedbackTimers.delete(button);
      }, COPY_FEEDBACK_MS)
    );
  }

  elements.generateTab.addEventListener("click", () => setTab(UI_TABS.GENERATE));
  elements.recoverTab.addEventListener("click", () => setTab(UI_TABS.RECOVER));
  elements.generateTab.addEventListener("keydown", (event) => {
    handleTabKeydown(event as KeyboardEvent);
  });
  elements.recoverTab.addEventListener("keydown", (event) => {
    handleTabKeydown(event as KeyboardEvent);
  });
  globalThis.addEventListener("hashchange", () => {
    setTab(tabModeFromHash(globalThis.location.hash), { syncHash: false });
  });
  elements.secretHexInput.addEventListener("input", updateSecretInput);
  for (const input of elements.secretInputModes) {
    input.addEventListener("change", handleSecretInputModeChange);
  }

  elements.generateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setBusy(elements.generateForm, true);
    setMessage("");

    try {
      const threshold = parsePositiveInteger(elements.threshold, "Threshold");
      const shareCount = parsePositiveInteger(elements.shareCount, "Total shares");
      const mode = selectedSecretMode();
      const masterSecret = await parseSecretInput(mode, elements.secretHexInput.value, core);
      const shares = await generateMnemonics(
        threshold,
        shareCount,
        masterSecret,
        elements.generatePassphrase.value
      );
      currentShares = shares;
      renderShares(elements, shares, threshold, shareCount, copyWithFeedback);
      updateRecoveryNote(mode);
      setMessage("Shares generated. Store each share separately.", "ok");
    } catch (error) {
      elements.sharesResult.hidden = true;
      setMessage(errorMessage(error), "error");
    } finally {
      setBusy(elements.generateForm, false);
    }
  });

  elements.recoverForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setBusy(elements.recoverForm, true);
    setMessage("");

    try {
      const mnemonics = splitSharesInput(elements.sharesInput.value);
      const recovered = await combineMnemonicsFlexible(mnemonics, elements.recoverPassphrase.value);
      const output = await renderRecoveryOutput(elements, recovered, core);
      setMessage(output.message, output.tone);
    } catch (error) {
      clearRecoveryOutput(elements);
      setMessage(errorMessage(error), "error");
    } finally {
      setBusy(elements.recoverForm, false);
    }
  });

  elements.copyAllShares.addEventListener("click", async () => {
    await copyWithFeedback(
      elements.copyAllShares,
      currentShares.join("\n"),
      "Copied all",
      "Copied all shares."
    );
  });

  elements.copyRecovered.addEventListener("click", async () => {
    await copyWithFeedback(
      elements.copyRecovered,
      elements.recoveredHex.value,
      "Copied",
      "Copied recovered hex."
    );
  });

  elements.copyRecoveredText.addEventListener("click", async () => {
    await copyWithFeedback(
      elements.copyRecoveredText,
      elements.recoveredText.value,
      "Copied",
      "Copied recovered text."
    );
  });

  elements.clearGenerate.addEventListener("click", () => {
    elements.secretHexInput.value = "";
    elements.generatePassphrase.value = "";
    resetGenerateResult();
    updateRecoveryNote(selectedSecretMode());
    updateSecretInput();
    setMessage("");
  });

  elements.clearRecover.addEventListener("click", () => {
    elements.sharesInput.value = "";
    elements.recoverPassphrase.value = "";
    clearRecoveryOutput(elements);
    setMessage("");
  });

  const initialSecretMode = setSelectedSecretMode(
    secretInputModeFromSearch(globalThis.location.search)
  );
  syncSearchToSecretMode(initialSecretMode);
  updateRecoveryNote(initialSecretMode);
  updateSecretInput();
  setTab(tabModeFromHash(globalThis.location.hash), { clearMessage: false });

  if (hasRequiredCrypto()) {
    elements.cryptoStatus.hidden = true;
  } else {
    elements.cryptoStatus.textContent = "Web Crypto unavailable";
    elements.cryptoStatus.hidden = false;
    elements.cryptoStatus.classList.add("is-error");
    setMessage("This browser cannot run the required Web Crypto operations.", "error");
  }
}
