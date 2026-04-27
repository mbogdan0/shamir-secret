import { copyText } from "./clipboard.js";
import { getElements } from "./dom.js";
import { parsePositiveInteger, splitSharesInput } from "./forms.js";
import { clearRecoveryOutput, renderRecoveryOutput } from "./recovery-output.js";
import {
  getSecretInputModeConfig,
  getSecretInputStatus,
  parseSecretInput,
  SECRET_INPUT_MODES
} from "./secret-input.js";
import { setBusy, setMessage as setElementMessage } from "./messages.js";
import { renderShares } from "./shares.js";
import {
  hrefForSecretInputMode,
  hashForTabMode,
  normalizeSecretInputMode,
  searchForSecretInputMode,
  secretInputModeFromSearch,
  tabModeFromHash,
  UI_TABS
} from "./tabs.js";

const COPY_FEEDBACK_MS = 1400;

/**
 * @typedef {import("./secret-input.js").SecretInputCore & import("./recovery-output.js").RecoveryCore & {
 *   combineMnemonicsFlexible(mnemonics: string[], passphrase?: string): Promise<Uint8Array>,
 *   generateMnemonics(threshold: number, shareCount: number, masterSecret: Uint8Array, passphrase?: string): Promise<string[]>,
 *   hasRequiredCrypto(): boolean
 * }} AppCore
 * @typedef {ReturnType<typeof import("./dom.js").getElements>} UiElements
 * @typedef {{ clearMessage?: boolean, syncHash?: boolean }} SetTabOptions
 */

/**
 * @param {unknown} error
 * @returns {string}
 */
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * @param {AppCore} core
 */
export function startUi(core) {
  const { combineMnemonicsFlexible, generateMnemonics, hasRequiredCrypto } = core;
  const elements = getElements();
  const tabs = [elements.generateTab, elements.recoverTab];
  /** @type {WeakMap<HTMLButtonElement, ReturnType<typeof setTimeout>>} */
  const copyFeedbackTimers = new WeakMap();
  /** @type {string[]} */
  let currentShares = [];

  /**
   * @param {string} text
   * @param {string} [tone]
   */
  function setMessage(text, tone = "") {
    setElementMessage(elements, text, tone);
  }

  /**
   * @returns {import("./tabs.js").SecretInputMode}
   */
  function selectedSecretMode() {
    return normalizeSecretInputMode(
      elements.secretInputModes.find((input) => input.checked)?.value
    );
  }

  /**
   * @param {unknown} mode
   * @returns {import("./tabs.js").SecretInputMode}
   */
  function setSelectedSecretMode(mode) {
    const normalizedMode = normalizeSecretInputMode(mode);
    for (const input of elements.secretInputModes) {
      input.checked = input.value === normalizedMode;
    }
    return normalizedMode;
  }

  /**
   * @param {unknown} mode
   */
  function updateRecoveryNote(mode) {
    elements.recoveryMasterSecret.textContent = getSecretInputModeConfig(mode).recoveryNote;
  }

  /**
   * @param {unknown} mode
   */
  function syncHashToTab(mode) {
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

  /**
   * @param {unknown} mode
   */
  function syncSearchToSecretMode(mode) {
    const nextSearch = searchForSecretInputMode(globalThis.location.search, mode);
    if (globalThis.location.search === nextSearch || !globalThis.history?.replaceState) {
      return;
    }
    globalThis.history.replaceState(null, "", hrefForSecretInputMode(globalThis.location, mode));
  }

  /**
   * @param {unknown} mode
   * @param {SetTabOptions} [options]
   */
  function setTab(mode, options = {}) {
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

  /**
   * @param {number} index
   */
  function focusTab(index) {
    tabs[index].focus();
    tabs[index].click();
  }

  /**
   * @param {KeyboardEvent} event
   */
  function handleTabKeydown(event) {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
      return;
    }

    event.preventDefault();
    const currentIndex = tabs.indexOf(/** @type {HTMLButtonElement} */ (event.currentTarget));
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

  function handleSecretInputModeChange() {
    const mode = selectedSecretMode();
    syncSearchToSecretMode(mode);
    updateRecoveryNote(mode);
    updateSecretInput();
  }

  function updateSecretInput() {
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

  function resetGenerateResult() {
    elements.sharesResult.hidden = true;
    elements.shareList.replaceChildren();
    currentShares = [];
  }

  /**
   * @param {HTMLButtonElement} button
   * @param {string} text
   * @param {string} copiedLabel
   * @param {string} statusMessage
   * @returns {Promise<void>}
   */
  async function copyWithFeedback(button, text, copiedLabel, statusMessage) {
    const originalLabel = button.dataset.originalLabel || button.textContent;
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
    handleTabKeydown(/** @type {KeyboardEvent} */ (event));
  });
  elements.recoverTab.addEventListener("keydown", (event) => {
    handleTabKeydown(/** @type {KeyboardEvent} */ (event));
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
      const masterSecret = /** @type {Uint8Array} */ (
        await parseSecretInput(mode, elements.secretHexInput.value, core)
      );
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
