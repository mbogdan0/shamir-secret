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
import { hashForTabMode, tabModeFromHash, UI_TABS } from "./tabs.js";

const COPY_FEEDBACK_MS = 1400;

export function startUi(core) {
  const {
    combineMnemonicsFlexible,
    generateMnemonics,
    hasRequiredCrypto
  } = core;
  const elements = getElements();
  const tabs = [elements.generateTab, elements.recoverTab];
  const copyFeedbackTimers = new WeakMap();
  let currentShares = [];

  function setMessage(text, tone = "") {
    setElementMessage(elements, text, tone);
  }

  function selectedSecretMode() {
    return elements.secretInputModes.find((input) => input.checked)?.value ?? SECRET_INPUT_MODES.HEX;
  }

  function updateRecoveryNote(mode) {
    elements.recoveryMasterSecret.textContent = getSecretInputModeConfig(mode).recoveryNote;
  }

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

  function focusTab(index) {
    tabs[index].focus();
    tabs[index].click();
  }

  function handleTabKeydown(event) {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
      return;
    }

    event.preventDefault();
    const currentIndex = tabs.indexOf(event.currentTarget);
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
    copyFeedbackTimers.set(button, setTimeout(() => {
      button.textContent = originalLabel;
      button.classList.remove("is-copied");
      copyFeedbackTimers.delete(button);
    }, COPY_FEEDBACK_MS));
  }

  elements.generateTab.addEventListener("click", () => setTab(UI_TABS.GENERATE));
  elements.recoverTab.addEventListener("click", () => setTab(UI_TABS.RECOVER));
  elements.generateTab.addEventListener("keydown", handleTabKeydown);
  elements.recoverTab.addEventListener("keydown", handleTabKeydown);
  globalThis.addEventListener("hashchange", () => {
    setTab(tabModeFromHash(globalThis.location.hash), { syncHash: false });
  });
  elements.secretHexInput.addEventListener("input", updateSecretInput);
  for (const input of elements.secretInputModes) {
    input.addEventListener("change", updateSecretInput);
  }

  elements.generateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setBusy(elements.generateForm, true);
    setMessage("");

    try {
      const threshold = parsePositiveInteger(elements.threshold, "Threshold");
      const shareCount = parsePositiveInteger(elements.shareCount, "Total shares");
      const mode = selectedSecretMode();
      const masterSecret = parseSecretInput(mode, elements.secretHexInput.value, core);
      const shares = await generateMnemonics(
        threshold,
        shareCount,
        masterSecret,
        elements.generatePassphrase.value,
      );
      currentShares = shares;
      renderShares(elements, shares, threshold, shareCount, copyWithFeedback);
      updateRecoveryNote(mode);
      setMessage("Shares generated. Store each share separately.", "ok");
    } catch (error) {
      elements.sharesResult.hidden = true;
      setMessage(error.message, "error");
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
      const output = renderRecoveryOutput(elements, recovered, core);
      setMessage(output.message, output.tone);
    } catch (error) {
      clearRecoveryOutput(elements);
      setMessage(error.message, "error");
    } finally {
      setBusy(elements.recoverForm, false);
    }
  });

  elements.copyAllShares.addEventListener("click", async () => {
    await copyWithFeedback(elements.copyAllShares, currentShares.join("\n"), "Copied all", "Copied all shares.");
  });

  elements.copyRecovered.addEventListener("click", async () => {
    await copyWithFeedback(elements.copyRecovered, elements.recoveredHex.value, "Copied", "Copied recovered hex.");
  });

  elements.copyRecoveredText.addEventListener("click", async () => {
    await copyWithFeedback(elements.copyRecoveredText, elements.recoveredText.value, "Copied", "Copied recovered text.");
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

  updateRecoveryNote(SECRET_INPUT_MODES.HEX);
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
