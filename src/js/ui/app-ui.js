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

export function startUi(core) {
  const {
    combineMnemonicsFlexible,
    generateMnemonics,
    hasRequiredCrypto
  } = core;
  const elements = getElements();
  const tabs = [elements.generateTab, elements.recoverTab];
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

  function setTab(mode) {
    const generating = mode === "generate";
    elements.generateTab.classList.toggle("is-active", generating);
    elements.recoverTab.classList.toggle("is-active", !generating);
    elements.generateTab.setAttribute("aria-selected", String(generating));
    elements.recoverTab.setAttribute("aria-selected", String(!generating));
    elements.generatePanel.hidden = !generating;
    elements.recoverPanel.hidden = generating;
    setMessage("");
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
    elements.secretBytes.textContent = status.text;
    elements.secretBytes.className = status.tone ? `is-${status.tone}` : "";
    elements.secretTransform.textContent = status.helpText;
  }

  function resetGenerateResult() {
    elements.sharesResult.hidden = true;
    elements.shareList.replaceChildren();
    currentShares = [];
  }

  elements.generateTab.addEventListener("click", () => setTab("generate"));
  elements.recoverTab.addEventListener("click", () => setTab("recover"));
  elements.generateTab.addEventListener("keydown", handleTabKeydown);
  elements.recoverTab.addEventListener("keydown", handleTabKeydown);
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
      renderShares(elements, shares, threshold, shareCount, copyText, setMessage);
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
    await copyText(currentShares.join("\n"));
    setMessage("Copied all shares.", "ok");
  });

  elements.copyRecovered.addEventListener("click", async () => {
    await copyText(elements.recoveredHex.value);
    setMessage("Copied recovered hex.", "ok");
  });

  elements.copyRecoveredText.addEventListener("click", async () => {
    await copyText(elements.recoveredText.value);
    setMessage("Copied recovered text.", "ok");
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

  if (hasRequiredCrypto()) {
    elements.cryptoStatus.textContent = "Web Crypto ready";
  } else {
    elements.cryptoStatus.textContent = "Web Crypto unavailable";
    elements.cryptoStatus.classList.add("is-error");
    setMessage("This browser cannot run the required Web Crypto operations.", "error");
  }

  updateRecoveryNote(SECRET_INPUT_MODES.HEX);
  updateSecretInput();
}
