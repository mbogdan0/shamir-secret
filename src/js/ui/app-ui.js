import { copyText } from "./clipboard.js";
import { getElements } from "./dom.js";
import { parsePositiveInteger, splitSharesInput } from "./forms.js";
import { setBusy, setMessage as setElementMessage } from "./messages.js";
import { renderShares } from "./shares.js";

export function startUi(core) {
  const {
    bitsToBytes,
    bytesToHex,
    combineMnemonicsFlexible,
    compactHex,
    decodeTextMasterSecret,
    describeTextMasterSecret,
    encodeTextMasterSecret,
    generateMnemonics,
    hasRequiredCrypto,
    MIN_STRENGTH_BITS,
    parseMasterSecretHex
  } = core;
  const elements = getElements();
  let currentShares = [];
  const hexPlaceholder = "32 hex digits minimum; whitespace is ignored; byte length must be even";
  const textPlaceholder = "Enter any text; whitespace and new lines are preserved";

  function setMessage(text, tone = "") {
    setElementMessage(elements, text, tone);
  }

  function formatByteCount(length) {
    return `${length} byte${length === 1 ? "" : "s"}`;
  }

  function isTextMode() {
    return elements.secretTextMode.checked;
  }

  function updateRecoveryNote(textMode) {
    elements.recoveryMasterSecret.textContent = textMode
      ? "Text encoded as a SLIP39TXT v1 envelope; external tools recover envelope bytes as hex"
      : "Raw bytes encoded as lowercase hex";
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

  function updateInputMode() {
    const textMode = isTextMode();
    elements.secretInputLabel.textContent = textMode ? "Master secret text" : "Master secret hex";
    elements.secretHexInput.placeholder = textMode ? textPlaceholder : hexPlaceholder;
    updateByteCount();
  }

  function updateByteCount() {
    if (isTextMode()) {
      elements.secretBytes.className = "";
      elements.secretTransform.textContent =
        "Text mode encodes UTF-8, adds a SLIP39TXT v1 envelope with original length and 16 random bytes, then adds one random padding byte only when needed.";
      try {
        const info = describeTextMasterSecret(elements.secretHexInput.value);
        elements.secretBytes.textContent =
          `${formatByteCount(info.utf8ByteLength)} UTF-8; ${formatByteCount(info.masterSecretByteLength)} SLIP-0039 bytes`;
      } catch (error) {
        elements.secretBytes.textContent = error.message;
        elements.secretBytes.className = "is-error";
      }
      return;
    }

    const hex = compactHex(elements.secretHexInput.value);
    elements.secretBytes.className = "";
    elements.secretTransform.textContent = "Hex mode shares the exact bytes from lowercase-normalized hex. Whitespace is ignored.";
    if (hex.length === 0) {
      elements.secretBytes.textContent = "0 bytes";
      return;
    }
    if (/[^0-9a-f]/i.test(hex)) {
      elements.secretBytes.textContent = "Only hex digits and whitespace";
      elements.secretBytes.className = "is-error";
      return;
    }
    if (hex.length % 2 !== 0) {
      elements.secretBytes.textContent = "Odd hex digit count; fix intentionally";
      elements.secretBytes.className = "is-error";
      return;
    }
    const byteLength = hex.length / 2;
    if (byteLength < bitsToBytes(MIN_STRENGTH_BITS)) {
      elements.secretBytes.textContent = `${byteLength} byte${byteLength === 1 ? "" : "s"}; minimum is 16 bytes`;
      elements.secretBytes.className = "is-warning";
      return;
    }
    if (byteLength % 2 !== 0) {
      elements.secretBytes.textContent = `${byteLength} bytes; byte length must be even; fix intentionally`;
      elements.secretBytes.className = "is-error";
      return;
    }
    elements.secretBytes.textContent = `${byteLength} bytes; normalized ${hex.length} hex digits`;
  }

  function parseMasterSecretInput() {
    return isTextMode()
      ? encodeTextMasterSecret(elements.secretHexInput.value)
      : parseMasterSecretHex(elements.secretHexInput.value);
  }

  elements.generateTab.addEventListener("click", () => setTab("generate"));
  elements.recoverTab.addEventListener("click", () => setTab("recover"));
  elements.secretHexInput.addEventListener("input", updateByteCount);
  elements.secretTextMode.addEventListener("change", updateInputMode);

  elements.generateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setBusy(elements.generateForm, true);
    setMessage("");

    try {
      const threshold = parsePositiveInteger(elements.threshold);
      const shareCount = parsePositiveInteger(elements.shareCount);
      const textMode = isTextMode();
      const shares = await generateMnemonics(
        threshold,
        shareCount,
        parseMasterSecretInput(),
        elements.generatePassphrase.value,
      );
      currentShares = shares;
      renderShares(elements, shares, threshold, shareCount, copyText, setMessage);
      updateRecoveryNote(textMode);
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
      elements.recoveredHex.value = bytesToHex(recovered);
      const recoveredText = decodeTextMasterSecret(recovered);
      if (recoveredText === null) {
        elements.recoveredTextBlock.hidden = true;
        elements.recoveredText.value = "";
        elements.recoveredHexHeading.textContent = "Recovered master secret hex";
        setMessage("Master secret bytes recovered. SLIP-0039 cannot verify whether the passphrase was the intended one.", "warning");
      } else {
        elements.recoveredText.value = recoveredText;
        elements.recoveredTextBlock.hidden = false;
        elements.recoveredHexHeading.textContent = "Recovered envelope hex";
        setMessage(
          "Text envelope recovered. The hex remains the canonical SLIP-0039 master-secret bytes. SLIP-0039 cannot verify whether the passphrase was the intended one.",
          "warning"
        );
      }
      elements.recoverResult.hidden = false;
    } catch (error) {
      elements.recoverResult.hidden = true;
      elements.recoveredTextBlock.hidden = true;
      elements.recoveredText.value = "";
      elements.recoveredHex.value = "";
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
    elements.secretTextMode.checked = false;
    elements.generatePassphrase.value = "";
    elements.sharesResult.hidden = true;
    elements.shareList.replaceChildren();
    currentShares = [];
    updateRecoveryNote(false);
    updateInputMode();
    setMessage("");
  });

  elements.clearRecover.addEventListener("click", () => {
    elements.sharesInput.value = "";
    elements.recoverPassphrase.value = "";
    elements.recoverResult.hidden = true;
    elements.recoveredTextBlock.hidden = true;
    elements.recoveredText.value = "";
    elements.recoveredHexHeading.textContent = "Recovered master secret hex";
    elements.recoveredHex.value = "";
    setMessage("");
  });

  if (hasRequiredCrypto()) {
    elements.cryptoStatus.textContent = "Web Crypto ready";
  } else {
    elements.cryptoStatus.textContent = "Web Crypto unavailable";
    elements.cryptoStatus.classList.add("is-error");
    setMessage("This browser cannot run the required Web Crypto operations.", "error");
  }

  updateRecoveryNote(false);
  updateInputMode();
}
