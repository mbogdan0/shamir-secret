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
    generateMnemonics,
    hasRequiredCrypto,
    MIN_STRENGTH_BITS,
    parseMasterSecretHex
  } = core;
  const elements = getElements();
  let currentShares = [];

  function setMessage(text, tone = "") {
    setElementMessage(elements, text, tone);
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

  function updateByteCount() {
    const hex = compactHex(elements.secretHexInput.value);
    elements.secretBytes.className = "";
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

  elements.generateTab.addEventListener("click", () => setTab("generate"));
  elements.recoverTab.addEventListener("click", () => setTab("recover"));
  elements.secretHexInput.addEventListener("input", updateByteCount);

  elements.generateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setBusy(elements.generateForm, true);
    setMessage("");

    try {
      const threshold = parsePositiveInteger(elements.threshold);
      const shareCount = parsePositiveInteger(elements.shareCount);
      const shares = await generateMnemonics(
        threshold,
        shareCount,
        parseMasterSecretHex(elements.secretHexInput.value),
        elements.generatePassphrase.value,
      );
      currentShares = shares;
      renderShares(elements, shares, threshold, shareCount, copyText, setMessage);
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
      elements.recoverResult.hidden = false;
      setMessage("Master secret bytes recovered. SLIP-0039 cannot verify whether the passphrase was the intended one.", "warning");
    } catch (error) {
      elements.recoverResult.hidden = true;
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

  elements.clearGenerate.addEventListener("click", () => {
    elements.secretHexInput.value = "";
    elements.generatePassphrase.value = "";
    elements.sharesResult.hidden = true;
    elements.shareList.replaceChildren();
    currentShares = [];
    updateByteCount();
    setMessage("");
  });

  elements.clearRecover.addEventListener("click", () => {
    elements.sharesInput.value = "";
    elements.recoverPassphrase.value = "";
    elements.recoverResult.hidden = true;
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

  updateByteCount();
}
