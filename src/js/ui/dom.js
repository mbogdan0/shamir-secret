/**
 * @typedef {{
 *   cryptoStatus: HTMLElement,
 *   generateTab: HTMLButtonElement,
 *   recoverTab: HTMLButtonElement,
 *   generatePanel: HTMLElement,
 *   recoverPanel: HTMLElement,
 *   generateForm: HTMLFormElement,
 *   recoverForm: HTMLFormElement,
 *   secretInputLabel: HTMLLabelElement,
 *   secretHexInput: HTMLTextAreaElement,
 *   secretInputModes: HTMLInputElement[],
 *   secretModeHint: HTMLElement,
 *   secretBytes: HTMLElement,
 *   secretTransform: HTMLElement,
 *   generatePassphrase: HTMLInputElement,
 *   recoverPassphrase: HTMLInputElement,
 *   shareCount: HTMLInputElement,
 *   threshold: HTMLInputElement,
 *   sharesResult: HTMLElement,
 *   shareList: HTMLOListElement,
 *   recoveryScheme: HTMLElement,
 *   recoveryMasterSecret: HTMLElement,
 *   sharesInput: HTMLTextAreaElement,
 *   recoverResult: HTMLElement,
 *   recoveredTextBlock: HTMLElement,
 *   recoveredText: HTMLTextAreaElement,
 *   recoveredHexHeading: HTMLElement,
 *   recoveredHexHelp: HTMLElement,
 *   recoveredHex: HTMLTextAreaElement,
 *   message: HTMLElement,
 *   copyAllShares: HTMLButtonElement,
 *   copyRecoveredText: HTMLButtonElement,
 *   copyRecovered: HTMLButtonElement,
 *   clearGenerate: HTMLButtonElement,
 *   clearRecover: HTMLButtonElement
 * }} UiElements
 */

/**
 * @param {string} selector
 * @returns {Element}
 */
function requiredElement(selector) {
  const element = document.querySelector(selector);
  if (!element) {
    throw new Error(`Missing required element: ${selector}`);
  }
  return element;
}

/**
 * @param {string} selector
 * @returns {Element[]}
 */
function requiredElements(selector) {
  const elements = [...document.querySelectorAll(selector)];
  if (elements.length === 0) {
    throw new Error(`Missing required elements: ${selector}`);
  }
  return elements;
}

/**
 * @returns {UiElements}
 */
export function getElements() {
  return {
    cryptoStatus: /** @type {HTMLElement} */ (requiredElement("#cryptoStatus")),
    generateTab: /** @type {HTMLButtonElement} */ (requiredElement("#generateTab")),
    recoverTab: /** @type {HTMLButtonElement} */ (requiredElement("#recoverTab")),
    generatePanel: /** @type {HTMLElement} */ (requiredElement("#generatePanel")),
    recoverPanel: /** @type {HTMLElement} */ (requiredElement("#recoverPanel")),
    generateForm: /** @type {HTMLFormElement} */ (requiredElement("#generateForm")),
    recoverForm: /** @type {HTMLFormElement} */ (requiredElement("#recoverForm")),
    secretInputLabel: /** @type {HTMLLabelElement} */ (requiredElement("#secretInputLabel")),
    secretHexInput: /** @type {HTMLTextAreaElement} */ (requiredElement("#secretHexInput")),
    secretInputModes: /** @type {HTMLInputElement[]} */ (
      requiredElements("input[name='secretInputMode']")
    ),
    secretModeHint: /** @type {HTMLElement} */ (requiredElement("#secretModeHint")),
    secretBytes: /** @type {HTMLElement} */ (requiredElement("#secretBytes")),
    secretTransform: /** @type {HTMLElement} */ (requiredElement("#secretTransform")),
    generatePassphrase: /** @type {HTMLInputElement} */ (requiredElement("#generatePassphrase")),
    recoverPassphrase: /** @type {HTMLInputElement} */ (requiredElement("#recoverPassphrase")),
    shareCount: /** @type {HTMLInputElement} */ (requiredElement("#shareCount")),
    threshold: /** @type {HTMLInputElement} */ (requiredElement("#threshold")),
    sharesResult: /** @type {HTMLElement} */ (requiredElement("#sharesResult")),
    shareList: /** @type {HTMLOListElement} */ (requiredElement("#shareList")),
    recoveryScheme: /** @type {HTMLElement} */ (requiredElement("#recoveryScheme")),
    recoveryMasterSecret: /** @type {HTMLElement} */ (requiredElement("#recoveryMasterSecret")),
    sharesInput: /** @type {HTMLTextAreaElement} */ (requiredElement("#sharesInput")),
    recoverResult: /** @type {HTMLElement} */ (requiredElement("#recoverResult")),
    recoveredTextBlock: /** @type {HTMLElement} */ (requiredElement("#recoveredTextBlock")),
    recoveredText: /** @type {HTMLTextAreaElement} */ (requiredElement("#recoveredText")),
    recoveredHexHeading: /** @type {HTMLElement} */ (requiredElement("#recoveredHexHeading")),
    recoveredHexHelp: /** @type {HTMLElement} */ (requiredElement("#recoveredHexHelp")),
    recoveredHex: /** @type {HTMLTextAreaElement} */ (requiredElement("#recoveredHex")),
    message: /** @type {HTMLElement} */ (requiredElement("#message")),
    copyAllShares: /** @type {HTMLButtonElement} */ (requiredElement("#copyAllShares")),
    copyRecoveredText: /** @type {HTMLButtonElement} */ (requiredElement("#copyRecoveredText")),
    copyRecovered: /** @type {HTMLButtonElement} */ (requiredElement("#copyRecovered")),
    clearGenerate: /** @type {HTMLButtonElement} */ (requiredElement("#clearGenerate")),
    clearRecover: /** @type {HTMLButtonElement} */ (requiredElement("#clearRecover"))
  };
}
