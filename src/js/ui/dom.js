function requiredElement(selector) {
  const element = document.querySelector(selector);
  if (!element) {
    throw new Error(`Missing required element: ${selector}`);
  }
  return element;
}

function requiredElements(selector) {
  const elements = [...document.querySelectorAll(selector)];
  if (elements.length === 0) {
    throw new Error(`Missing required elements: ${selector}`);
  }
  return elements;
}

export function getElements() {
  return {
    cryptoStatus: requiredElement("#cryptoStatus"),
    generateTab: requiredElement("#generateTab"),
    recoverTab: requiredElement("#recoverTab"),
    generatePanel: requiredElement("#generatePanel"),
    recoverPanel: requiredElement("#recoverPanel"),
    generateForm: requiredElement("#generateForm"),
    recoverForm: requiredElement("#recoverForm"),
    secretInputLabel: requiredElement("#secretInputLabel"),
    secretHexInput: requiredElement("#secretHexInput"),
    secretInputModes: requiredElements("input[name='secretInputMode']"),
    secretModeHint: requiredElement("#secretModeHint"),
    secretBytes: requiredElement("#secretBytes"),
    secretTransform: requiredElement("#secretTransform"),
    generatePassphrase: requiredElement("#generatePassphrase"),
    recoverPassphrase: requiredElement("#recoverPassphrase"),
    shareCount: requiredElement("#shareCount"),
    threshold: requiredElement("#threshold"),
    sharesResult: requiredElement("#sharesResult"),
    shareList: requiredElement("#shareList"),
    recoveryScheme: requiredElement("#recoveryScheme"),
    recoveryMasterSecret: requiredElement("#recoveryMasterSecret"),
    sharesInput: requiredElement("#sharesInput"),
    recoverResult: requiredElement("#recoverResult"),
    recoveredTextBlock: requiredElement("#recoveredTextBlock"),
    recoveredText: requiredElement("#recoveredText"),
    recoveredHexHeading: requiredElement("#recoveredHexHeading"),
    recoveredHexHelp: requiredElement("#recoveredHexHelp"),
    recoveredHex: requiredElement("#recoveredHex"),
    message: requiredElement("#message"),
    copyAllShares: requiredElement("#copyAllShares"),
    copyRecoveredText: requiredElement("#copyRecoveredText"),
    copyRecovered: requiredElement("#copyRecovered"),
    clearGenerate: requiredElement("#clearGenerate"),
    clearRecover: requiredElement("#clearRecover")
  };
}
