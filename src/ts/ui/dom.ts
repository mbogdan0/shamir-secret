export type UiElements = {
  cryptoStatus: HTMLElement;
  generateTab: HTMLButtonElement;
  recoverTab: HTMLButtonElement;
  generatePanel: HTMLElement;
  recoverPanel: HTMLElement;
  generateForm: HTMLFormElement;
  recoverForm: HTMLFormElement;
  secretInputLabel: HTMLLabelElement;
  secretHexInput: HTMLTextAreaElement;
  secretInputModes: HTMLInputElement[];
  secretModeHint: HTMLElement;
  secretBytes: HTMLElement;
  secretTransform: HTMLElement;
  generatePassphrase: HTMLInputElement;
  recoverPassphrase: HTMLInputElement;
  shareCount: HTMLInputElement;
  threshold: HTMLInputElement;
  sharesResult: HTMLElement;
  shareList: HTMLOListElement;
  recoveryScheme: HTMLElement;
  recoveryMasterSecret: HTMLElement;
  sharesInput: HTMLTextAreaElement;
  recoverResult: HTMLElement;
  recoveredTextBlock: HTMLElement;
  recoveredText: HTMLTextAreaElement;
  recoveredHexHeading: HTMLElement;
  recoveredHexHelp: HTMLElement;
  recoveredHex: HTMLTextAreaElement;
  message: HTMLElement;
  copyAllShares: HTMLButtonElement;
  copyRecoveredText: HTMLButtonElement;
  copyRecovered: HTMLButtonElement;
  clearGenerate: HTMLButtonElement;
  clearRecover: HTMLButtonElement;
};

function requiredElement(selector: string): Element {
  const element = document.querySelector(selector);
  if (!element) {
    throw new Error(`Missing required element: ${selector}`);
  }
  return element;
}

function requiredElements(selector: string): Element[] {
  const elements = [...document.querySelectorAll(selector)];
  if (elements.length === 0) {
    throw new Error(`Missing required elements: ${selector}`);
  }
  return elements;
}

export function getElements(): UiElements {
  return {
    cryptoStatus: requiredElement("#cryptoStatus") as HTMLElement,
    generateTab: requiredElement("#generateTab") as HTMLButtonElement,
    recoverTab: requiredElement("#recoverTab") as HTMLButtonElement,
    generatePanel: requiredElement("#generatePanel") as HTMLElement,
    recoverPanel: requiredElement("#recoverPanel") as HTMLElement,
    generateForm: requiredElement("#generateForm") as HTMLFormElement,
    recoverForm: requiredElement("#recoverForm") as HTMLFormElement,
    secretInputLabel: requiredElement("#secretInputLabel") as HTMLLabelElement,
    secretHexInput: requiredElement("#secretHexInput") as HTMLTextAreaElement,
    secretInputModes: requiredElements("input[name='secretInputMode']") as HTMLInputElement[],
    secretModeHint: requiredElement("#secretModeHint") as HTMLElement,
    secretBytes: requiredElement("#secretBytes") as HTMLElement,
    secretTransform: requiredElement("#secretTransform") as HTMLElement,
    generatePassphrase: requiredElement("#generatePassphrase") as HTMLInputElement,
    recoverPassphrase: requiredElement("#recoverPassphrase") as HTMLInputElement,
    shareCount: requiredElement("#shareCount") as HTMLInputElement,
    threshold: requiredElement("#threshold") as HTMLInputElement,
    sharesResult: requiredElement("#sharesResult") as HTMLElement,
    shareList: requiredElement("#shareList") as HTMLOListElement,
    recoveryScheme: requiredElement("#recoveryScheme") as HTMLElement,
    recoveryMasterSecret: requiredElement("#recoveryMasterSecret") as HTMLElement,
    sharesInput: requiredElement("#sharesInput") as HTMLTextAreaElement,
    recoverResult: requiredElement("#recoverResult") as HTMLElement,
    recoveredTextBlock: requiredElement("#recoveredTextBlock") as HTMLElement,
    recoveredText: requiredElement("#recoveredText") as HTMLTextAreaElement,
    recoveredHexHeading: requiredElement("#recoveredHexHeading") as HTMLElement,
    recoveredHexHelp: requiredElement("#recoveredHexHelp") as HTMLElement,
    recoveredHex: requiredElement("#recoveredHex") as HTMLTextAreaElement,
    message: requiredElement("#message") as HTMLElement,
    copyAllShares: requiredElement("#copyAllShares") as HTMLButtonElement,
    copyRecoveredText: requiredElement("#copyRecoveredText") as HTMLButtonElement,
    copyRecovered: requiredElement("#copyRecovered") as HTMLButtonElement,
    clearGenerate: requiredElement("#clearGenerate") as HTMLButtonElement,
    clearRecover: requiredElement("#clearRecover") as HTMLButtonElement
  };
}
