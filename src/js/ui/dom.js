export function getElements() {
  return {
    cryptoStatus: document.querySelector("#cryptoStatus"),
    generateTab: document.querySelector("#generateTab"),
    recoverTab: document.querySelector("#recoverTab"),
    generatePanel: document.querySelector("#generatePanel"),
    recoverPanel: document.querySelector("#recoverPanel"),
    generateForm: document.querySelector("#generateForm"),
    recoverForm: document.querySelector("#recoverForm"),
    secretHexInput: document.querySelector("#secretHexInput"),
    secretBytes: document.querySelector("#secretBytes"),
    generatePassphrase: document.querySelector("#generatePassphrase"),
    recoverPassphrase: document.querySelector("#recoverPassphrase"),
    shareCount: document.querySelector("#shareCount"),
    threshold: document.querySelector("#threshold"),
    sharesResult: document.querySelector("#sharesResult"),
    shareList: document.querySelector("#shareList"),
    recoveryScheme: document.querySelector("#recoveryScheme"),
    sharesInput: document.querySelector("#sharesInput"),
    recoverResult: document.querySelector("#recoverResult"),
    recoveredHex: document.querySelector("#recoveredHex"),
    message: document.querySelector("#message"),
    copyAllShares: document.querySelector("#copyAllShares"),
    copyRecovered: document.querySelector("#copyRecovered"),
    clearGenerate: document.querySelector("#clearGenerate"),
    clearRecover: document.querySelector("#clearRecover")
  };
}
