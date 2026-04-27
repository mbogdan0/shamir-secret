/**
 * @typedef {ReturnType<typeof import("./dom.js").getElements>} UiElements
 */

/**
 * @param {UiElements} elements
 * @param {string} text
 * @param {string} [tone]
 */
export function setMessage(elements, text, tone = "") {
  elements.message.textContent = text;
  elements.message.className = `message${tone ? ` is-${tone}` : ""}`;
}

/**
 * @param {HTMLFormElement} form
 * @param {boolean} busy
 */
export function setBusy(form, busy) {
  for (const button of form.querySelectorAll("button")) {
    button.disabled = busy;
  }
}
