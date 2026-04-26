export function setMessage(elements, text, tone = "") {
  elements.message.textContent = text;
  elements.message.className = `message${tone ? ` is-${tone}` : ""}`;
}

export function setBusy(form, busy) {
  for (const button of form.querySelectorAll("button")) {
    button.disabled = busy;
  }
}
