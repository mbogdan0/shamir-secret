import type { UiElements } from "./dom.ts";

export function setMessage(elements: UiElements, text: string, tone: string = ""): void {
  elements.message.textContent = text;
  elements.message.className = `message${tone ? ` is-${tone}` : ""}`;
}

export function setBusy(form: HTMLFormElement, busy: boolean): void {
  for (const button of form.querySelectorAll("button")) {
    button.disabled = busy;
  }
}
