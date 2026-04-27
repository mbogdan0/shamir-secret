import type { UiElements } from "./dom.ts";

export type CopyShareHandler = (
  button: HTMLButtonElement,
  text: string,
  copiedLabel: string,
  statusMessage: string
) => Promise<void>;

export function renderShares(
  elements: UiElements,
  shares: string[],
  threshold: number,
  shareCount: number,
  copyShare: CopyShareHandler
): void {
  elements.recoveryScheme.textContent = `Single group ${threshold}-of-${shareCount}`;
  elements.shareList.replaceChildren();

  shares.forEach((share, index) => {
    const item = document.createElement("li");
    item.className = "share-item";
    const row = document.createElement("div");
    row.className = "share-row";
    const text = document.createElement("div");
    text.className = "share-text";
    text.textContent = share;
    const button = document.createElement("button");
    button.className = "secondary";
    button.type = "button";
    button.textContent = `Copy share ${index + 1}`;
    button.addEventListener("click", async () => {
      await copyShare(button, share, "Copied", `Copied share ${index + 1}.`);
    });
    row.append(text, button);
    item.append(row);
    elements.shareList.append(item);
  });

  elements.sharesResult.hidden = false;
}
