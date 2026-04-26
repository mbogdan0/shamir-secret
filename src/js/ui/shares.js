export function renderShares(elements, shares, threshold, shareCount, copyText, setMessage) {
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
    button.textContent = "Copy";
    button.addEventListener("click", async () => {
      await copyText(share);
      setMessage(`Copied share ${index + 1}.`, "ok");
    });
    row.append(text, button);
    item.append(row);
    elements.shareList.append(item);
  });

  elements.sharesResult.hidden = false;
}
