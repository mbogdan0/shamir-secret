export async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const scratch = document.createElement("textarea");
  scratch.value = text;
  scratch.style.position = "fixed";
  scratch.style.left = "-9999px";
  document.body.append(scratch);
  scratch.select();
  document.execCommand("copy");
  scratch.remove();
}
