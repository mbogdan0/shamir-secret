export async function copyText(text) {
  const canUseClipboardApi =
    location.protocol !== "file:" && globalThis.isSecureContext && navigator.clipboard?.writeText;
  if (canUseClipboardApi) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fall back for local file usage where clipboard permissions may be denied.
    }
  }
  const scratch = document.createElement("textarea");
  scratch.value = text;
  scratch.style.position = "fixed";
  scratch.style.left = "-9999px";
  document.body.append(scratch);
  scratch.focus();
  scratch.select();
  scratch.setSelectionRange(0, scratch.value.length);
  const copied = document.execCommand("copy");
  scratch.remove();
  if (!copied) {
    throw new Error("Copy failed.");
  }
}
