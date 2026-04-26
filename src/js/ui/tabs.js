export const UI_TABS = Object.freeze({
  GENERATE: "generate",
  RECOVER: "recover"
});

export function normalizeTabMode(value) {
  return value === UI_TABS.RECOVER ? UI_TABS.RECOVER : UI_TABS.GENERATE;
}

export function tabModeFromHash(hash) {
  const value = String(hash).replace(/^#/, "");
  return value === UI_TABS.RECOVER ? UI_TABS.RECOVER : UI_TABS.GENERATE;
}

export function hashForTabMode(mode) {
  return `#${normalizeTabMode(mode)}`;
}
