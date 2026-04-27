export const UI_TABS = Object.freeze({
  GENERATE: "generate",
  RECOVER: "recover"
});

export const SECRET_INPUT_QUERY_KEY = "input";

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

export function normalizeSecretInputMode(value) {
  return value === "hex" ? "hex" : "text";
}

export function secretInputModeFromSearch(search) {
  const params = new URLSearchParams(String(search).replace(/^\?/, ""));
  return normalizeSecretInputMode(params.get(SECRET_INPUT_QUERY_KEY));
}

export function searchForSecretInputMode(search, mode) {
  const params = new URLSearchParams(String(search).replace(/^\?/, ""));
  params.set(SECRET_INPUT_QUERY_KEY, normalizeSecretInputMode(mode));
  const serialized = params.toString();
  return serialized ? `?${serialized}` : "";
}

export function hrefForSecretInputMode(locationLike, mode) {
  return `${locationLike.pathname}${searchForSecretInputMode(locationLike.search, mode)}${locationLike.hash}`;
}
