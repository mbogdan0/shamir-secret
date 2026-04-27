export const UI_TABS = Object.freeze({
  GENERATE: "generate",
  RECOVER: "recover"
});

/**
 * @typedef {"generate" | "recover"} TabMode
 * @typedef {"hex" | "text"} SecretInputMode
 * @typedef {{ pathname: string, search: string, hash: string }} LocationLike
 */

export const SECRET_INPUT_QUERY_KEY = "input";

/**
 * @param {unknown} value
 * @returns {TabMode}
 */
export function normalizeTabMode(value) {
  return value === UI_TABS.RECOVER ? UI_TABS.RECOVER : UI_TABS.GENERATE;
}

/**
 * @param {unknown} hash
 * @returns {TabMode}
 */
export function tabModeFromHash(hash) {
  const value = String(hash).replace(/^#/, "");
  return value === UI_TABS.RECOVER ? UI_TABS.RECOVER : UI_TABS.GENERATE;
}

/**
 * @param {unknown} mode
 * @returns {string}
 */
export function hashForTabMode(mode) {
  return `#${normalizeTabMode(mode)}`;
}

/**
 * @param {unknown} value
 * @returns {SecretInputMode}
 */
export function normalizeSecretInputMode(value) {
  return value === "hex" ? "hex" : "text";
}

/**
 * @param {unknown} search
 * @returns {SecretInputMode}
 */
export function secretInputModeFromSearch(search) {
  const params = new URLSearchParams(String(search).replace(/^\?/, ""));
  return normalizeSecretInputMode(params.get(SECRET_INPUT_QUERY_KEY));
}

/**
 * @param {unknown} search
 * @param {unknown} mode
 * @returns {string}
 */
export function searchForSecretInputMode(search, mode) {
  const params = new URLSearchParams(String(search).replace(/^\?/, ""));
  params.set(SECRET_INPUT_QUERY_KEY, normalizeSecretInputMode(mode));
  const serialized = params.toString();
  return serialized ? `?${serialized}` : "";
}

/**
 * @param {LocationLike} locationLike
 * @param {unknown} mode
 * @returns {string}
 */
export function hrefForSecretInputMode(locationLike, mode) {
  return `${locationLike.pathname}${searchForSecretInputMode(locationLike.search, mode)}${locationLike.hash}`;
}
