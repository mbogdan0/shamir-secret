export const UI_TABS = Object.freeze({
  GENERATE: "generate",
  RECOVER: "recover"
} as const);

export type TabMode = "generate" | "recover";
export type SecretInputMode = "hex" | "text";
export type LocationLike = { pathname: string; search: string; hash: string };

export const SECRET_INPUT_QUERY_KEY = "input";

export function normalizeTabMode(value: unknown): TabMode {
  return value === UI_TABS.RECOVER ? UI_TABS.RECOVER : UI_TABS.GENERATE;
}

export function tabModeFromHash(hash: unknown): TabMode {
  const value = String(hash).replace(/^#/, "");
  return value === UI_TABS.RECOVER ? UI_TABS.RECOVER : UI_TABS.GENERATE;
}

export function hashForTabMode(mode: unknown): string {
  return `#${normalizeTabMode(mode)}`;
}

export function normalizeSecretInputMode(value: unknown): SecretInputMode {
  return value === "hex" ? "hex" : "text";
}

export function secretInputModeFromSearch(search: unknown): SecretInputMode {
  const params = new URLSearchParams(String(search).replace(/^\?/, ""));
  return normalizeSecretInputMode(params.get(SECRET_INPUT_QUERY_KEY));
}

export function searchForSecretInputMode(search: unknown, mode: unknown): string {
  const params = new URLSearchParams(String(search).replace(/^\?/, ""));
  params.set(SECRET_INPUT_QUERY_KEY, normalizeSecretInputMode(mode));
  const serialized = params.toString();
  return serialized ? `?${serialized}` : "";
}

export function hrefForSecretInputMode(locationLike: LocationLike, mode: unknown): string {
  return `${locationLike.pathname}${searchForSecretInputMode(locationLike.search, mode)}${locationLike.hash}`;
}
