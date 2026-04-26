export function parsePositiveInteger(input, label) {
  const value = Number(input.value);
  if (!Number.isInteger(value)) {
    throw new Error(`${label} must be an integer.`);
  }
  return value;
}

export function splitSharesInput(value) {
  return value
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
}
