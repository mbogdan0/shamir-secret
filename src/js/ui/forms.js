export function parsePositiveInteger(input) {
  const value = Number(input.value);
  if (!Number.isInteger(value)) {
    throw new Error(`${input.previousElementSibling.textContent} must be an integer.`);
  }
  return value;
}

export function splitSharesInput(value) {
  return value
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
}
