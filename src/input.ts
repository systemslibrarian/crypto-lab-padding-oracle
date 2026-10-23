export const DEMO_INPUT_LIMITS = {
  lastBlock: 200,
  oneBlock: 16,
  fullCiphertext: 128,
  defenseBench: 16,
} as const;

/**
 * Apply workload limits to the bytes cryptography actually receives.
 * HTML maxlength counts UTF-16 code units, so it is not a security boundary
 * for UTF-8 input and can also be bypassed by scripts or browser automation.
 */
export function boundedUtf8(
  text: string,
  maxBytes: number,
  label: string,
): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > maxBytes) {
    throw new RangeError(
      `${label} must be at most ${maxBytes} UTF-8 bytes (received ${bytes.length})`,
    );
  }
  return bytes;
}
