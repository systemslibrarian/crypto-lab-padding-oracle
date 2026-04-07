/**
 * oracle.ts — Real AES-CBC encryption/decryption with genuine PKCS#7 padding validation.
 *
 * The oracle is the core vulnerability: a function that tells the attacker only
 * whether decrypted padding is valid. No key is revealed. No plaintext is revealed.
 * One bit of information — valid or invalid — is enough to decrypt everything.
 *
 * Implementation uses WebCrypto exclusively. No pure-JS AES.
 * PKCS#7 validation is real — actual byte inspection, no simulation.
 */

export const BLOCK_SIZE = 16;

/**
 * Ensure a Uint8Array is backed by a plain ArrayBuffer for WebCrypto compatibility.
 * TypeScript 6+ tightened BufferSource to require ArrayBuffer, not SharedArrayBuffer.
 */
function toAB(u8: Uint8Array): Uint8Array<ArrayBuffer> {
  if (u8.buffer instanceof ArrayBuffer) {
    return u8 as Uint8Array<ArrayBuffer>;
  }
  return new Uint8Array(u8) as Uint8Array<ArrayBuffer>;
}

/** AES-CBC key wrapper for reuse across oracle calls */
export interface OracleSession {
  key: CryptoKey;
  iv: Uint8Array;
  ciphertext: Uint8Array;  // full ciphertext WITHOUT the IV
  plaintext: Uint8Array;   // original plaintext (for verification only)
  queryCount: number;
}

/** Result of a single oracle query */
export interface OracleResult {
  valid: boolean;
  queryCount: number;
}

/**
 * Generate a new AES-128-CBC key and encrypt the given plaintext.
 * Returns a session object for use with the oracle.
 */
export async function createOracleSession(plaintext: Uint8Array): Promise<OracleSession> {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-CBC', length: 128 },
    false,  // not extractable — key never leaves WebCrypto
    ['encrypt', 'decrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(BLOCK_SIZE));

  // WebCrypto applies PKCS#7 padding automatically
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: toAB(iv) },
    key,
    toAB(plaintext)
  );

  return {
    key,
    iv: iv.slice(),
    ciphertext: new Uint8Array(encrypted),
    plaintext: plaintext.slice(),
    queryCount: 0,
  };
}

/**
 * The padding oracle.
 *
 * Accepts a modified (prev_block || target_block) pair and returns true if
 * AES-CBC decryption of target_block, XORed with prev_block, produces
 * valid PKCS#7 padding.
 *
 * This is the ONLY information the attacker receives — one bit.
 *
 * @param session    - Active oracle session (key is opaque to caller)
 * @param prevBlock  - 16-byte block acting as the "IV" for target block
 * @param targetBlock - 16-byte ciphertext block to decrypt
 */
export async function queryOracle(
  session: OracleSession,
  prevBlock: Uint8Array,
  targetBlock: Uint8Array
): Promise<OracleResult> {
  session.queryCount++;

  // Use prevBlock as the IV (first block is XORed with IV in CBC decryption)
  // WebCrypto AES-CBC decryption: P[i] = D_K(C[i]) XOR C[i-1]
  // When we pass prevBlock as IV and targetBlock as ciphertext:
  //   P = D_K(targetBlock) XOR prevBlock
  try {
    await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: toAB(prevBlock) },
      session.key,
      toAB(targetBlock)  // just the one block
    );

    // WebCrypto throws on invalid padding, so reaching here means valid padding.
    // The returned ArrayBuffer has PKCS#7 already stripped — do NOT re-validate it.
    return { valid: true, queryCount: session.queryCount };
  } catch {
    // AES-CBC decrypt threw — invalid padding
    return { valid: false, queryCount: session.queryCount };
  }
}

/**
 * Validate PKCS#7 padding manually.
 * Returns true if the last n bytes all equal n, where 1 <= n <= 16.
 */
export function validatePKCS7(data: Uint8Array): boolean {
  if (data.length === 0) return false;
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > BLOCK_SIZE) return false;
  if (padLen > data.length) return false;
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) return false;
  }
  return true;
}

/**
 * Apply PKCS#7 padding to plaintext to reach a multiple of BLOCK_SIZE.
 */
export function applyPKCS7(data: Uint8Array): Uint8Array {
  const padLen = BLOCK_SIZE - (data.length % BLOCK_SIZE);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(padLen, data.length);
  return padded;
}

/**
 * Strip PKCS#7 padding from decrypted data.
 * Returns null if padding is invalid.
 */
export function stripPKCS7(data: Uint8Array): Uint8Array | null {
  if (!validatePKCS7(data)) return null;
  const padLen = data[data.length - 1];
  return data.slice(0, data.length - padLen);
}

/**
 * Encrypt plaintext with a session key directly (for creating test ciphertexts).
 * Returns the ciphertext bytes (does NOT include the IV).
 */
export async function encryptWithSession(
  key: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: toAB(iv) },
    key,
    toAB(plaintext)
  );
  return new Uint8Array(encrypted);
}

/**
 * Split a ciphertext buffer into 16-byte blocks.
 */
export function splitBlocks(data: Uint8Array): Uint8Array[] {
  const blocks: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += BLOCK_SIZE) {
    blocks.push(data.slice(i, i + BLOCK_SIZE));
  }
  return blocks;
}

/**
 * XOR two equal-length byte arrays.
 */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/**
 * Format a Uint8Array as a space-separated hex string.
 */
export function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');
}

/**
 * Convert a hex string (optionally space-separated) to Uint8Array.
 */
export function fromHex(hex: string): Uint8Array {
  const cleaned = hex.replace(/\s+/g, '');
  if (cleaned.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert a UTF-8 string to Uint8Array.
 */
export function toBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Convert a Uint8Array to a UTF-8 string (best-effort, replacing invalid sequences).
 */
export function fromBytes(data: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(data);
}
