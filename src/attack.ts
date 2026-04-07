/**
 * attack.ts — CBC Padding Oracle Attack Engine
 *
 * Implements Vaudenay 2002 ("Security Flaws Induced by CBC Padding" —
 * Serge Vaudenay, EUROCRYPT 2002) exactly:
 *
 * For each target block C[n] (n > 0):
 *   For each byte position j from 15 down to 0:
 *     1. Set desired padding byte p = BLOCK_SIZE - j  (0x01, 0x02, … 0x10)
 *     2. For bytes already recovered: set C'[k] = I[k] XOR p  (fix-up)
 *     3. Probe C'[j] through all 256 values
 *     4. When oracle returns valid: I[j] = C'[j] XOR p
 *     5. P[j] = I[j] XOR C[n-1][j]
 *
 * I[j] is the "intermediate value" — D_K(C[n])[j] before XOR with C[n-1].
 * Recovering I[j] does NOT require the key.
 *
 * Attack complexity: O(256 × block_size × block_count) oracle queries.
 * In practice, ~128 queries per byte on average (expected value of uniform
 * distribution over 0x00–0xFF), so ~2048 per block, ~2048n total for n blocks.
 *
 * No shortcuts. No simulated responses. All oracle calls use real WebCrypto.
 */

import {
  BLOCK_SIZE,
  OracleSession,
  queryOracle,
  splitBlocks,
  xorBytes,
  stripPKCS7,
} from './oracle.ts';

/** Callback invoked after each oracle query (for UI updates) */
export type ProgressCallback = (event: AttackEvent) => void;

export type AttackEventKind =
  | 'byte-probe'        // single byte probe attempt
  | 'byte-found'        // byte successfully recovered
  | 'block-complete'    // full block recovered
  | 'attack-complete';  // all blocks recovered

export interface AttackEvent {
  kind: AttackEventKind;
  blockIndex: number;       // which ciphertext block (0-based, skip IV)
  byteIndex: number;        // byte position within block (0=leftmost)
  probeValue?: number;      // current probe byte value (0–255)
  intermediateValue?: number; // I[j] = D_K(C[n])[j]
  recoveredByte?: number;   // P[j] (plaintext byte)
  recoveredBlock?: Uint8Array; // full block when complete
  queryCount: number;       // cumulative oracle queries so far
  totalBlocks: number;      // total blocks being attacked
}

/** Full result of the attack */
export interface AttackResult {
  plaintext: Uint8Array;
  queryCount: number;
  intermediates: Uint8Array[]; // one per attacked block
}

/**
 * Recover a single byte of the intermediate state using the padding oracle.
 *
 * @param session       - Active oracle session
 * @param prevBlock     - C[n-1] (the actual ciphertext block before the target)
 * @param targetBlock   - C[n]   (the target ciphertext block)
 * @param bytePos       - Byte index to recover (0–15, 0=leftmost)
 * @param knownInter    - Already-recovered intermediate bytes (indices bytePos+1 to 15)
 * @param onProgress    - Optional progress callback
 * @param blockIndex    - For progress reporting
 * @param totalBlocks   - For progress reporting
 * @param signal        - AbortSignal for cancellation
 */
export async function recoverByte(
  session: OracleSession,
  prevBlock: Uint8Array,
  targetBlock: Uint8Array,
  bytePos: number,
  knownInter: Uint8Array,
  onProgress?: ProgressCallback,
  blockIndex = 0,
  totalBlocks = 1,
  signal?: AbortSignal
): Promise<number> {
  // The padding value we want to produce: 0x01 for last byte, 0x02 for second-to-last, etc.
  const padByte = BLOCK_SIZE - bytePos;

  // Build the manipulated prev block
  const modified = prevBlock.slice();

  // Fix up bytes already recovered (positions bytePos+1 to 15) to produce `padByte`
  for (let k = bytePos + 1; k < BLOCK_SIZE; k++) {
    // We want D_K(C[n])[k] XOR modified[k] = padByte
    // => modified[k] = D_K(C[n])[k] XOR padByte = knownInter[k] XOR padByte
    modified[k] = knownInter[k] ^ padByte;
  }

  // Probe all 256 values for modified[bytePos]
  // We need: D_K(C[n])[bytePos] XOR modified[bytePos] = padByte
  // => modified[bytePos] = D_K(C[n])[bytePos] XOR padByte = intermediateVal XOR padByte
  for (let guess = 0; guess < 256; guess++) {
    if (signal?.aborted) throw new DOMException('Attack aborted', 'AbortError');

    modified[bytePos] = guess;

    onProgress?.({
      kind: 'byte-probe',
      blockIndex,
      byteIndex: bytePos,
      probeValue: guess,
      queryCount: session.queryCount,
      totalBlocks,
    });

    const result = await queryOracle(session, modified, targetBlock);

    if (result.valid) {
      // ── Disambiguation for the LAST byte (bytePos == 15) ──
      // When probing byte 15, bytes 0–14 are unchanged (original prevBlock).
      // A false‐positive occurs when the decrypted block ends with 0x02 0x02,
      // 0x03 0x03 0x03, etc. — valid multi‐byte padding that is NOT 0x01.
      // Probability: ~1/256 per attempt. Standard fix (Vaudenay §3.1):
      // flip an adjacent byte and re‐query; if still valid, it really is 0x01.
      if (bytePos === BLOCK_SIZE - 1) {
        const verify = modified.slice();
        verify[bytePos - 1] ^= 0x01;          // perturb byte 14
        const vr = await queryOracle(session, verify, targetBlock);
        if (!vr.valid) continue;               // false positive — keep scanning
      }

      // Found valid padding.
      // Intermediate value: I[bytePos] = guess XOR padByte
      const intermediateVal = guess ^ padByte;
      // Plaintext byte: P[bytePos] = I[bytePos] XOR original prevBlock[bytePos]
      const plaintextByte = intermediateVal ^ prevBlock[bytePos];

      onProgress?.({
        kind: 'byte-found',
        blockIndex,
        byteIndex: bytePos,
        probeValue: guess,
        intermediateValue: intermediateVal,
        recoveredByte: plaintextByte,
        queryCount: session.queryCount,
        totalBlocks,
      });

      return intermediateVal; // return intermediate, not plaintext — caller does final XOR
    }
  }

  // Should never happen with a correct oracle — all 256 guesses exhausted
  throw new Error(`No valid padding found for block ${blockIndex}, byte ${bytePos}`);
}

/**
 * Recover all 16 bytes of a single target block.
 *
 * @param session       - Active oracle session
 * @param prevBlock     - C[n-1]
 * @param targetBlock   - C[n]
 * @param blockIndex    - For progress reporting
 * @param totalBlocks   - For progress reporting
 * @param onProgress    - Optional progress callback
 * @param signal        - AbortSignal for cancellation
 */
export async function recoverBlock(
  session: OracleSession,
  prevBlock: Uint8Array,
  targetBlock: Uint8Array,
  blockIndex: number,
  totalBlocks: number,
  onProgress?: ProgressCallback,
  signal?: AbortSignal
): Promise<{ plaintext: Uint8Array; intermediate: Uint8Array }> {
  const intermediate = new Uint8Array(BLOCK_SIZE);

  // Attack bytes right-to-left: position 15, 14, 13, ... 0
  for (let bytePos = BLOCK_SIZE - 1; bytePos >= 0; bytePos--) {
    if (signal?.aborted) throw new DOMException('Attack aborted', 'AbortError');

    const interVal = await recoverByte(
      session,
      prevBlock,
      targetBlock,
      bytePos,
      intermediate,
      onProgress,
      blockIndex,
      totalBlocks,
      signal
    );
    intermediate[bytePos] = interVal;
  }

  // Recover plaintext: P = intermediate XOR prevBlock
  const plaintext = xorBytes(intermediate, prevBlock);

  onProgress?.({
    kind: 'block-complete',
    blockIndex,
    byteIndex: 0,
    recoveredBlock: plaintext,
    queryCount: session.queryCount,
    totalBlocks,
  });

  return { plaintext, intermediate };
}

/**
 * Full ciphertext decryption via padding oracle.
 *
 * Attacks all blocks from last to first (or first to last — order doesn't matter).
 * The IV is required to recover block 0's plaintext — if the IV is known (standard),
 * full recovery is possible. If IV is unknown, block 0 is unrecoverable (only
 * the intermediate state is recovered, which still XORs to something).
 *
 * @param session    - Active oracle session
 * @param onProgress - Optional progress callback
 * @param signal     - AbortSignal for cancellation
 */
export async function fullCiphertextAttack(
  session: OracleSession,
  onProgress?: ProgressCallback,
  signal?: AbortSignal
): Promise<AttackResult> {
  const ciphertextBlocks = splitBlocks(session.ciphertext);
  const totalBlocks = ciphertextBlocks.length;
  const allIntermediates: Uint8Array[] = [];
  const allPlaintext: Uint8Array[] = [];

  for (let blockIdx = 0; blockIdx < totalBlocks; blockIdx++) {
    if (signal?.aborted) throw new DOMException('Attack aborted', 'AbortError');

    // The "prev block" for block 0 is the IV
    const prevBlock = blockIdx === 0 ? session.iv : ciphertextBlocks[blockIdx - 1];
    const targetBlock = ciphertextBlocks[blockIdx];

    const { plaintext, intermediate } = await recoverBlock(
      session,
      prevBlock,
      targetBlock,
      blockIdx,
      totalBlocks,
      onProgress,
      signal
    );

    allPlaintext.push(plaintext);
    allIntermediates.push(intermediate);
  }

  // Concatenate and strip PKCS#7 padding from final result
  const totalLen = allPlaintext.reduce((acc, b) => acc + b.length, 0);
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  for (const block of allPlaintext) {
    combined.set(block, offset);
    offset += block.length;
  }

  const stripped = stripPKCS7(combined) ?? combined;

  onProgress?.({
    kind: 'attack-complete',
    blockIndex: totalBlocks - 1,
    byteIndex: 0,
    queryCount: session.queryCount,
    totalBlocks,
  });

  return {
    plaintext: stripped,
    queryCount: session.queryCount,
    intermediates: allIntermediates,
  };
}

/**
 * Theoretical oracle query complexity for a given ciphertext length.
 * O(256 × block_size × block_count) — worst case.
 * Expected case: ~128 × block_size × block_count (avg 128 probes per byte).
 */
export function theoreticalQueryCount(ciphertextLen: number): {
  worstCase: number;
  expectedCase: number;
  blockCount: number;
} {
  const blockCount = ciphertextLen / BLOCK_SIZE;
  return {
    worstCase: 256 * BLOCK_SIZE * blockCount,
    expectedCase: 128 * BLOCK_SIZE * blockCount,
    blockCount,
  };
}
