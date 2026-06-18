/**
 * attack.test.ts — End-to-end regression tests for the padding oracle attack.
 *
 * Run with `npm test` (node --test). Node runs the TypeScript directly via
 * type stripping; WebCrypto is provided by globalThis.crypto.
 *
 * These tests assert the attack recovers the exact plaintext from a ciphertext
 * using only the padding oracle — across block-aligned, empty, and multibyte
 * inputs — and that the progress callback is awaited (so animation pacing works).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createOracleSession, fromBytes, stripPKCS7, toBytes, BLOCK_SIZE } from './oracle.ts';
import { fullCiphertextAttack, recoverBlock } from './attack.ts';
import { splitBlocks } from './oracle.ts';

const CASES: { name: string; text: string }[] = [
  { name: 'short ascii', text: 'Hello, padding oracle!' },
  { name: 'block-aligned (16 bytes)', text: 'Attack at dawn!!' },
  { name: 'empty string', text: '' },
  { name: 'multi-block', text: 'The quick brown fox jumps over the lazy dog. Secrets in CBC.' },
  { name: 'multibyte unicode', text: 'unicode: café résumé ☕' },
];

for (const { name, text } of CASES) {
  test(`fullCiphertextAttack recovers: ${name}`, async () => {
    const session = await createOracleSession(toBytes(text));
    const result = await fullCiphertextAttack(session);
    const recovered = fromBytes(stripPKCS7(result.plaintext) ?? result.plaintext);
    assert.equal(recovered, text);
    assert.equal(result.queryCount, session.queryCount);
    assert.ok(result.queryCount > 0);
  });
}

test('progress callback is awaited (pacing works)', async () => {
  const session = await createOracleSession(toBytes('Attack at dawn!!'));
  const order: string[] = [];
  await fullCiphertextAttack(session, async (ev) => {
    if (ev.kind === 'byte-found') {
      // If the callback were not awaited, this microtask delay would let the
      // attack loop race ahead and 'after' would interleave out of order.
      await Promise.resolve();
      order.push(`found-${ev.byteIndex}-before`);
      order.push(`found-${ev.byteIndex}-after`);
    }
  });
  // Each found callback's before/after must be adjacent (no interleaving).
  for (let i = 0; i < order.length; i += 2) {
    assert.ok(order[i].endsWith('-before'));
    assert.ok(order[i + 1].endsWith('-after'));
    assert.equal(order[i].split('-')[1], order[i + 1].split('-')[1]);
  }
});

test('recoverBlock yields 16 intermediate + plaintext bytes', async () => {
  const session = await createOracleSession(toBytes('Attack at dawn!!'));
  const blocks = splitBlocks(session.ciphertext);
  const { plaintext, intermediate } = await recoverBlock(
    session,
    session.iv,
    blocks[0],
    0,
    blocks.length,
  );
  assert.equal(plaintext.length, BLOCK_SIZE);
  assert.equal(intermediate.length, BLOCK_SIZE);
  assert.equal(fromBytes(plaintext), 'Attack at dawn!!');
});
