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

import { createOracleSession, encryptWithSession, fromBytes, stripPKCS7, toBytes, BLOCK_SIZE } from './oracle.ts';
import type { OracleSession } from './oracle.ts';
import { fullCiphertextAttack, recoverBlock } from './attack.ts';
import { splitBlocks } from './oracle.ts';

const CASES: { name: string; text: string }[] = [
  { name: 'short ascii', text: 'Hello, padding oracle!' },
  { name: 'block-aligned (16 bytes)', text: 'Attack at dawn!!' },
  { name: 'empty string', text: '' },
  { name: 'multi-block', text: 'The quick brown fox jumps over the lazy dog. Secrets in CBC.' },
  { name: 'multibyte unicode', text: 'unicode: café résumé ☕' },
];

// NIST SP 800-38A, Appendix F.2.1/F.2.2, CBC-AES128 block 1. The standard's
// CBC example has no PKCS#7 padding; WebCrypto adds a block when encrypting, so
// compare the first ciphertext block rather than its padded full output.
const nist = {
  key: '2b7e151628aed2a6abf7158809cf4f3c',
  iv: '000102030405060708090a0b0c0d0e0f',
  plaintext: '6bc1bee22e409f96e93d7e117393172a',
  intermediate: '6bc0bce12a459991e134741a7f9e1925',
  ciphertext: '7649abac8119b246cee98e9b12e9197d',
};
const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));

test('NIST SP 800-38A CBC block is encrypted and recovered through the padding oracle', async () => {
  const key = await crypto.subtle.importKey('raw', bytes(nist.key), 'AES-CBC', false, ['encrypt', 'decrypt']);
  const iv = bytes(nist.iv);
  const expected = bytes(nist.plaintext);
  const target = bytes(nist.ciphertext);
  const encrypted = await encryptWithSession(key, iv, expected);
  assert.deepEqual(encrypted.slice(0, BLOCK_SIZE), target);

  // Only the leaky mode is used. Its MAC fields are inert, but a real HMAC key
  // keeps this a complete OracleSession instead of casting away the contract.
  const macKey = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const session: OracleSession = {
    key, iv, ciphertext: target, plaintext: expected, queryCount: 0,
    mode: 'leaky', macKey, legitTags: new Set(), paddingChecks: 0, macRejections: 0,
  };
  const found: { index: number; value: number }[] = [];
  const result = await recoverBlock(session, iv, target, 0, 1, (event) => {
    if (event.kind === 'byte-found') {
      found.push({ index: event.byteIndex, value: event.recoveredByte! });
    }
  });

  assert.deepEqual(result.plaintext, expected);
  assert.deepEqual(result.intermediate, bytes(nist.intermediate));
  assert.deepEqual(found[0], { index: 15, value: 0x2a });
  assert.equal(session.paddingChecks, session.queryCount);
  assert.ok(session.queryCount > BLOCK_SIZE);
});

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
