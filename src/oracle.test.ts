import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  BLOCK_SIZE,
  createOracleSession,
  fromHex,
  queryOracle,
  splitBlocks,
  toBytes,
  xorBytes,
} from './oracle.ts';

test('hex parsing accepts whitespace but rejects non-hex and odd-length input', () => {
  assert.deepEqual(fromHex('00 aF\n10'), new Uint8Array([0x00, 0xaf, 0x10]));
  assert.throws(() => fromHex('0g'), /Invalid hex string/);
  assert.throws(() => fromHex('abc'), /Invalid hex string/);
});

test('block and XOR helpers reject malformed lengths instead of truncating silently', () => {
  assert.throws(() => splitBlocks(new Uint8Array(BLOCK_SIZE + 1)), /multiple of 16/);
  assert.throws(
    () => xorBytes(new Uint8Array([1, 2]), new Uint8Array([3])),
    /equal length/,
  );
});

test('malformed oracle submissions are rejected before they count as cryptographic queries', async () => {
  const session = await createOracleSession(toBytes('shape check'));
  const target = splitBlocks(session.ciphertext)[0];

  await assert.rejects(
    queryOracle(session, new Uint8Array(BLOCK_SIZE - 1), target),
    /two 16-byte blocks/,
  );
  assert.equal(session.queryCount, 0);
  assert.equal(session.paddingChecks, 0);
  assert.equal(session.macRejections, 0);
});
