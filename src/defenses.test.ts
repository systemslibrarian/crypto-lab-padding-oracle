/**
 * defenses.test.ts — The same attack, three servers.
 *
 * Panel 6 claims that a uniform error response starves the attack and that
 * Encrypt-then-MAC kills it before decryption. These tests run the identical
 * recoverBlock()/trialAgainstMode() path the page runs and assert both the
 * success and the failure outcomes, including the counters the page prints.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  BLOCK_SIZE,
  applyPKCS7,
  createOracleSession,
  fromBytes,
  queryOracle,
  splitBlocks,
  stripPKCS7,
  toBytes,
} from './oracle.ts';
import { trialAgainstMode } from './attack.ts';

const TEXT = 'Attack at dawn!!';

test('leaky server: the attack recovers the block byte-for-byte', async () => {
  const trial = await trialAgainstMode(toBytes(TEXT), 'leaky');

  assert.equal(trial.failure, null);
  assert.equal(trial.matchedPlaintext, true);
  assert.equal(trial.bytesRecovered, BLOCK_SIZE);
  assert.equal(fromBytes(stripPKCS7(trial.recovered!) ?? trial.recovered!), TEXT);
  assert.ok(trial.queryCount > 0);
  // Everything reached the padding check; nothing was MAC-rejected.
  assert.equal(trial.paddingChecks, trial.queryCount);
  assert.equal(trial.macRejections, 0);
});

test('silent server: the attack starves after exhausting all 256 probes', async () => {
  const trial = await trialAgainstMode(toBytes(TEXT), 'silent');

  assert.notEqual(trial.failure, null);
  assert.match(trial.failure!, /No valid padding found/);
  assert.equal(trial.recovered, null);
  assert.equal(trial.matchedPlaintext, false);
  assert.equal(trial.bytesRecovered, 0);
  // The server did the work — it just never varied its answer.
  assert.equal(trial.paddingChecks, trial.queryCount);
  assert.equal(trial.queryCount, 256);
  assert.equal(trial.macRejections, 0);
});

test('Encrypt-then-MAC: every forged query dies before decryption', async () => {
  const trial = await trialAgainstMode(toBytes(TEXT), 'etm');

  assert.notEqual(trial.failure, null);
  assert.equal(trial.recovered, null);
  assert.equal(trial.bytesRecovered, 0);
  // At most one probe out of 256 replays the untouched ciphertext pair, so the
  // padding check is reached either never or exactly once.
  assert.ok(trial.paddingChecks <= 1, `paddingChecks was ${trial.paddingChecks}`);
  assert.equal(trial.macRejections, trial.queryCount - trial.paddingChecks);
});

test('the MAC accepts the ciphertext the session actually issued', async () => {
  const session = await createOracleSession(toBytes(TEXT), 'etm');
  const blocks = splitBlocks(session.ciphertext);

  // Unmodified (IV, C[0]) — a legitimate submission, so it is verified and the
  // padding check runs for real.
  const honest = await queryOracle(session, session.iv, blocks[0]);
  assert.equal(honest.reachedPaddingCheck, true);
  assert.equal(session.macRejections, 0);

  // One flipped bit anywhere and the MAC rejects before decryption.
  const tampered = session.iv.slice();
  tampered[0] ^= 0x01;
  const forged = await queryOracle(session, tampered, blocks[0]);
  assert.equal(forged.valid, false);
  assert.equal(forged.reachedPaddingCheck, false);
  assert.equal(session.macRejections, 1);
});

test('silent mode still performs the real padding check, it just never says so', async () => {
  const session = await createOracleSession(toBytes(TEXT), 'silent');
  const blocks = splitBlocks(session.ciphertext);

  // The untouched last block genuinely has valid padding; a leaky server would
  // say so. The silent one reports invalid anyway.
  const last = blocks.length - 1;
  const answer = await queryOracle(session, blocks[last - 1] ?? session.iv, blocks[last]);
  assert.equal(answer.reachedPaddingCheck, true);
  assert.equal(answer.valid, false);
  assert.equal(session.paddingChecks, 1);

  const leakySession = await createOracleSession(session.plaintext, 'leaky');
  const leakyBlocks = splitBlocks(leakySession.ciphertext);
  const leakyAnswer = await queryOracle(
    leakySession,
    leakyBlocks[leakyBlocks.length - 2] ?? leakySession.iv,
    leakyBlocks[leakyBlocks.length - 1],
  );
  assert.equal(leakyAnswer.valid, true);
});

test('a short plaintext is still graded against its padded block', async () => {
  const trial = await trialAgainstMode(toBytes('short'), 'leaky');
  assert.equal(trial.matchedPlaintext, true);
  const expected = applyPKCS7(toBytes('short')).slice(0, BLOCK_SIZE);
  assert.deepEqual(Array.from(trial.recovered!), Array.from(expected));
});
