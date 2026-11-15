/**
 * The two claims this lab once had backwards, pinned.
 *
 * 1. A padding oracle attack recovers *plaintext*. The attacker already holds the
 *    ciphertext; what the oracle gives up is what that ciphertext decrypts to, and
 *    never the key. The README's opening sentence and all four of the page's
 *    self-descriptions said "recovers ciphertext".
 *
 * 2. POODLE *is* a padding-oracle attack. Moller, Duong & Kotowicz, "This POODLE
 *    Bites: Exploiting The SSL 3.0 Fallback" (2014) name it "Padding Oracle On
 *    Downgraded Legacy Encryption" and write that a spliced record "will in all
 *    likelihood be rejected otherwise, giving rise to a padding oracle attack",
 *    at "256 SSL 3.0 requests per byte". The README said it worked "without a
 *    traditional padding oracle".
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath, URL } from 'node:url';

const read = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`../${name}`, import.meta.url)), 'utf8');

/** The four descriptions the page publishes about itself. */
const SELF_DESCRIPTIONS = [
  /<meta name="description" content="([^"]*)"/,
  /<meta property="og:description" content="([^"]*)"/,
  /<meta name="twitter:description" content="([^"]*)"/,
  /"description": "([^"]*)"/,
];

/** "recovers ciphertext" in any of its phrasings. */
const RECOVERS_CIPHERTEXT = /recover(?:s|ing)?\s+(?:the\s+)?(?:AES-)?(?:CBC\s+)?ciphertext/i;

test('what the attack recovers is plaintext, everywhere the lab says so', () => {
  const readme = read('README.md');
  const whatItIs = readme.split('## What It Is')[1].split('\n## ')[0];
  assert.match(whatItIs, /recovers the plaintext of CBC ciphertext/);
  assert.doesNotMatch(whatItIs, RECOVERS_CIPHERTEXT);

  const html = read('index.html');
  for (const pattern of SELF_DESCRIPTIONS) {
    const match = html.match(pattern);
    assert.ok(match, `index.html has no self-description matching ${pattern}`);
    assert.match(match[1], /plaintext/i);
    assert.doesNotMatch(match[1], RECOVERS_CIPHERTEXT);
  }
});

test('POODLE is described as the padding-oracle attack it is', () => {
  const readme = read('README.md');
  const ssl3 = readme
    .split('\n')
    .find((line) => line.includes('Ignored padding bytes in SSL 3.0'));
  assert.ok(ssl3, 'the SSL 3.0 bullet is missing from "What Can Go Wrong"');
  assert.match(ssl3, /only validates the last padding byte/);
  assert.match(ssl3, /is itself a padding oracle/);
  assert.match(ssl3, /one plaintext byte per ~256 requests/);
  assert.doesNotMatch(readme, /without a traditional padding oracle/);
});
