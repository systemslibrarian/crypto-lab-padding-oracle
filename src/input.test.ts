import { test } from 'node:test';
import assert from 'node:assert/strict';

import { boundedUtf8 } from './input.ts';

test('demo input limits are enforced on UTF-8 bytes, not JavaScript characters', () => {
  assert.equal(boundedUtf8('A'.repeat(16), 16, 'Block').length, 16);
  assert.equal(boundedUtf8('🔐'.repeat(4), 16, 'Block').length, 16);
  assert.throws(
    () => boundedUtf8('🔐'.repeat(5), 16, 'Block'),
    /Block must be at most 16 UTF-8 bytes \(received 20\)/,
  );
});
