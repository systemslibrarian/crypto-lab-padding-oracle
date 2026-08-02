import { expect, test, type Page } from '@playwright/test';

/**
 * Functional gate for the claims the page makes in the browser: the recovered
 * plaintext, the query counters, the AEAD rejection, the learner-driven padding
 * prediction, and the defense bench — including the two servers the attack is
 * supposed to fail against.
 *
 * The node --test suite proves the attack engine. This proves the page wired to
 * it actually reports what it computed.
 */

async function openPanel(page: Page, index: number): Promise<void> {
  await page.locator('.panel-tab').nth(index).click();
  await expect(page.locator('.panel').nth(index)).toBeVisible();
}

test('Panel 2 recovers a block and reports a real query count', async ({ page }) => {
  await page.goto('.');
  await openPanel(page, 1);

  await page.locator('#p2-plaintext').fill('Meet me at seven');
  await page.locator('#p2-speed').selectOption('0');
  await page.locator('#p2-encrypt-btn').click();
  await expect(page.locator('#p2-status')).toContainText('Session ready');

  await page.locator('#p2-run-btn').click();
  await expect(page.locator('#p2-status')).toContainText('Attack complete', { timeout: 120_000 });

  const result = page.locator('#p2-result');
  await expect(result).toContainText('Total oracle queries');

  // The counter must be a real number of queries, not a placeholder. Each byte
  // costs at most 256 probes and there are 16 of them.
  const queries = Number((await page.locator('#p2-result .query-count').innerText()).replace(/[^\d]/g, ''));
  expect(queries).toBeGreaterThan(16);
  expect(queries).toBeLessThanOrEqual(256 * 16 + 16);
  expect(Number(await page.locator('#p2-query-count').innerText())).toBe(queries);
});

test('Panel 3 recovers the block the learner typed', async ({ page }) => {
  await page.goto('.');
  await openPanel(page, 2);

  await page.locator('#p3-plaintext').fill('RENDEZVOUS 0400!');
  await expect(page.locator('#p3-bytecount')).toContainText('16 bytes');
  await page.locator('#p3-speed').selectOption('0');

  await page.locator('#p3-encrypt-btn').click();
  await expect(page.locator('#p3-status')).toContainText('RENDEZVOUS 0400!');

  await page.locator('#p3-run-btn').click();
  await expect(page.locator('#p3-status')).toContainText('Full block recovered', { timeout: 120_000 });

  const result = page.locator('#p3-result');
  await expect(result).toContainText('RENDEZVOUS 0400!');
  await expect(result).toContainText('byte-for-byte match');
  await expect(result).not.toContainText('MISMATCH');
  await expect(page.locator('#p3-query-count')).not.toHaveText('0');
});

test('Panel 3 handles a shorter message than one block', async ({ page }) => {
  await page.goto('.');
  await openPanel(page, 2);

  await page.locator('#p3-plaintext').fill('short');
  await expect(page.locator('#p3-bytecount')).toContainText('PKCS#7 padding');
  await page.locator('#p3-speed').selectOption('0');
  await page.locator('#p3-encrypt-btn').click();
  await page.locator('#p3-run-btn').click();

  await expect(page.locator('#p3-status')).toContainText('Full block recovered', { timeout: 120_000 });
  await expect(page.locator('#p3-result')).toContainText('byte-for-byte match');
});

test('Panel 4 checks the full recovery against the encrypted plaintext', async ({ page }) => {
  await page.goto('.');
  await openPanel(page, 3);

  await page.locator('#p4-plaintext').fill('Two blocks of secret text here.');
  await page.locator('#p4-speed').selectOption('0');
  await page.locator('#p4-generate-btn').click();
  await expect(page.locator('#p4-status')).toContainText('block(s) encrypted');

  await page.locator('#p4-run-btn').click();
  await expect(page.locator('#p4-status')).toContainText('Attack complete', { timeout: 180_000 });

  const result = page.locator('#p4-result');
  await expect(result).toContainText('Two blocks of secret text here.');
  await expect(result).toContainText('byte-for-byte match');
  await expect(result).not.toContainText('MISMATCH');
});

test('Panel 6 AES-GCM rejects tampering without revealing plaintext', async ({ page }) => {
  await page.goto('.');
  await openPanel(page, 5);

  await page.locator('#p6-aead-btn').click();
  await expect(page.locator('#p6-aead-result')).toContainText('Ciphertext + auth tag');
  await expect(page.locator('#p6-tamper-btn')).toBeEnabled();

  await page.locator('#p6-tamper-btn').click();
  const result = page.locator('#p6-aead-result');
  await expect(result).toContainText('Tampered ciphertext REJECTED by authentication tag');
  await expect(result).not.toContainText('Unexpected: decryption succeeded');
  // The protected message must never appear on the page.
  await expect(result).not.toContainText('Secret message protected by AES-GCM');
});

test('the same attack succeeds on the leaky server and fails on both defended ones', async ({ page }) => {
  await page.goto('.');
  await openPanel(page, 5);

  await page.locator('#p6-bench-plaintext').fill('Attack at dawn!!');
  await page.locator('#p6-bench-btn').click();
  await expect(page.locator('#p6-bench-status')).toContainText(
    'Attack succeeded against the leaky server and failed against both defended ones',
    { timeout: 180_000 },
  );

  const rows = page.locator('#p6-bench-rows tr');
  await expect(rows).toHaveCount(3);

  // Leaky: plaintext out, verified against what was encrypted.
  await expect(rows.nth(0)).toContainText('plaintext recovered');
  await expect(rows.nth(0)).toContainText('Attack at dawn!!');
  await expect(rows.nth(0)).toContainText('byte-for-byte match');

  // Silent: the padding check still ran, the attack still starved.
  await expect(rows.nth(1)).toContainText('attack failed');
  await expect(rows.nth(1)).toContainText('No valid padding found');
  await expect(rows.nth(1)).toContainText('0 of 16 bytes');

  // Encrypt-then-MAC: the queries died at the MAC, before any decryption.
  await expect(rows.nth(2)).toContainText('attack failed');
  await expect(rows.nth(2)).toContainText('0 of 16 bytes');

  const cells = (row: number) => rows.nth(row).locator('td.query-count');
  const macRejections = Number((await cells(2).nth(2).innerText()).replace(/[^\d]/g, ''));
  const paddingChecks = Number((await cells(2).nth(1).innerText()).replace(/[^\d]/g, ''));
  expect(macRejections).toBeGreaterThan(200);
  expect(paddingChecks).toBeLessThanOrEqual(1);

  await expect(page.locator('#p6-bench-note')).toContainText('died at MAC');
});

test('Panel 1 scores the learner padding prediction against a real oracle query', async ({ page }) => {
  await page.goto('.');

  await page.locator('#p1-craft-setup-btn').click();
  await expect(page.locator('#p1-craft-result')).toContainText('Padding practice');
  await expect(page.locator('#p1-predict-valid-btn')).toBeEnabled();

  // 0x01 is a single padding byte that is itself — the oracle must accept it.
  await page.locator('#p1-craft-byte').selectOption('1');
  await page.locator('#p1-predict-valid-btn').click();
  await expect(page.locator('#p1-craft-result')).toContainText('Valid ✓');
  await expect(page.locator('#p1-craft-result')).toContainText('Correct.');
  await expect(page.locator('#p1-craft-correct')).toHaveText('1');
  await expect(page.locator('#p1-craft-total')).toHaveText('1');

  // 0x02 needs the byte before it to be 0x02 as well; it is 0x10, so invalid.
  await page.locator('#p1-craft-byte').selectOption('2');
  await page.locator('#p1-predict-valid-btn').click();
  await expect(page.locator('#p1-craft-result')).toContainText('Invalid ✗');
  await expect(page.locator('#p1-craft-result')).toContainText('Not this time.');
  await expect(page.locator('#p1-craft-correct')).toHaveText('1');
  await expect(page.locator('#p1-craft-total')).toHaveText('2');

  // Same byte, opposite call — now the prediction is right.
  await page.locator('#p1-predict-invalid-btn').click();
  await expect(page.locator('#p1-craft-result')).toContainText('Correct.');
  await expect(page.locator('#p1-craft-correct')).toHaveText('2');
  await expect(page.locator('#p1-craft-total')).toHaveText('3');

  // A whole block of 0x10 is valid padding, so forcing 0x10 back is accepted.
  await page.locator('#p1-craft-byte').selectOption('16');
  await page.locator('#p1-predict-valid-btn').click();
  await expect(page.locator('#p1-craft-result')).toContainText('Valid ✓');
  await expect(page.locator('#p1-craft-result')).toContainText('Correct.');
  await expect(page.locator('#p1-craft-correct')).toHaveText('3');
});
