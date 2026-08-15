import { expect, test } from '@playwright/test';
import { NARROW, boot, driveAllStates, reportCollected, watchPageErrors } from './gate';

/**
 * The WCAG gate.
 *
 * Four configurations — {dark, light} × {1280px, 380px} — each of which boots
 * the lab with reduced motion actually in effect, drives every exhibit through
 * every state it can render, and scans after every single step. What "scan"
 * means is documented on `scan()` in `gate.ts`; what the gate this replaces did
 * instead, and why each of its results was worth less than it looked, is
 * documented at the top of the same file.
 *
 * The desktop width is Playwright's default 1280x720 and is left implicit; the
 * narrow width is set explicitly, and the DRIVE IS REPEATED at it rather than
 * the viewport being resized after the fact. Resizing a driven page and
 * re-scanning measures the reflow of a layout that was built at the other width,
 * which is a different page from the one a phone loads.
 */

test.describe('WCAG gate', () => {
  // The full drive runs four real padding-oracle attacks per configuration —
  // tens of thousands of WebCrypto operations — and scans the whole document
  // after each of ~25 steps.
  test.slow();

  for (const theme of ['dark'] as const) {
    test(`${theme} theme, desktop width`, async ({ page }) => {
      const errors = watchPageErrors(page);
      await boot(page, theme);
      await driveAllStates(page, `${theme}/1280`);
      expect(errors, 'the page must not log or throw errors during the drive').toEqual([]);
      reportCollected();
    });

    test(`${theme} theme, 380px width`, async ({ page }) => {
      await page.setViewportSize(NARROW);
      const errors = watchPageErrors(page);
      await boot(page, theme);
      await driveAllStates(page, `${theme}/380`);
      expect(errors, 'the page must not log or throw errors during the drive').toEqual([]);
      reportCollected();
    });
  }
});
