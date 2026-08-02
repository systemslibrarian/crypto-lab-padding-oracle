import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the padding-oracle attack
 * correctness; this gates them on accessibility the same way. Scans the full
 * page with every tab panel revealed and the live demo output rendered, in both
 * themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Kill transitions/animations/opacity fades: a mid-fade element produces phantom
// contrast failures that do not reflect the settled UI.
const NEUTRALIZE_MOTION = `
  *, *::before, *::after {
    transition: none !important;
    animation: none !important;
  }
`;

async function revealEverything(page: Page): Promise<void> {
  await page.evaluate(() => {
    // The demo panels are a mutually-exclusive tablist; every inactive panel is
    // [hidden]. Reveal them all so their contents are scanned in one pass.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
    // Open any native <details> (future-proofing; the page currently has none).
    for (const d of document.querySelectorAll('details')) {
      (d as HTMLDetailsElement).open = true;
    }
    // Reveal any class-toggled panels that render collapsed by default.
    for (const el of document.querySelectorAll<HTMLElement>('.is-hidden, .collapsed')) {
      el.classList.remove('is-hidden', 'collapsed');
    }
  });
  await page.addStyleTag({ content: NEUTRALIZE_MOTION });
}

// Drive the Panel 1 live oracle demo so the dynamically-injected result region
// (valid/invalid badges) is present in the DOM when we scan.
async function runDemo(page: Page): Promise<void> {
  const btn = page.locator('#p1-oracle-demo-btn');
  if (await btn.count()) {
    await btn.click();
    await expect(page.locator('#p1-oracle-demo-result')).not.toBeEmpty();
  }

  // Panel 1's padding-prediction exercise: its result block carries badges and
  // an error-toned variant, so scan it populated.
  await page.locator('#p1-craft-setup-btn').click();
  await expect(page.locator('#p1-predict-valid-btn')).toBeEnabled();
  await page.locator('#p1-craft-byte').selectOption('2');
  await page.locator('#p1-predict-valid-btn').click();
  await expect(page.locator('#p1-craft-result')).toContainText('The oracle answered');

  // Panel 6's defense bench fills a table with badges in both tones.
  await page.locator('#p6-bench-btn').click();
  await expect(page.locator('#p6-bench-status')).toContainText('failed against both defended ones', {
    timeout: 60_000,
  });

  // Panel 6's AEAD rejection block is an alert region with its own styling.
  await page.locator('#p6-aead-btn').click();
  await expect(page.locator('#p6-tamper-btn')).toBeEnabled();
  await page.locator('#p6-tamper-btn').click();
  await expect(page.locator('#p6-aead-result')).toContainText('REJECTED');
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealEverything(page);
  await runDemo(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealEverything(page);
  await runDemo(page);
  await scan(page);
});
