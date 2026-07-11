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
