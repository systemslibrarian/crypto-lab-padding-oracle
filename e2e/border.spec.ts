import { expect, test, type Page } from '@playwright/test';

async function minimumControlBoundaryContrast(page: Page): Promise<number> {
  return page.locator('.text-input, .select-input').evaluateAll((elements) => {
    const luminance = (color: string): number => {
      const channels = color.match(/[\d.]+/g)!.slice(0, 3).map(Number).map((channel) => {
        const normalized = channel / 255;
        return normalized <= 0.04045
          ? normalized / 12.92
          : ((normalized + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
    };
    return Math.min(...elements.map((element) => {
      const style = getComputedStyle(element);
      const border = luminance(style.borderTopColor);
      const background = luminance(style.backgroundColor);
      return (Math.max(border, background) + 0.05) / (Math.min(border, background) + 0.05);
    }));
  });
}

test('text and select boundaries clear WCAG non-text contrast in both themes', async ({ page }) => {
  await page.goto('.');
  expect(await minimumControlBoundaryContrast(page)).toBeGreaterThanOrEqual(3);

  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  expect(await minimumControlBoundaryContrast(page)).toBeGreaterThanOrEqual(3);
});
