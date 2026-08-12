import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures } from './nontext';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces (`e2e/a11y.spec.ts`, deleted with this commit) and its companion
 * `e2e/border.spec.ts`.
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `transition: none !important; animation: none !important` through
 *     `addStyleTag`. That BYPASSED this stylesheet's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it.
 *     Here the block clamps `animation-duration`, `animation-iteration-count`,
 *     `transition-duration` and `scroll-behavior` — and the one animation on the
 *     page, `byte-probe-pulse`, is applied ONLY inside
 *     `@media (prefers-reduced-motion: no-preference)`, so under the preference
 *     the probing byte cell is never animated at all. Injection could not
 *     reproduce that distinction; asking for the preference and asserting it took
 *     effect does, and it is the rendering a reader with the preference set
 *     actually gets.
 *
 *  2. IT FORCE-REVEALED EVERY PANEL. `revealEverything()` stripped `hidden` from
 *     every element on the page, opened every `<details>`, and cleared
 *     `.is-hidden`/`.collapsed`. This lab's six exhibit panels are a
 *     mutually-exclusive tablist: exactly one is ever on screen, and the other
 *     five carry the `hidden` attribute. Stripping it assembled a document with
 *     all six panels stacked open at once, five of them empty — a page no visitor
 *     can reach, and one no assertion about it describes. This gate never touches
 *     `hidden`; every panel is reached by clicking its own tab.
 *
 *  3. IT SCANNED ONCE, AT ONE VIEWPORT, AFTER THE WHOLE DRIVE. Every state the
 *     old drive built was overwritten before anything measured it: the craft
 *     exercise's correct and incorrect verdicts, the byte-recovery grid mid-probe,
 *     the AEAD "REJECTED" alert — all were scanned only in whatever state the
 *     LAST step happened to leave behind. And the first drive step was guarded
 *     with `if (await btn.count())`, so a missing control skipped silently instead
 *     of failing. This drive scans after every single step, in
 *     {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. On this page in
 *     particular, an `aria-label` on a role-less element is PROHIBITED and lands
 *     in axe's `incomplete` bucket, never in `violations` — and `src/ui.ts`
 *     builds dozens of them; and `#p5-exploits` is a `role="list"` whose children
 *     are injected on mount, so `aria-required-children` is an `incomplete`
 *     result at first paint too.
 *
 *  5. IT HAD NO REFLOW ORACLE, and `border.spec.ts` — the only 1.4.11 check the
 *     repo had — was self-confirming: it queried `.text-input, .select-input`,
 *     which is exactly the set `--color-control-border` was written for and
 *     correctly applied to, and it compared each element's border against its own
 *     background rather than against the surface around it. Every BUTTON on this
 *     page draws a 2px border in its own fill colour, and nothing measured it.
 *     `nontext.ts` measures all of them, plus generated content, which neither
 *     axe nor the arithmetic text walk can reach.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page is not currently in that shape, and the assertion is what makes that
 * a measurement rather than a reading: `styles/main.css` declares one
 * `@keyframes` (`byte-probe-pulse`, which cycles opacity 1 → 0.5 → 1) and gates
 * it behind `@media (prefers-reduced-motion: no-preference)`, so under the
 * preference the rule never applies and `.byte-cell--probing` keeps the opacity
 * it was declared with. The check runs in every state regardless, because that is
 * a property of the current stylesheet rather than of the page.
 *
 * `aria-hidden` subtrees are excluded, matching the boundary `contrast.ts` and
 * axe both draw.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page is
 * created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * Unlike some labs in this fleet, this page really does declare a second one —
 * `<header class="cl-hero">` is a direct child of `<body>`, outside `<main>`, so
 * it carries an implicit `banner` role. `index.html`'s `dedupeBanner()` demotes
 * it to `role="group"` on DOMContentLoaded. Asserting the OUTCOME rather than
 * either mechanism means both a change to the nesting and a failure of the
 * demotion script are caught.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/** The six exhibit panels, in tab order, with the tab that reveals each. */
export const PANELS = [
  { panel: '#panel-1', tab: '#tab-1' },
  { panel: '#panel-2', tab: '#tab-2' },
  { panel: '#panel-3', tab: '#tab-3' },
  { panel: '#panel-4', tab: '#tab-4' },
  { panel: '#panel-5', tab: '#tab-5' },
  { panel: '#panel-6', tab: '#tab-6' },
] as const;

/** The nine controls that ship DISABLED until a prerequisite has been run. */
export const LOCKED_CONTROLS = [
  '#p1-predict-valid-btn',
  '#p1-predict-invalid-btn',
  '#p2-run-btn',
  '#p2-stop-btn',
  '#p3-run-btn',
  '#p3-stop-btn',
  '#p4-run-btn',
  '#p4-stop-btn',
  '#p6-tamper-btn',
] as const;

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then *asserted*
 * from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and the shared bar's toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * `hidden` is asserted to actually hide. The attribute's UA rule is
 * `[hidden] { display: none }` at specificity (0,1,0) — the same as a class — so
 * any later `.panel { display: … }` in this stylesheet would beat it and the five
 * closed panels would silently render stacked on top of the open one. That is a
 * confirmed defect elsewhere in this fleet, and here it would also quietly turn
 * every "panel N" scan into a scan of all six.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // Both skip links must land on an element that exists. axe's skip-link rule is
  // "best-practice", not WCAG-tagged, so a green axe run says nothing about this.
  const skipTargets = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLAnchorElement>('a[href^="#"]')).map((a) => ({
      href: a.getAttribute('href'),
      resolves: !!document.querySelector(a.getAttribute('href') as string),
    }))
  );
  expect(
    skipTargets.filter((t) => !t.resolves),
    'every in-page anchor must resolve to an element that exists'
  ).toEqual([]);

  // Every panel is mounted by `src/main.ts`, so a navigation that resolves proves
  // nothing about whether the exhibits are wired.
  for (const id of ['#p1-oracle-demo-btn', '#p2-encrypt-btn', '#p3-encrypt-btn', '#p4-generate-btn', '#p6-bench-btn', '#p6-aead-btn']) {
    await expect(page.locator(id)).toBeEnabled();
  }

  // ── The tablist ships with exactly one panel open ───────────────────────
  await expect(page.locator('#panel-1')).toBeVisible();
  for (const { panel } of PANELS.slice(1)) await expect(page.locator(panel)).toBeHidden();
  expect(
    await page.evaluate(() => getComputedStyle(document.querySelector('#panel-2')!).display),
    'the [hidden] attribute must really hide a panel — a later `.panel { display }` rule beats it'
  ).toBe('none');
  await expect(page.locator('.panel-tab[aria-selected="true"]')).toHaveCount(1);

  // ── Everything that unlocks later ships locked ──────────────────────────
  for (const sel of LOCKED_CONTROLS) await expect(page.locator(sel)).toBeDisabled();

  // ── Every shipped control default, asserted rather than assumed ─────────
  await expect(page.locator('#p1-craft-byte')).toHaveValue('1');
  await expect(page.locator('#p2-plaintext')).toHaveValue('Hello, padding oracle!');
  await expect(page.locator('#p2-speed')).toHaveValue('50');
  await expect(page.locator('#p3-plaintext')).toHaveValue('Attack at dawn!!');
  await expect(page.locator('#p3-speed')).toHaveValue('80');
  await expect(page.locator('#p4-speed')).toHaveValue('10');
  await expect(page.locator('#p6-bench-plaintext')).toHaveValue('Attack at dawn!!');

  // Panel 1's diagram and example lists are injected on mount; Panel 5's exploit
  // cards are the children of a `role="list"`, so an empty one is a live
  // `aria-required-children` result on every load.
  await expect(page.locator('#p1-cbc-diagram')).not.toBeEmpty();
  await expect(page.locator('#p1-valid-padding .badge--valid')).toHaveCount(3);
  await expect(page.locator('#p1-invalid-padding .badge--invalid')).toHaveCount(3);
  await expect(page.locator('#p5-exploits > *').first()).toBeAttached();

  // Nothing on this page has generated a byte yet.
  await expect(page.locator('#p1-oracle-demo-result')).toBeEmpty();
  await expect(page.locator('#p2-query-count')).toHaveText('0');
  await expect(page.locator('#p6-bench-status')).toHaveText('Not run yet.');

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page is a
 * shape that breaks it: two five-column comparison tables, a six-tab bar, byte
 * grids of sixteen fixed-width cells, and hex readouts of unbreakable
 * two-character tokens.
 *
 * `document.scrollWidth` is only a truthful oracle if nothing is clipping the
 * overflow away. `styles/main.css` used to set `body { overflow-x: hidden }`,
 * which propagates to the viewport and makes `scrollWidth === clientWidth` no
 * matter how wide the content is — the check would have reported green while the
 * content ran off the side unreachable, which under 1.4.10 is worse than
 * scrolling, not better. That declaration was removed; this asserts it stays
 * removed, because without that the rest of this function cannot fail.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };
    // A page that hides its own overflow cannot fail the scrollWidth test, so
    // that is checked first and reported as its own failure.
    for (const el of [doc, document.body]) {
      const ox = getComputedStyle(el).overflowX;
      if (ox === 'hidden' || ox === 'clip') {
        return { suppressed: `${el.tagName.toLowerCase()} sets overflow-x: ${ox}` };
      }
    }
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A wide
    // box inside an `overflow-x: auto` wrapper has a huge bounding rect but is
    // clipped by its scroller and contributes nothing to the document's scroll
    // width — naming it sends you off fixing the wrong element. This page has a
    // decoy behind every `.comparison-table-wrapper` and the tab bar.
    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This is a live question here rather than a formality. The two
 * `.comparison-table-wrapper`s and `.panel-tabs-wrapper` are `overflow-x: auto`
 * and only actually overflow at phone width; the hex readouts and byte grids
 * scroll only once an attack has filled them. Both are states a drive has to go
 * and build, which is why this is asserted after every step rather than once.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Anything the drive makes focusable has to SHOW that it is focused (WCAG 2.4.7).
 *
 * A scroller given `tabindex="0"` to satisfy 2.1.1 becomes a tab stop, and a tab
 * stop with no visible indicator is a new failure introduced by the fix for the
 * old one. `styles/main.css` has a global `:focus-visible` outline; this asserts
 * it actually resolves to a drawn outline on the elements this lab makes
 * focusable, rather than trusting that the rule exists.
 */
export async function expectFocusIndicators(page: Page, label: string): Promise<void> {
  // `:focus-visible` depends on the browser's current interaction modality, and
  // a programmatic `.focus()` on a <div> does not match it unless the last input
  // was a keypress. Pressing a key first puts Chromium in keyboard modality, so
  // what this measures is the indicator a keyboard user actually sees rather
  // than the one a mouse user would not.
  await page.keyboard.press('Shift');
  const missing = await page.evaluate(() => {
    const out: string[] = [];
    const targets = Array.from(
      document.querySelectorAll<HTMLElement>('[tabindex="0"]')
    ).filter((el) => (el as HTMLElement).checkVisibility?.());
    const scroll = { x: window.scrollX, y: window.scrollY };
    for (const el of targets) {
      el.focus({ preventScroll: true });
      const cs = getComputedStyle(el);
      const w = parseFloat(cs.outlineWidth || '0');
      if (!(w > 0) || cs.outlineStyle === 'none') {
        out.push(`${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}`);
      }
      el.blur();
    }
    window.scrollTo(scroll.x, scroll.y);
    return Array.from(new Set(out));
  });
  expect(missing, `focusable elements with no visible focus outline in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * FAILS at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/** Run a throwing async assertion, recording instead of throwing when collecting. */
async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion this whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * The shared Crypto Lab top bar is excluded from the 1.4.11 audit, and that is a
 * decision rather than an oversight.
 *
 * `.cl-btn` draws its boundary as
 * `1px solid color-mix(in srgb, var(--accent, #35d6bb) 38%, transparent)` over a
 * transparent fill on the bar's fixed `#0b1512`. This lab defines no `--accent`,
 * so the fallback teal applies and the edge resolves to rgb(27, 94, 82):
 * **2.45:1 against the bar, in both themes** (the bar is always dark, so the
 * theme does not move it). That is under 3:1 and it is real — but every repo in
 * this fleet carries a byte-identical copy of that markup and CSS, and
 * `CLAUDE.md` is explicit that a change every lab should get is a reviewed
 * fleet-wide pass, never an overwrite driven from one repo. So it is measured
 * here, excluded here, and reported upward.
 *
 * The exclusion is exactly the bar and nothing else: everything inside `<main>`,
 * the hero, and the footer are all audited.
 */
const NONTEXT_EXCLUDE = '.cl-topbar';

/**
 * Scan the page as it currently stands.
 *
 * Seven oracles, because axe's `violations` array alone is not a complete one:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically. Everything else there is a real result axe simply could not
 *    finish — including `aria-prohibited-attr`, which is where an `aria-label` on
 *    a role-less element hides, and `aria-required-children`, which is where an
 *    empty `role="list"` hides. Both are live on this page.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content — SC 1.4.11 plus `::before`/`::after`
 *    ink, neither of which axe nor the text walk can see.
 *  - keyboard reachability of scrolling regions (2.1.1) and a visible focus
 *    indicator on everything made focusable (2.4.7).
 *  - reflow (1.4.10), which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write `runOnly`,
  // so the second call SILENTLY REPLACES the first — the axe-core/playwright
  // source says so in as many words ("Cannot be used with AxeBuilder#withTags").
  // Chained as `.withTags(TAGS).withRules([...4 landmark rules])`, which is the
  // form this gate was copied from, axe therefore ran those four best-practice
  // rules and NOT ONE WCAG RULE. A green result meant "no duplicate landmarks",
  // and nothing whatsoever about WCAG A/AA — while reading exactly like a full
  // pass. Running the two sets separately and merging is the only way to have
  // both; the landmark four are wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them, and this page has
  // the shape they catch: a shared sticky `<header role="banner">` above a
  // second `<header class="cl-hero">` that is a sibling of `<main>`, with an
  // `<aside class="cl-hero-why">` inside that hero.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const nonText = await auditNonText(page, 'body *', NONTEXT_EXCLUDE);
  expect(
    nonText.controlsMeasured,
    `no controls found to measure in state: ${label}`
  ).toBeGreaterThan(0);
  softExpect(
    Array.from(new Set(formatNonTextFailures(nonText.failures))),
    `non-text contrast (SC 1.4.11) / generated content in state: ${label}`,
    []
  );

  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectFocusIndicators(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Put the next Tab back at the top of the document.
 *
 * Chromium keeps a *sequential focus navigation starting point*, and both this
 * page and this gate move it: the lab's `activateTab` used to call
 * `scrollIntoView()` on mount (fixed in `src/ui.ts`), and `expectFocusIndicators`
 * focuses every `[tabindex="0"]` element in turn. Neither `blur()` nor collapsing
 * the selection to the start of `<body>` resets it — focusing `<body>` itself
 * does. The temporary `tabindex` is removed immediately, so the DOM the following
 * scan measures is the DOM a reader loads.
 */
async function resetFocusToTop(page: Page): Promise<void> {
  await page.evaluate(() => {
    (document.activeElement as HTMLElement | null)?.blur?.();
    window.scrollTo(0, 0);
    document.body.setAttribute('tabindex', '-1');
    document.body.focus();
    document.body.blur();
    document.body.removeAttribute('tabindex');
  });
}

/** Switch to a tab by clicking it, and assert the swap really happened. */
async function openPanel(page: Page, n: number): Promise<void> {
  await page.locator(`#tab-${n}`).click();
  await expect(page.locator(`#panel-${n}`)).toBeVisible();
  await expect(page.locator(`#tab-${n}`)).toHaveAttribute('aria-selected', 'true');
  for (const { panel } of PANELS) {
    if (panel !== `#panel-${n}`) await expect(page.locator(panel)).toBeHidden();
  }
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - EVERY PANEL IS REACHED THROUGH ITS OWN TAB, and every panel is scanned
 *    BEFORE anything in it has been run as well as after. The arrival state of
 *    each exhibit — empty grids, "Not run yet.", nine disabled controls — is a
 *    real state, it is the one every reader meets first, and the gate this
 *    replaces measured none of them.
 *
 *  - BOTH BRANCHES OF THE PADDING-PREDICTION FORK. Panel 1's exercise scores a
 *    prediction against the real oracle, and renders a `--color-valid` "correct"
 *    verdict or a `--color-invalid` "wrong" one. Only one of those two inks is
 *    ever painted in a given run, so both are driven: 0x01 predicted valid
 *    (correct), then 0x02 predicted valid (wrong).
 *
 *  - THE ATTACK IS SCANNED MID-FLIGHT, not only at its end. `.byte-cell--probing`
 *    and `.byte-cell--found` exist only while a recovery is running; at the end
 *    every cell is `--complete`. The drive runs Panel 3 at the slowest animation
 *    speed and scans while the grid is still part-recovered, which is the only
 *    state those two tones appear in.
 *
 *  - THE STOP PATH AND THE RESET PATH. Panel 2's Stop button is enabled only
 *    while an attack is in flight, and re-encrypting resets the grid — a state
 *    with a populated status line above an emptied grid that no other step
 *    produces.
 *
 *  - NO FIXED TIMEOUTS. Every exhibit is real WebCrypto, and every one has a DOM
 *    completion signal: a status line, a query count, a button returning from
 *    `disabled`. The drive waits on those.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, panel 1 open and nine controls locked');

  await resetFocusToTop(page);
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('shared skip link focused');

  // This page carries a SECOND skip link of its own, after the shared bar's five
  // controls. Tabbing to it rather than focusing it from script keeps the claim
  // a keyboard claim; the count is bounded rather than fixed so a change to the
  // bar's control count fails loudly instead of silently focusing the wrong
  // thing. (The scan above moved the starting point again, hence the reset.)
  await resetFocusToTop(page);
  let reached = false;
  for (let i = 0; i < 10 && !reached; i++) {
    await page.keyboard.press('Tab');
    reached = await page.evaluate(() =>
      document.activeElement?.classList.contains('skip-link') === true
    );
  }
  expect(reached, 'the page skip link must be reachable by tabbing from the top').toBe(true);
  await expect(page.locator('a.skip-link')).toBeFocused();
  await scanAt('page skip link focused');

  // ── Panel 1 ──────────────────────────────────────────────────────────────
  await page.click('#p1-oracle-demo-btn');
  await expect(page.locator('#p1-oracle-demo-result')).not.toBeEmpty();
  await expect(page.locator('#p1-oracle-demo-result .badge--valid').first()).toBeVisible();
  await expect(page.locator('#p1-oracle-demo-result .badge--invalid').first()).toBeVisible();
  await scanAt('live oracle query answered, both verdict badges on screen');

  await expect(page.locator('#p1-predict-valid-btn')).toBeDisabled();
  await page.click('#p1-craft-setup-btn');
  await expect(page.locator('#p1-predict-valid-btn')).toBeEnabled();
  await expect(page.locator('#p1-predict-invalid-btn')).toBeEnabled();
  await scanAt('practice ciphertext set up, prediction unlocked');

  // 0x01 forced into the last decrypted byte IS valid PKCS#7, so predicting
  // "valid" is correct — the only route to the correct-verdict ink.
  await page.selectOption('#p1-craft-byte', '1');
  await page.click('#p1-predict-valid-btn');
  await expect(page.locator('#p1-craft-result')).toContainText('The oracle answered');
  await expect(page.locator('#p1-craft-correct')).toHaveText('1');
  await scanAt('prediction correct, the valid-tone verdict');

  // 0x02 as a single trailing byte is NOT valid padding, so the same prediction
  // is now wrong — the only route to the incorrect-verdict ink.
  await page.selectOption('#p1-craft-byte', '2');
  await page.click('#p1-predict-valid-btn');
  await expect(page.locator('#p1-craft-total')).toHaveText('2');
  await expect(page.locator('#p1-craft-correct')).toHaveText('1');
  await scanAt('prediction wrong, the invalid-tone verdict');

  // ── Panel 2 ──────────────────────────────────────────────────────────────
  await openPanel(page, 2);
  await scanAt('panel 2 arrival, empty grid and locked run button');

  await page.locator('#p2-plaintext').fill('Meet me at seven');
  await page.selectOption('#p2-speed', '0');
  await page.click('#p2-encrypt-btn');
  await expect(page.locator('#p2-status')).toContainText('Session ready');
  await expect(page.locator('#p2-run-btn')).toBeEnabled();
  await expect(page.locator('#p2-iv-display')).not.toBeEmpty();
  await scanAt('panel 2 encrypted, IV and ciphertext rendered');

  await page.click('#p2-run-btn');
  await expect(page.locator('#p2-status')).toContainText('Attack complete', { timeout: 120_000 });
  await expect(page.locator('#p2-result')).not.toBeEmpty();
  await expect(page.locator('#p2-query-count')).not.toHaveText('0');
  await scanAt('panel 2 single byte recovered, grid complete');

  // Re-encrypting resets the grid under a populated status line.
  await page.click('#p2-encrypt-btn');
  await expect(page.locator('#p2-status')).toContainText('Session ready');
  await expect(page.locator('#p2-query-count')).toHaveText('0');
  await scanAt('panel 2 reset, grid emptied under a live status line');

  // ── Panel 3 ──────────────────────────────────────────────────────────────
  await openPanel(page, 3);
  await scanAt('panel 3 arrival, both grids empty');

  // A short message first: the byte-count hint and the "shorter messages are
  // padded" branch are the only place `.control-hint` renders anything but the
  // shipped default, and re-typing also drives the "Plaintext changed" status.
  await page.locator('#p3-plaintext').fill('hi');
  await expect(page.locator('#p3-bytecount')).toContainText('2 bytes');
  await expect(page.locator('#p3-status')).toContainText('Plaintext changed');
  await scanAt('panel 3 plaintext edited, stale-session warning shown');

  await page.locator('#p3-plaintext').fill('Attack at dawn!!');
  await expect(page.locator('#p3-bytecount')).toContainText('16 bytes');
  await page.selectOption('#p3-speed', '300');
  await page.click('#p3-encrypt-btn');
  await expect(page.locator('#p3-run-btn')).toBeEnabled();
  await scanAt('panel 3 target block encrypted');

  // Slow speed on purpose: `.byte-cell--probing` and `.byte-cell--found` exist
  // only mid-recovery, and at the end every cell is `--complete`.
  await page.click('#p3-run-btn');
  await expect(page.locator('#p3-stop-btn')).toBeEnabled();
  await expect(page.locator('#p3-byte-grid .byte-cell--found').first()).toBeVisible({
    timeout: 60_000,
  });
  await scanAt('panel 3 mid-recovery, probing and found cells side by side');

  await page.click('#p3-stop-btn');
  await expect(page.locator('#p3-status')).toContainText(/stopped/i, { timeout: 30_000 });
  await scanAt('panel 3 attack stopped part-way');

  await page.selectOption('#p3-speed', '0');
  await page.click('#p3-encrypt-btn');
  await page.click('#p3-run-btn');
  await expect(page.locator('#p3-status')).toContainText('Full block recovered', {
    timeout: 180_000,
  });
  await expect(page.locator('#p3-xor-display')).not.toBeEmpty();
  await expect(page.locator('#p3-result')).not.toBeEmpty();
  await scanAt('panel 3 full block recovered, XOR view rendered');

  // ── Panel 4 ──────────────────────────────────────────────────────────────
  await openPanel(page, 4);
  await scanAt('panel 4 arrival, progress bar at zero');

  // Two blocks: enough to exercise the multi-block block-viz and the progress
  // bar's intermediate state without a 20k-query run.
  await page.locator('#p4-plaintext').fill('Two whole blocks of secret text.');
  await page.selectOption('#p4-speed', '0');
  await page.click('#p4-generate-btn');
  await expect(page.locator('#p4-run-btn')).toBeEnabled();
  await expect(page.locator('#p4-block-viz')).not.toBeEmpty();
  await scanAt('panel 4 multi-block ciphertext generated');

  await page.click('#p4-run-btn');
  await expect(page.locator('#p4-status')).toContainText(/complete/i, { timeout: 180_000 });
  await expect(page.locator('#p4-result')).not.toBeEmpty();
  await scanAt('panel 4 whole ciphertext recovered');

  // ── Panel 5 ──────────────────────────────────────────────────────────────
  await openPanel(page, 5);
  await expect(page.locator('#p5-exploits [role="listitem"]').first()).toBeVisible();
  await scanAt('panel 5 exploit hall of fame');

  // ── Panel 6 ──────────────────────────────────────────────────────────────
  await openPanel(page, 6);
  await scanAt('panel 6 arrival, bench not run and tamper locked');

  await page.click('#p6-aead-btn');
  await expect(page.locator('#p6-tamper-btn')).toBeEnabled();
  await expect(page.locator('#p6-aead-result')).not.toBeEmpty();
  await scanAt('AES-GCM encrypted, tamper unlocked');

  await page.click('#p6-tamper-btn');
  await expect(page.locator('#p6-aead-result')).toContainText('REJECTED');
  await scanAt('AES-GCM tamper rejected, the alert tone');

  await page.click('#p6-bench-btn');
  await expect(page.locator('#p6-bench-status')).toContainText('failed against both defended ones', {
    timeout: 180_000,
  });
  await expect(page.locator('#p6-bench-rows tr')).toHaveCount(3);
  await expect(page.locator('#p6-bench-note')).not.toBeEmpty();
  await scanAt('defense bench complete, one broken server and two defended');

  // Back to where a reader started, with every exhibit behind it populated.
  await openPanel(page, 1);
  await scanAt('returned to panel 1 with every other exhibit populated');
}
