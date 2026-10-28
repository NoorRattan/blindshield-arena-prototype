import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Landing Page E2E & Accessibility', () => {
  test('renders Landing (/), passes axe audit, tests interactions, and captures screenshots', async ({
    page,
  }, testInfo) => {
    const cdnRequests: string[] = [];
    page.on('request', (req) => {
      const url = req.url();
      if (url.includes('fonts.googleapis.com') || url.includes('fonts.gstatic.com')) {
        cdnRequests.push(url);
      }
    });

    await page.goto('/');

    // 1. Verify Hero headline
    const heroHeadline = page.locator('h1');
    await expect(heroHeadline).toContainText('Every safety finding,');
    await expect(heroHeadline).toContainText('accountable to its');
    await expect(heroHeadline).toContainText('execution conditions.');

    // 2. Verify all 5 numbered editorial sections
    await expect(page.locator('text=01 — THE FAILURE MODES OF UNCHECKED TESTING')).toBeVisible();
    await expect(page.locator('text=02 — SEPARATION OF INTEGRITY AND OUTCOME')).toBeVisible();
    await expect(page.locator('text=03 — EXECUTION ENVELOPE WATERFALL')).toBeVisible();
    await expect(page.locator('text=04 — BOUNDARIES OF ASSURANCE')).toBeVisible();
    await expect(page.locator('text=05 — ARENA ENTRY & AUDIT SINK')).toBeVisible();

    // 3. Test DualVerdict interactive simulation
    const toggleTimeoutBtn = page.getByRole('button', { name: /Inject Defense Timeout/i });
    await expect(toggleTimeoutBtn).toBeVisible();

    await toggleTimeoutBtn.click();
    await expect(page.locator('text=DEADLINE_EXCEEDED')).toBeVisible();
    await expect(page.getByRole('button', { name: /Restore Normal Flow/i })).toBeVisible();

    const restoreBtn = page.getByRole('button', { name: /Restore Normal Flow/i });
    await restoreBtn.click();
    await expect(page.locator('text=EXECUTION_COMPLIANT')).toBeVisible();

    // 4. Test Six Hand-offs stepper navigation
    const step2Tab = page.getByRole('tab', { name: /02/i });
    await step2Tab.click();
    await expect(page.getByRole('heading', { name: /Default-Deny Ingestion/i })).toBeVisible();
    await expect(page.locator('text=WHAT OBSERVER CAN SEE')).toBeVisible();

    // 5. Axe-core accessibility check on Landing (zero violations permitted)
    // Wait for GSAP text timelines to reach resting opacity=1 state (~1400ms total)
    await page.waitForTimeout(1400);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axeResults = await new AxeBuilder({ page: page as any }).analyze();
    expect(axeResults.violations).toEqual([]);

    // 6. Verify zero external font CDN calls (strict self-hosted fonts)
    expect(cdnRequests).toEqual([]);

    // 7. Capture full-page viewport screenshot for project
    await page.screenshot({
      path: `test-results/landing-${testInfo.project.name}.png`,
      fullPage: true,
    });
  });

  test('renders reduced-motion fallback correctly with 2D topology', async ({ page }) => {
    // Emulate prefers-reduced-motion
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/');

    // In reduced motion, 2D SVG fallback with role="img" must be rendered (in hero and handoffs)
    const fallbackSvgs = page.locator('div[role="img"][aria-label*="BlindShield Arena Topology Diagram"]');
    await expect(fallbackSvgs.first()).toBeVisible();
    expect(await fallbackSvgs.count()).toBe(2);

    await page.screenshot({
      path: `test-results/landing-reduced-motion.png`,
      fullPage: false,
    });
  });
});
