import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Smoke E2E & Accessibility', () => {
  test('renders shell, passes axe accessibility, and self-hosts fonts', async ({ page }, testInfo) => {
    const cdnRequests: string[] = [];

    // Monitor network requests for any unexpected font CDN leakage
    page.on('request', (request) => {
      const url = request.url();
      if (url.includes('fonts.googleapis.com') || url.includes('fonts.gstatic.com')) {
        cdnRequests.push(url);
      }
    });

    await page.goto('/smoke');

    // 1. Verify headline text rendered
    const heading = page.locator('h1');
    await expect(heading).toHaveText('BLINDSHIELD ARENA');

    // 2. Take viewport screenshot
    await page.screenshot({
      path: `test-results/smoke-${testInfo.project.name}.png`,
      fullPage: true,
    });

    // 3. Axe accessibility check (0 serious / critical violations)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axeResults = await new AxeBuilder({ page: page as any }).analyze();
    expect(axeResults.violations).toEqual([]);

    // 4. Verify no CDN requests (fonts are strictly self-hosted via @fontsource)
    expect(cdnRequests).toEqual([]);

    // 5. Verify dark theme is strictly enforced
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.locator('#smoke-theme-badge')).toBeVisible();
  });

  test('renders /__kit showcase, passes axe audit, and verifies keyboard dialogs', async ({ page }, testInfo) => {
    await page.goto('/__kit');

    // 1. Verify page title
    const heading = page.locator('h1');
    await expect(heading).toHaveText('COMPONENT & PRIMITIVE KIT');

    // 2. Verify primitives are mounted
    await expect(page.locator('text=DUAL VERDICT INVARIANT')).toBeVisible();
    await expect(page.locator('text=UNTRUSTED TEXT SINK')).toBeVisible();
    await expect(page.locator('text=THREAT SCOPE & RESIDUAL RISK')).toBeVisible();

    // 3. Axe accessibility check on /__kit (zero violations allowed; wait for mount tween)
    await page.waitForTimeout(800);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axeResults = await new AxeBuilder({ page: page as any }).analyze();
    expect(axeResults.violations).toEqual([]);

    // 4. Take full-page screenshot of kit
    await page.screenshot({
      path: `test-results/kit-${testInfo.project.name}.png`,
      fullPage: true,
    });

    // 5. Verify Command Palette open via shortcut and close with Esc
    await page.keyboard.press('Control+KeyK');
    const palette = page.locator('[role="dialog"][aria-label="Command Palette"]');
    await expect(palette).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(palette).not.toBeVisible();

    // 6. Test typed confirm dialog interaction
    const triggerBtn = page.getByRole('button', { name: /Trigger Quarantine Dialog/i });
    await triggerBtn.click();

    const confirmDialog = page.locator('[role="dialog"][aria-labelledby="confirm-dialog-title"]');
    await expect(confirmDialog).toBeVisible();

    const actionBtn = page.getByRole('button', { name: /EXECUTE QUARANTINE/i });
    await expect(actionBtn).toBeDisabled();

    const inputField = page.locator('#confirm-input-field');
    await inputField.fill('QUARANTINE-ARENA');
    await expect(actionBtn).toBeEnabled();

    // Cancel and close dialog
    const cancelBtn = page.getByRole('button', { name: /Cancel/i });
    await cancelBtn.click();
    await expect(confirmDialog).not.toBeVisible();
  });
});
