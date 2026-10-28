import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Overview Page E2E, Role Matrix & Accessibility', () => {
  test('renders Overview (/overview), verifies metrics, filters, navigation, and passes axe audit', async ({
    page,
  }, testInfo) => {
    await page.goto('/overview');

    // 1. Verify PageHeader document ID & headline
    const headline = page.locator('h1');
    await expect(headline).toContainText('ARENA ROSTER & INTEGRITY OVERVIEW');
    await expect(page.locator('text=OVW-ARENA-01')).toBeVisible();

    // 2. Verify all 4 Metric Tiles
    await expect(page.locator('text=01 / ACTIVE DOMAINS')).toBeVisible();
    await expect(page.locator('text=02 / EVALUATIONS RUN')).toBeVisible();
    await expect(page.locator('text=03 / INTEGRITY RATE')).toBeVisible();
    await expect(page.locator('text=04 / P95 BROKER LATENCY')).toBeVisible();

    // Numerator / denominator & invalid count
    await expect(page.locator('text=33 / 34')).toBeVisible();
    await expect(page.locator('text=[1 INVALIDATED]')).toBeVisible();

    // Blocked count shown separately
    await expect(page.locator('text=[9 BLOCKED]')).toBeVisible();

    // Target line
    await expect(page.locator('text=TARGET ≤ 100 ms')).toBeVisible();

    // 3. Verify Arena Roster DataTable
    const dataTable = page.getByRole('region', { name: /Data Table/i });
    await expect(dataTable.getByText('BAYORA-PROD-01')).toBeVisible();
    await expect(dataTable.getByText('BAYORA-SEC-02')).toBeVisible();
    await expect(dataTable.getByText('BAYORA-TEST-03')).toBeVisible();
    await expect(dataTable.getByText('BAYORA-EVAL-04')).toBeVisible();

    // Invalid arena visibly distinct with purple pill and reason code
    await expect(dataTable.getByText('(DEADLINE_EXCEEDED)')).toBeVisible();

    // 4. Test Filter Chips
    const runningChip = page.getByRole('button', { name: /^Running/i });
    await runningChip.click();
    await expect(dataTable.getByText('BAYORA-PROD-01')).toBeVisible();
    await expect(dataTable.getByText('BAYORA-SEC-02')).not.toBeVisible();

    const invalidChip = page.getByRole('button', { name: /^Invalid/i });
    await invalidChip.click();
    await expect(dataTable.getByText('BAYORA-TEST-03')).toBeVisible();
    await expect(dataTable.getByText('BAYORA-PROD-01')).not.toBeVisible();

    const allChip = page.getByRole('button', { name: /^All Arenas/i });
    await allChip.click();
    await expect(dataTable.getByText('BAYORA-PROD-01')).toBeVisible();
    await expect(dataTable.getByText('BAYORA-SEC-02')).toBeVisible();

    // 5. Verify Streaming Alert Feed and Heartbeat Strip
    await expect(page.locator('text=02 — INTEGRITY ALERTS')).toBeVisible();
    await expect(page.locator('text=03 — WITNESS CONSENSUS HEARTBEAT')).toBeVisible();
    await expect(page.locator('text=WATERMARK #441')).toBeVisible();

    // 6. Axe-core accessibility audit (zero violations permitted)
    await page.waitForTimeout(1200);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axeResults = await new AxeBuilder({ page: page as any }).analyze();
    expect(axeResults.violations).toEqual([]);

    // 7. Capture page screenshot for this viewport project
    await page.screenshot({
      path: `test-results/overview-${testInfo.project.name}.png`,
      fullPage: true,
    });

    // 8. Test row navigation to War Room
    const prodRow = page.locator('tr').filter({ hasText: 'BAYORA-PROD-01' });
    await prodRow.click();
    await expect(page).toHaveURL(/.*\/war-room\?arena=exp_running_01/);
  });

  test('role matrix: verifies all 4 roles and captures screenshots', async ({ page }) => {
    await page.goto('/overview');

    const roleConfig = [
      { id: 'operator', name: 'Operator' },
      { id: 'red', name: 'Red Team' },
      { id: 'blue', name: 'Blue Team' },
      { id: 'auditor', name: 'Auditor' },
    ] as const;

    for (const r of roleConfig) {
      // Switch role via the RoleSwitcher button in the header
      const roleBtn = page.getByRole('button', { name: new RegExp(`^${r.name}$`, 'i') });
      if (await roleBtn.isVisible()) {
        await roleBtn.click();
      }

      await page.waitForTimeout(300);

      if (r.id !== 'operator') {
        // Non-operator roles MUST display DELAYED T-30s
        await expect(page.locator('text=DELAYED T-30s').first()).toBeVisible();
      }

      await page.screenshot({
        path: `test-results/overview-role-${r.id}.png`,
        fullPage: false,
      });
    }
  });
});
