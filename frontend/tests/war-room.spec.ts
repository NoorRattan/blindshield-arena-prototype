import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Live War Room E2E & Accessibility', () => {
  test('renders War Room (/war-room), verifies waterfall, failure injections, quarantine, and passes axe audit', async ({
    page,
  }, testInfo) => {
    // Navigate to war room with default running arena
    await page.goto('/war-room?arena=exp_running_01');

    // 1. Verify PageHeader document ID & headline
    const headline = page.locator('h1');
    await expect(headline).toContainText('LIVE ARENA WAR ROOM');
    await expect(page.locator('text=DOC-WAR-04').first()).toBeVisible();

    // 2. Verify Top Bar metadata
    const topBar = page.getByLabel('War Room Command Header');
    await expect(topBar.getByText('BAYORA-PROD-01')).toBeVisible();
    await expect(topBar.getByText('EPOCH')).toBeVisible();
    await expect(topBar.getByText('04', { exact: true })).toBeVisible();
    await expect(topBar.getByText('EMERGENCY QUARANTINE')).toBeVisible();
    await expect(topBar.getByRole('button', { name: /Re-Witness/i })).toBeVisible();

    // Verify DualVerdict component (two separate verdicts)
    const dualVerdict = page.getByRole('group', { name: /Dual Verdict/i });
    await expect(dualVerdict.getByText('Model Outcome')).toBeVisible();
    await expect(dualVerdict.getByText('Assurance Integrity')).toBeVisible();

    // 3. Verify Pipeline Waterfall with 6 stages
    await expect(page.locator('text=PIPELINE EXECUTION WATERFALL')).toBeVisible();
    await expect(page.locator('text=01 / RED SUBMIT')).toBeVisible();
    await expect(page.locator('text=02 / BROKER INGEST')).toBeVisible();
    await expect(page.locator('text=03 / BLUE DEFENSE')).toBeVisible();
    await expect(page.locator('text=04 / TARGET MODEL')).toBeVisible();
    await expect(page.locator('text=05 / SCORER')).toBeVisible();
    await expect(page.locator('text=06 / RECORDER')).toBeVisible();

    // 4. Verify Telemetry Gauges with ILLUSTRATIVE tags
    await expect(page.locator('text=ATTRIBUTE TELEMETRY GAUGES')).toBeVisible();
    await expect(page.locator('text=Broker Queue Depth')).toBeVisible();
    await expect(page.locator('text=Blue Cell Memory')).toBeVisible();
    await expect(page.locator('text=Target TTFT')).toBeVisible();
    await expect(page.locator('text=Generation Speed')).toBeVisible();
    await expect(page.locator('text=Circuit Breaker')).toBeVisible();
    await expect(page.locator('text=Network Isolation')).toBeVisible();
    await expect(page.locator('text=Witness Watermark')).toBeVisible();

    // Verify ILLUSTRATIVE tags appear on telemetry
    const illustrativeTags = page.locator('text=ILLUSTRATIVE');
    expect(await illustrativeTags.count()).toBeGreaterThan(0);

    // 5. Verify Virtualized Audit Log
    await expect(page.locator('text=LIVE CHAINED AUDIT LOG')).toBeVisible();
    await expect(page.locator('text=EVENTS (VIRTUALISED)')).toBeVisible();

    // Verify Actor Filters
    const actorFilters = page.getByRole('group', { name: /Actor Filters/i });
    await expect(actorFilters.getByRole('button', { name: /^all$/i })).toBeVisible();
    await expect(actorFilters.getByRole('button', { name: /^red$/i })).toBeVisible();
    await expect(actorFilters.getByRole('button', { name: /^blue$/i })).toBeVisible();
    await expect(actorFilters.getByRole('button', { name: /^target$/i })).toBeVisible();
    await expect(actorFilters.getByRole('button', { name: /^broker$/i })).toBeVisible();
    await expect(actorFilters.getByRole('button', { name: /^recorder$/i })).toBeVisible();

    // 6. Test Failure Injection: defense_timeout
    const timeoutBtn = page.getByRole('button', { name: /defense_timeout/i });
    await timeoutBtn.click();

    // Stage 3 should enter purple timeout state
    await expect(page.locator('text=Deadline 1,000ms exceeded')).toBeVisible();
    await expect(page.locator('text=TIMEOUT').first()).toBeVisible();
    // Verdict updates to INVALID
    await expect(page.locator('text=DEFENSE_DEADLINE_EXCEEDED (1,002ms)')).toBeVisible();

    // 7. Test Failure Injection: witness_lag
    const witnessLagBtn = page.getByRole('button', { name: /witness_lag/i });
    await witnessLagBtn.click();
    await expect(page.locator('text=WITNESS: LAGGING')).toBeVisible();

    // Reset failure injections
    const resetBtn = page.getByRole('button', { name: /Reset/i });
    await resetBtn.click();
    await expect(page.locator('text=Deadline 1,000ms exceeded')).not.toBeVisible();

    // 8. Test Role Observability Preview
    await expect(page.locator('text=ROLE OBSERVABILITY BOUNDARY')).toBeVisible();
    await expect(page.locator('text=Operator (Full Telemetry)')).toBeVisible();
    await expect(page.locator('text=View as Red Team')).toBeVisible();
    await expect(page.locator('text=View as Blue Team')).toBeVisible();

    // 9. Test Emergency Quarantine Modal
    const quarantineBtn = topBar.getByRole('button', { name: /Emergency Quarantine/i });
    await quarantineBtn.click();

    // Dialog should appear
    await expect(page.locator('text=EMERGENCY STOP & DOMAIN QUARANTINE')).toBeVisible();

    // Confirm button should be disabled until exact string is typed
    const confirmBtn = page.getByRole('button', { name: /Confirm Quarantine/i });
    await expect(confirmBtn).toBeDisabled();

    // Type QUARANTINE into input
    const confirmInput = page.getByPlaceholder('QUARANTINE');
    await confirmInput.fill('QUARANTINE');
    await expect(confirmBtn).toBeEnabled();

    // Execute quarantine
    await confirmBtn.click({ force: true });

    // Modal closes and domain marked INVALID / Domain Quarantined
    await expect(topBar.getByText('Domain Quarantined')).toBeVisible();

    // 10. Axe-core accessibility audit
    await page.waitForTimeout(1000);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axeResults = await new AxeBuilder({ page: page as any }).analyze();
    expect(axeResults.violations).toEqual([]);

    // 11. Capture screenshot for viewport
    await page.screenshot({
      path: `test-results/war-room-${testInfo.project.name}.png`,
      fullPage: true,
    });
  });

  test('role matrix: verifies non-operator role receives delayed coarse telemetry', async ({ page }) => {
    await page.goto('/war-room?arena=exp_running_01');

    // Switch role to Red Team via Header Role Selector
    const redRoleBtn = page.getByRole('button', { name: /Red Team/i });
    if (await redRoleBtn.isVisible()) {
      await redRoleBtn.click();
      // Verify DELAYED T-30s badge appears in TopBar
      await expect(page.getByText('DELAYED T-30s', { exact: true })).toBeVisible();
      // Verify Emergency Quarantine is NOT available for non-operators
      await expect(page.getByRole('button', { name: /EMERGENCY QUARANTINE/i })).not.toBeVisible();
    }
  });
});
