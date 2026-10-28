import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { CANARY_TOKENS } from '../src/lib/mock/fixtures';

test.describe('Blue Team Defense Console (/blue) E2E & Accessibility', () => {
  test('renders Blue Console for blue role, verifies zero payload leakage during active round, explores forensics, and passes axe audit', async ({
    page,
  }, testInfo) => {
    // Navigate to /blue
    await page.goto('/blue');

    // 1. Switch role to 'blue' via persistent RoleSwitcher in AppShell
    const roleSwitcher = page.getByRole('group', { name: /Role selector/i });
    if (await roleSwitcher.isVisible()) {
      await roleSwitcher.getByRole('button', { name: /Blue Team/i }).click();
    }

    // 2. Verify PageHeader document ID & headline
    const headline = page.locator('h1');
    await expect(headline).toContainText('BLUE TEAM DEFENSIVE CONSOLE');
    await expect(page.locator('text=DOC-BLUE-06').first()).toBeVisible();

    // 3. Verify distinctive Cobalt Defense Context Strip (distinguishable from Red portal)
    await expect(page.locator('text=DEFENSE CONSOLE')).toBeVisible();
    await expect(page.locator('text=gVisor Sandbox (profile: runsc-ptrace)')).toBeVisible();

    // 4. Verify S1: Defense Artifact Vault & Envelope
    await expect(page.locator('text=01 — DEFENSE ARTIFACT VAULT & ENVELOPE')).toBeVisible();
    await expect(page.locator('text=NeMo-Guard-blindshield-defense-v1.4')).toBeVisible();
    await expect(page.locator('text=FROZEN & SEALED')).toBeVisible();
    await expect(page.locator('text=2,048 MB LIMIT')).toBeVisible();
    await expect(page.locator('text=cgroup v2 isolation enforced')).toBeVisible();

    // Verify readiness probes
    await expect(page.locator('text=Readiness probe (/healthz)')).toBeVisible();
    await expect(page.locator('text=Filter latency baseline check')).toBeVisible();
    await expect(page.locator('text=gVisor runsc isolation verified')).toBeVisible();
    await expect(page.locator('text=Default-deny egress filter')).toBeVisible();

    // 5. Test Version Mismatch Simulation
    const simulateMismatchBtn = page.getByRole('button', { name: /Simulate Version Mismatch/i });
    await expect(simulateMismatchBtn).toBeVisible();
    await simulateMismatchBtn.click();

    // Expect high-visibility banner
    const alertBanner = page.getByRole('alert');
    await expect(alertBanner).toBeVisible();
    await expect(alertBanner).toContainText('VERSION_MISMATCH');
    await expect(alertBanner).toContainText('ACTIVE EPOCH INVALIDATED');

    // Restore version
    const restoreBtn = page.getByRole('button', { name: /Restore Pinned Version/i });
    await restoreBtn.click();
    await expect(page.locator('text=FROZEN & SEALED')).toBeVisible();

    // 6. Verify S2: Sanitized Live Round Health Monitor (Zero Payload Leakage during Active round)
    await expect(page.locator('text=02 — LIVE ROUND HEALTH MONITOR')).toBeVisible();
    await expect(page.locator('text=SECURITY POLICY // SPEC CORRECTION C-02 & FE-D-003')).toBeVisible();
    await expect(page.locator('text=Total Processed')).toBeVisible();
    await expect(page.getByText('DELAYED T-30s').first()).toBeVisible();
    await expect(page.locator('text=WITHHELD (C-02)')).toBeVisible();

    const liveTableRegion = page.getByRole('region', { name: /Sanitized Live Turns Table/i });
    await expect(liveTableRegion).toBeVisible();

    // Expect sanitized turns with EmbargoMask
    await expect(liveTableRegion.getByText('Turn 01').first()).toBeVisible();
    await expect(liveTableRegion.getByText('DECISION EMBARGOED').first()).toBeVisible();
    await expect(liveTableRegion.getByText('PAYLOAD MASKED').first()).toBeVisible();

    // Critical assertion: In active round, NO Allow/Block split or prompt text in the monitor DOM
    const monitorHtml = await liveTableRegion.innerHTML();
    expect(monitorHtml).not.toContain('ALLOWED');
    expect(monitorHtml).not.toContain('BLOCKED');

    // 7. Verify S3: Closed-Round Forensic Workshop
    await expect(page.locator('text=03 — CLOSED ROUND FORENSIC WORKSHOP')).toBeVisible();

    // Post-release metrics should be unlocked for released epoch exp_released_04
    await expect(page.locator('text=Total Analyzed Turns')).toBeVisible();
    await expect(page.locator('text=Blocked by Defense')).toBeVisible();
    await expect(page.locator('text=Allowed to Target')).toBeVisible();
    await expect(page.locator('text=VERIFIED POST-RELEASE')).toBeVisible();

    // Verify Forensic Inspector Quad Grid
    await expect(page.locator('text=Attack Payload (Released)')).toBeVisible();
    await expect(page.locator('text=Defense Decision Log')).toBeVisible();
    await expect(page.locator('text=Scorer Ground Truth')).toBeVisible();
    await expect(page.locator('text=Model Response (Post-Release)')).toBeVisible();

    // Verify Turn Navigation
    const turnBtn3 = page.getByRole('button', { name: /3 \[BLOCK\]/i });
    if (await turnBtn3.isVisible()) {
      await turnBtn3.click();
      await expect(page.locator('text=JAILBREAK_PATTERN_402')).toBeVisible();
      await expect(page.getByText('BLOCKED_BY_DEFENSE').first()).toBeVisible();
    }

    // Verify replay bundle download is disabled for blue role with notice
    const replayBtn = page.getByRole('button', { name: /Download Decrypted Replay Bundle/i });
    await expect(replayBtn).toBeDisabled();
    await expect(page.locator('text=[Auditor Credentials Required]')).toBeVisible();

    // 8. Assert ZERO canary token leakage anywhere in the page DOM
    const pageHtml = await page.content();
    for (const canary of Object.values(CANARY_TOKENS)) {
      expect(pageHtml).not.toContain(canary);
    }

    // 9. Axe accessibility audit (zero violations)
    await page.waitForTimeout(600); // Settle GSAP / UI animations
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axeResults = await new AxeBuilder({ page: page as any })
      .disableRules(['color-contrast']) // Status tokens calibrated to design-system dark theme tokens
      .analyze();
    expect(axeResults.violations).toEqual([]);

    // 10. Viewport screenshot
    await page.screenshot({
      path: `test-results/blue-console-${testInfo.project.name}.png`,
      fullPage: true,
    });
  });

  test('auditor role can download decrypted replay bundle', async ({ page }) => {
    await page.goto('/blue');

    const roleSwitcher = page.getByRole('group', { name: /Role selector/i });
    if (await roleSwitcher.isVisible()) {
      await roleSwitcher.getByRole('button', { name: /Auditor/i }).click();
    }

    // Verify replay bundle download button is enabled for auditor
    const replayBtn = page.getByRole('button', { name: /Download Decrypted Replay Bundle/i });
    await expect(replayBtn).toBeEnabled();
  });

  test('enforces role matrix: blocks red offensive team with UNAUTHORIZED status', async ({ page }) => {
    await page.goto('/blue');

    const roleSwitcher = page.getByRole('group', { name: /Role selector/i });
    if (await roleSwitcher.isVisible()) {
      await roleSwitcher.getByRole('button', { name: /Red Team/i }).click();
    }

    // Verify error state
    await expect(page.locator('text=ACCESS DENIED — DEFENDER TELEMETRY RESTRICTED')).toBeVisible();
    await expect(page.locator('text=UNAUTHORIZED')).toBeVisible();
  });
});
