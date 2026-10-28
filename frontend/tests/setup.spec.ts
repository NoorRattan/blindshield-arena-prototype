import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Experiment Setup Page E2E, Canonical Manifest & Role Matrix', () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem('blindshield_role', 'operator');
    });
  });

  test('renders /setup for Operator, verifies 5-step wizard, live canonical preview, preflight, registration receipt, and passes axe audit', async ({
    page,
  }, testInfo) => {
    const cdnRequests: string[] = [];
    page.on('request', (request) => {
      const url = request.url();
      if (url.includes('fonts.googleapis.com') || url.includes('fonts.gstatic.com')) {
        cdnRequests.push(url);
      }
    });

    await page.goto('/setup');

    // 1. Verify PageHeader document ID & headline
    const headline = page.locator('h1');
    await expect(headline).toContainText('EXPERIMENT SETUP & CANONICAL MANIFEST COMPOSER');
    await expect(page.locator('text=DOC-EXP-SETUP')).toBeVisible();
    await expect(page.locator('text=OPERATOR READY')).toBeVisible();

    // 2. Verify Stepper & Step 1: Domain & Epoch
    await expect(page.getByRole('tab', { name: /1. Domain & Epoch/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /2. Target Inference/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /3. Blue Defense/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /4. Red Constraints/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /5. Disclosure Policy/i })).toBeVisible();

    // Verify Invariant 5 (Strict positive integer validation)
    const epochInput = page.locator('#epoch-input');
    await epochInput.fill('0');
    await page.getByRole('button', { name: /Next Step/i }).click();
    await expect(page.locator('text=Epoch must be an exact positive integer')).toBeVisible();

    // Reset epoch to valid 1
    await epochInput.fill('1');

    // 3. Verify Live Canonical Manifest Preview with Web Worker Digest
    await expect(page.locator('text=CANONICAL MANIFEST PREVIEW')).toBeVisible();
    await expect(page.locator('text=LIVE WEB WORKER DIGEST')).toBeVisible();
    await expect(page.getByRole('button', { name: /Copy Canonical JSON/i })).toBeVisible();

    // Verify line numbers in canonical viewer
    await expect(page.locator('text=RFC 8785').first()).toBeVisible();
    await expect(page.locator('text=Computed Manifest Digest')).toBeVisible();

    // 4. Step 2: Target Inference
    const step2Tab = page.getByRole('tab', { name: /2. Target Inference/i });
    await step2Tab.click();
    await expect(page.locator('text=01. Target Model Under Evaluation')).toBeVisible();
    await expect(page.locator('text=02. Serving Engine & Runtime')).toBeVisible();
    await expect(page.locator('text=TARGET DEFAULT').first()).toBeVisible();

    // 5. Step 3: Blue Defense (Embargoed prefix-cache salt)
    const step3Tab = page.getByRole('tab', { name: /3. Blue Defense/i });
    await step3Tab.click();
    await expect(page.locator('text=01. Defense Image Digest (OCI Container)')).toBeVisible();
    await expect(page.locator('text=04. Prefix-Cache Isolation Salt')).toBeVisible();
    await expect(page.locator('text=server-assigned secret [embargoed]').first()).toBeVisible();
    await expect(page.locator('text=LOCKED · SERVER SECRET')).toBeVisible();

    // 6. Step 4: Red Constraints & Assurance Lane
    const step4Tab = page.getByRole('tab', { name: /4. Red Constraints/i });
    await step4Tab.click();
    await expect(page.locator('text=01. Red Team Submission Ingestion Limits')).toBeVisible();
    await expect(page.locator('text=02. Infrastructure Assurance Lane')).toBeVisible();
    await expect(page.locator('text=Shared-host (gVisor cells)')).toBeVisible();

    // 7. Step 5: Disclosure Policy
    const step5Tab = page.getByRole('tab', { name: /5. Disclosure Policy/i });
    await step5Tab.click();
    await expect(page.locator('text=SEALED_BATCH (Default)')).toBeVisible();
    await expect(page.locator('text=CONTROLLED_FEEDBACK').first()).toBeVisible();

    // 8. Verify Infrastructure Preflight Scanner
    await expect(page.locator('text=INFRASTRUCTURE PREFLIGHT SCANNER')).toBeVisible();
    await expect(page.locator('text=gVisor runsc runtime confirmed')).toBeVisible();
    await expect(page.locator('text=Witness reachable')).toBeVisible();
    await expect(page.locator('text=PREFLIGHT CLEARED · 8 OF 8 REQUIRED CHECKS PASSED')).toBeVisible();

    // 9. Verify Residual Risk Panel (with NOT VERIFIED status)
    await expect(page.locator('text=THREAT SCOPE & RESIDUAL RISK')).toBeVisible();
    await expect(page.getByRole('region', { name: /Committed Threat Scope/i }).locator('text=NOT VERIFIED').first()).toBeVisible();

    // 10. Sign & Register experiment
    const signBtn = page.getByRole('button', { name: /SIGN & REGISTER WITH WITNESS/i });
    await expect(signBtn).toBeEnabled();
    await signBtn.click();

    // 11. Verify ReceiptCard (Receipt object returned from server)
    await expect(page.locator('text=EXPERIMENT SEALED & ATTESTED')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Witness Receipt ID')).toBeVisible();
    await expect(page.locator('text=Sealed Manifest Digest')).toBeVisible();
    await expect(page.getByRole('button', { name: /Enter War Room/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Configure Another Experiment/i })).toBeVisible();

    // 12. Axe-core accessibility audit (zero violations permitted)
    await page.waitForTimeout(900);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axeResults = await new AxeBuilder({ page: page as any }).analyze();
    expect(axeResults.violations).toEqual([]);

    // 13. Verify zero CDN font requests
    expect(cdnRequests).toEqual([]);

    // 14. Capture full-page screenshot
    await page.screenshot({
      path: `test-results/setup-${testInfo.project.name}.png`,
      fullPage: true,
    });
  });

  test('role matrix: non-operator roles receive an explicit UNAUTHORIZED state', async ({ page }) => {
    await page.goto('/setup');

    // Switch to Red Team via Header RoleSwitcher or store
    const redRoleBtn = page.getByRole('button', { name: /Red Team/i });
    if (await redRoleBtn.isVisible()) {
      await redRoleBtn.click();
    } else {
      await page.evaluate(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (window as any).__arenaStore?.getState().setRole('red');
      });
    }

    await page.waitForTimeout(400);

    // Verify explicit ErrorState
    await expect(page.locator('text=OPERATOR PRIVILEGES REQUIRED')).toBeVisible();
    await expect(page.locator('text=restricted to the operator role')).toBeVisible();

    // Verify wizard and preflight are strictly not mounted
    await expect(page.locator('text=01 — EXPERIMENT WIZARD')).not.toBeVisible();
    await expect(page.locator('text=INFRASTRUCTURE PREFLIGHT SCANNER')).not.toBeVisible();

    // Switch back to Operator via error recovery button
    const switchBackBtn = page.getByRole('button', { name: /SWITCH TO OPERATOR ROLE/i });
    await expect(switchBackBtn).toBeVisible();
    await switchBackBtn.click();

    await page.waitForTimeout(400);

    // Verify wizard restored
    await expect(page.locator('text=EXPERIMENT SETUP & CANONICAL MANIFEST COMPOSER')).toBeVisible();
  });
});
