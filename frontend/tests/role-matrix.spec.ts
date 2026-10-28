import { test, expect, type Page } from '@playwright/test';

test.describe('P12-S1 Cross-Role Matrix & Gating E2E', () => {
  // Helper to switch roles via the top-bar RoleSwitcher
  async function switchRole(page: Page, roleLabel: 'Operator' | 'Red Team' | 'Blue Team' | 'Auditor') {
    const roleBtn = page.getByRole('button', { name: roleLabel });
    await roleBtn.click();
    await expect(roleBtn).toHaveAttribute('aria-pressed', 'true');
  }

  test.describe('Operator Role Full Access', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/');
      await switchRole(page, 'Operator');
    });

    test('accesses /setup with full 5-step wizard controls', async ({ page }) => {
      await page.goto('/setup');
      await expect(page.locator('h1')).toContainText(/EXPERIMENT SETUP/i);
      await expect(page.getByRole('tab', { name: /Domain & Epoch/i })).toBeVisible();
      await expect(page.getByText('OPERATOR PRIVILEGES REQUIRED')).not.toBeVisible();
    });

    test('accesses /war-room with operational controls and no delayed banner in command header', async ({ page }) => {
      await page.goto('/war-room');
      await expect(page.locator('h1')).toContainText(/LIVE ARENA WAR ROOM/i);
      const headerRegion = page.getByRole('region', { name: 'War Room Command Header' });
      await expect(headerRegion.getByRole('button', { name: /Emergency Quarantine/i })).toBeVisible();
      await expect(headerRegion.getByRole('button', { name: /Re-Witness/i })).toBeVisible();
      await expect(headerRegion.getByText('DELAYED T-30s')).not.toBeVisible();
    });

    test('accesses /red portal with active submission workshop', async ({ page }) => {
      await page.goto('/red');
      await expect(page.locator('h1')).toContainText(/RED TEAM OPERATIONAL PORTAL/i);
      await expect(page.getByRole('button', { name: /SUBMIT PAYLOAD TO BROKER/i })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'ACCESS DENIED — ROLE BOUNDARY ENFORCED' })).not.toBeVisible();
    });

    test('accesses /blue console with artifact inspection', async ({ page }) => {
      await page.goto('/blue');
      await expect(page.locator('h1')).toContainText(/BLUE TEAM DEFENSIVE CONSOLE/i);
      await expect(page.getByText('ACCESS DENIED — DEFENDER TELEMETRY RESTRICTED')).not.toBeVisible();
    });
  });

  test.describe('Red Team Role Gating & Boundary Restrictions', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/');
      await switchRole(page, 'Red Team');
    });

    test('is denied access to /setup wizard with OPERATOR PRIVILEGES REQUIRED', async ({ page }) => {
      await page.goto('/setup');
      await expect(page.getByText('OPERATOR PRIVILEGES REQUIRED')).toBeVisible();
      await expect(page.getByRole('tab', { name: /Domain & Epoch/i })).not.toBeVisible();
    });

    test('observes /war-room in DELAYED T-30s mode without operator controls', async ({ page }) => {
      await page.goto('/war-room');
      await expect(page.locator('h1')).toContainText(/LIVE ARENA WAR ROOM/i);
      const headerRegion = page.getByRole('region', { name: 'War Room Command Header' });
      await expect(headerRegion.getByText('DELAYED T-30s')).toBeVisible();
      await expect(headerRegion.getByRole('button', { name: /Emergency Quarantine/i })).not.toBeVisible();
      await expect(headerRegion.getByRole('button', { name: /Re-Witness/i })).not.toBeVisible();
    });

    test('is denied access to /blue console with ACCESS DENIED — DEFENDER TELEMETRY RESTRICTED', async ({ page }) => {
      await page.goto('/blue');
      await expect(page.getByText('ACCESS DENIED — DEFENDER TELEMETRY RESTRICTED')).toBeVisible();
    });

    test('can access /red portal with own workshop and bounded feedback', async ({ page }) => {
      await page.goto('/red');
      await expect(page.locator('h1')).toContainText(/RED TEAM OPERATIONAL PORTAL/i);
      await expect(page.getByRole('button', { name: /SUBMIT PAYLOAD TO BROKER/i })).toBeVisible();
    });
  });

  test.describe('Blue Team Role Gating & Boundary Restrictions', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/');
      await switchRole(page, 'Blue Team');
    });

    test('is denied access to /setup wizard with OPERATOR PRIVILEGES REQUIRED', async ({ page }) => {
      await page.goto('/setup');
      await expect(page.getByText('OPERATOR PRIVILEGES REQUIRED')).toBeVisible();
    });

    test('is denied access to /red portal with ACCESS DENIED — ROLE BOUNDARY ENFORCED', async ({ page }) => {
      await page.goto('/red');
      await expect(page.getByRole('heading', { name: 'ACCESS DENIED — ROLE BOUNDARY ENFORCED' })).toBeVisible();
    });

    test('can access /blue console; during ACTIVE round allow/block split is withheld (C-02)', async ({
      page,
    }) => {
      await page.goto('/blue');
      await expect(page.locator('h1')).toContainText(/BLUE TEAM DEFENSIVE CONSOLE/i);
      await expect(page.getByText(/WITHHELD \(C-02\)/i)).toBeVisible();
    });

    test('observes /war-room in DELAYED T-30s mode', async ({ page }) => {
      await page.goto('/war-room');
      const headerRegion = page.getByRole('region', { name: 'War Room Command Header' });
      await expect(headerRegion.getByText('DELAYED T-30s')).toBeVisible();
      await expect(headerRegion.getByRole('button', { name: /Emergency Quarantine/i })).not.toBeVisible();
    });
  });

  test.describe('Auditor Role Gating & Verification Access', () => {
    test.beforeEach(async ({ page }) => {
      await page.goto('/');
      await switchRole(page, 'Auditor');
    });

    test('is denied access to /red offensive workshop with ACCESS DENIED', async ({ page }) => {
      await page.goto('/red');
      await expect(page.getByRole('heading', { name: 'ACCESS DENIED — ROLE BOUNDARY ENFORCED' })).toBeVisible();
    });

    test('can access /blue console in read-only audit mode', async ({ page }) => {
      await page.goto('/blue');
      await expect(page.locator('h1')).toContainText(/BLUE TEAM DEFENSIVE CONSOLE/i);
      await expect(page.getByText('ACCESS DENIED — DEFENDER TELEMETRY RESTRICTED')).not.toBeVisible();
    });

    test('has full verified bundle inspection and export access on /evidence', async ({ page }) => {
      await page.goto('/evidence');
      await expect(page.locator('h1')).toContainText(/EVIDENCE INSPECTOR/i);
      const verdictChip = page.getByTestId('overall-verdict-chip');
      await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE', { timeout: 15000 });
      const exportBtn = page.getByRole('button', { name: /EXPORT REPORT/i });
      await expect(exportBtn).toBeVisible();
    });
  });
});

