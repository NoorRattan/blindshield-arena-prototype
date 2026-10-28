import { test, expect } from '@playwright/test';

test.describe('P12-S6 Error Boundaries, 404, & Failure Resilience', () => {
  test('renders 404 page with ERR_ROUTE_NOT_FOUND on unmapped routes', async ({ page }) => {
    await page.goto('/nonexistent-test-partition');

    await expect(page.locator('h1')).toHaveText(/ROUTE NOT RESOLVED/i);
    await expect(page.getByText('ERR_ROUTE_NOT_FOUND')).toBeVisible();
    await expect(page.getByText(/Unmapped Arena Endpoint/i)).toBeVisible();

    // Verify recovery link back to landing
    const returnLink = page.getByRole('link', { name: /Return to Landing/i });
    await expect(returnLink).toBeVisible();
    await returnLink.click();

    await expect(page).toHaveURL('http://localhost:5173/');
    await expect(page.locator('h1')).toHaveText(/Every safety finding/i);
  });

  test('displays typed integrity alerts when failure modes are injected in War Room', async ({
    page,
  }) => {
    await page.goto('/war-room');
    await page.waitForLoadState('networkidle');

    // Inject Defense Timeout failure mode
    const timeoutBtn = page.getByRole('button', { name: /defense_timeout/i });
    await timeoutBtn.click();

    // Verify typed error banner appears
    const alertBanner = page.locator('[role="alert"]');
    await expect(alertBanner).toBeVisible();
    await expect(alertBanner).toContainText(/ASSURANCE INTEGRITY ALERT/i);
    await expect(alertBanner).toContainText(/DEFENSE_DEADLINE_EXCEEDED/i);
    await expect(alertBanner).toContainText(/NO RETRY PERMITTED/i);

    // Reset failure mode to nominal
    const resetBtn = page.getByRole('button', { name: /Reset/i });
    await resetBtn.click();
    await expect(alertBanner).not.toBeVisible();
  });
});
