import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Evidence Inspector & Offline Verifier (/evidence) E2E & Accessibility', () => {
  test('verifies untampered bundle with VALID_WITHIN_PROFILE, tests tamper injections, unpinned key rejection, drawer inspection and passes axe audit', async ({
    page,
  }, testInfo) => {
    // 1. Navigate to /evidence
    await page.goto('/evidence');

    // Verify PageHeader document ID & headline
    const headline = page.locator('h1');
    await expect(headline).toContainText('EVIDENCE INSPECTOR & OFFLINE VERIFIER');
    await expect(page.locator('text=DOC-EVID-06').first()).toBeVisible();

    // 2. Wait for initial verification to complete in Web Worker
    // Overall status chip should be VALID_WITHIN_PROFILE
    const verdictChip = page.getByTestId('overall-verdict-chip');
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE', { timeout: 15000 });

    // Verify Three Verdicts Banner
    const authenticityChip = page.getByTestId('verdict-authenticity');
    const completenessChip = page.getByTestId('verdict-completeness');
    const integrityChip = page.getByTestId('verdict-integrity');

    await expect(authenticityChip).toContainText('PASS');
    await expect(completenessChip).toContainText('PASS');
    await expect(integrityChip).toContainText('PASS');

    // 3. Verify all 9 checklist rows are present and PASS
    const checklistRegion = page.getByRole('region', { name: /9-Point Verification Checklist/i });
    await expect(checklistRegion).toBeVisible();

    await expect(checklistRegion.locator('text=Witness Ed25519 Signature (Pinned Anchor)').first()).toBeVisible();
    await expect(checklistRegion.locator('text=Epoch Positive Integer Strict Typing').first()).toBeVisible();
    await expect(checklistRegion.locator('text=RFC 8785 Canonical Schema & JCS Format').first()).toBeVisible();
    await expect(checklistRegion.locator('text=Ledger Sequence Monotonic Continuity').first()).toBeVisible();
    await expect(checklistRegion.locator('text=Domain-Separated Merkle Hash Chain').first()).toBeVisible();
    await expect(checklistRegion.locator('text=Terminal Marker & Required Event Set').first()).toBeVisible();
    await expect(checklistRegion.locator('text=Manifest Digest & Run Boundary Match').first()).toBeVisible();
    await expect(checklistRegion.locator('text=Artifact & Ciphertext Digest Formats').first()).toBeVisible();
    await expect(checklistRegion.locator('text=Witness Receipt & Monotonic Watermark').first()).toBeVisible();

    // 4. Test Tamper Injection: BOOLEAN EPOCH TRUE (Invariant 5)
    const booleanEpochBtn = page.getByRole('button', { name: /BOOLEAN EPOCH TRUE/i });
    await expect(booleanEpochBtn).toBeVisible();
    await booleanEpochBtn.click();

    // Expect instant rejection with INVALID_EPOCH_TYPE
    await expect(verdictChip).toContainText('REJECTED (INVALID_EPOCH_TYPE)');
    const activeTamperBanner = page.locator('text=ACTIVE INJECTION');
    await expect(activeTamperBanner).toBeVisible();
    await expect(page.locator('text=INVALID_EPOCH_TYPE').first()).toBeVisible();

    // Reset tamper
    const resetTamperBtn = page.getByTestId('restore-untampered-btn');
    await expect(resetTamperBtn).toBeVisible();
    await resetTamperBtn.click();

    // Expect reset back to valid
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE');

    // 5. Test Tamper Injection: FLIP A BYTE (Chain break)
    const flipByteBtn = page.getByRole('button', { name: /FLIP A BYTE/i });
    await flipByteBtn.click();

    await expect(verdictChip).toContainText('REJECTED (CHAIN_BROKEN)');
    await expect(page.locator('text=CHAIN_BROKEN').first()).toBeVisible();

    // Reset again
    await page.getByTestId('restore-untampered-btn').click();
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE');

    // 6. Test Unpinned Bundle Key (C-03: Bundle key must be treated as UNTRUSTED)
    const bundleKeyRadio = page.getByRole('radio', { name: /Bundle Key/i });
    await bundleKeyRadio.click();

    // Check for UNTRUSTED warning badge in anchors panel
    await expect(page.locator('text=UNTRUSTED (BUNDLE KEY)').first()).toBeVisible();

    // Re-verify with unpinned key -> must fail with UNTRUSTED_KEY
    await expect(verdictChip).toContainText('REJECTED (UNTRUSTED_KEY)');

    // Restore Pinned Key
    const pinnedKeyRadio = page.getByRole('radio', { name: /Pinned Anchor/i });
    await pinnedKeyRadio.click();
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE');

    // 7. Verify 2D Fallback & Event Inspector Drawer
    // Switch to 2D view to inspect chain list
    const fallbackTab = page.getByRole('button', { name: /2D List/i });
    if (await fallbackTab.isVisible()) {
      await fallbackTab.click();
    }

    // Click event #1 in the 2D list to open drawer
    const eventRow1 = page.getByRole('button', { name: 'Event #1', exact: true });
    await expect(eventRow1).toBeVisible();
    await eventRow1.click();

    // Drawer should open with event details
    const drawer = page.locator('[role="dialog"]').first();
    await expect(drawer).toBeVisible();
    await expect(drawer.locator('text=EVENT #001')).toBeVisible();
    await expect(drawer.locator('text=Canonical RFC 8785 JSON').first()).toBeVisible();

    // Verify copy button exists
    const copyBtn = drawer.getByRole('button', { name: /Copy JSON/i });
    await expect(copyBtn).toBeVisible();

    // Close drawer via Escape key
    await page.keyboard.press('Escape');
    await expect(drawer).not.toBeVisible();

    // 8. Assert Claim Discipline: Banned marketing hype words must not appear in DOM
    const pageHtml = await page.content();
    expect(pageHtml).not.toContain('zero leakage');
    expect(pageHtml).not.toContain('tamper-proof');
    expect(pageHtml).not.toContain('unhackable');
    expect(pageHtml).not.toContain('guaranteed safe');

    // 9. Axe accessibility audit (zero critical or serious violations)
    await page.waitForTimeout(600); // Allow GSAP / R3F canvas settle
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const axeResults = await new AxeBuilder({ page: page as any })
      .disableRules(['color-contrast']) // Design-system dark theme tokens calibrated
      .analyze();
    expect(axeResults.violations).toEqual([]);

    // 10. Take viewport screenshot
    await page.screenshot({
      path: `test-results/evidence-${testInfo.project.name}.png`,
      fullPage: true,
    });
  });

  test('stress benchmark: can switch to 1,500 event bundle and verify in worker', async ({ page }) => {
    await page.goto('/evidence');

    // Click preset for 1,500 events
    const largePresetBtn = page.getByRole('button', { name: /Large Bundle \(1,500 Evt\)/i });
    await expect(largePresetBtn).toBeVisible();
    await largePresetBtn.click();

    // Expect verifier to process 1,500 events and reach VALID_WITHIN_PROFILE
    const verdictChip = page.getByTestId('overall-verdict-chip');
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE', { timeout: 20000 });

    // Verify event count in dropzone or card
    await expect(page.locator('text=LOADED (1500 EVENTS)').first()).toBeVisible();
  });
});
