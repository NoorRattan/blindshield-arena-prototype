import { test, expect } from '@playwright/test';

test.describe('P13 Judge Demo Rehearsal E2E Walkthrough (DEMO.md)', () => {
  test.beforeEach(async ({ page }) => {
    // Reset to default operator role before starting rehearsal
    await page.addInitScript(() => {
      if (!sessionStorage.getItem('blindshield_rehearsal_initialized')) {
        localStorage.setItem('blindshield_role', 'operator');
        localStorage.setItem('blindshield_connection_mode', 'simulated');
        sessionStorage.setItem('blindshield_rehearsal_initialized', 'true');
      }
    });
  });

  test('walks through all 5 demo steps without dead steps or failures', async ({ page }) => {
    // =========================================================================
    // STEP 1: Arena Setup & Broker-Controlled Ingestion
    // =========================================================================
    await page.goto('/setup');
    // Assert the visible UI below rather than waiting for background traffic to stop.

    // 1.1 Verify PageHeader and Stepper are mounted
    const headline = page.locator('h1');
    await expect(headline).toContainText('EXPERIMENT SETUP & CANONICAL MANIFEST COMPOSER');
    await expect(page.getByRole('tab', { name: /1. Domain & Epoch/i })).toBeVisible();

    // 1.2 Navigate through steps to Step 5 (Disclosure Policy & Preflight)
    const step5Tab = page.getByRole('tab', { name: /5. Disclosure Policy/i });
    await step5Tab.click();
    await expect(page.locator('text=SEALED_BATCH (Default)')).toBeVisible();

    // 1.3 Verify Preflight Scanner status
    await expect(page.locator('text=INFRASTRUCTURE PREFLIGHT SCANNER')).toBeVisible();
    await expect(page.locator('text=PREFLIGHT CLEARED · 8 OF 8 REQUIRED CHECKS PASSED')).toBeVisible();

    // 1.4 Click Sign & Register with Witness
    const signBtn = page.getByRole('button', { name: /SIGN & REGISTER WITH WITNESS/i });
    await expect(signBtn).toBeEnabled();
    await signBtn.click();

    // 1.5 Verify Witness Checkpoint Receipt Card is displayed with signature
    await expect(page.locator('text=EXPERIMENT SEALED & ATTESTED')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Witness Receipt ID')).toBeVisible();

    // 1.6 Navigate to War Room
    await page.goto('/war-room?arena=exp_running_01');
    // Assert the visible UI below rather than waiting for background traffic to stop.

    // =========================================================================
    // STEP 2: Live War Room & Cross-Team Role Boundary
    // =========================================================================
    // 2.1 Verify 6-stage pipeline waterfall
    await expect(page.locator('text=PIPELINE EXECUTION WATERFALL')).toBeVisible();
    await expect(page.locator('text=01 / RED SUBMIT')).toBeVisible();
    await expect(page.locator('text=02 / BROKER INGEST')).toBeVisible();
    await expect(page.locator('text=03 / BLUE DEFENSE')).toBeVisible();
    await expect(page.locator('text=04 / TARGET MODEL')).toBeVisible();
    await expect(page.locator('text=05 / SCORER')).toBeVisible();
    await expect(page.locator('text=06 / RECORDER')).toBeVisible();

    // 2.2 Verify telemetry gauges
    await expect(page.locator('text=Broker Queue Depth')).toBeVisible();

    // 2.3 Switch Role to RED TEAM and inspect Red Portal
    const roleGroup = page.getByRole('group', { name: 'Role selector' });
    await roleGroup.getByRole('button', { name: 'Red Team' }).click();
    await page.goto('/red');
    // Assert the visible UI below rather than waiting for background traffic to stop.

    await expect(page.locator('h1')).toContainText('RED TEAM OPERATIONAL PORTAL');
    await expect(page.locator('text=PAYLOAD COMMITMENT WORKSHOP')).toBeVisible();
    await expect(page.locator('text=OUTCOME & FEEDBACK LOG')).toBeVisible();

    // 2.4 Switch Role to BLUE TEAM and inspect Blue Console
    await roleGroup.getByRole('button', { name: 'Blue Team' }).click();
    await page.goto('/blue');
    // Assert the visible UI below rather than waiting for background traffic to stop.

    await expect(page.locator('h1')).toContainText('BLUE TEAM DEFENSIVE CONSOLE');
    // Verify Sanitized Live Monitor is mounted and payload strings are withheld (Spec C-02)
    await expect(page.locator('text=02 — LIVE ROUND HEALTH MONITOR')).toBeVisible();
    await expect(page.getByText('STATIC EMBARGOED PROJECTION (EmbargoedView)', { exact: true })).toBeVisible();
    await expect(page.getByText('WITHHELD (C-02)', { exact: true })).toBeVisible();

    // =========================================================================
    // STEP 3: Failure Injection & Deterministic Invalidity
    // =========================================================================
    // 3.1 Switch back to Operator and go to War Room
    await roleGroup.getByRole('button', { name: 'Operator' }).click();
    await page.goto('/war-room?arena=exp_running_01');
    // Assert the visible UI below rather than waiting for background traffic to stop.

    // 3.2 Inject Defense Timeout fault
    const timeoutBtn = page.getByRole('button', { name: /defense_timeout/i });
    await expect(timeoutBtn).toBeVisible();
    await timeoutBtn.click();

    // 3.3 Verify round transitions to INVALID with dual verdict
    await expect(page.locator('text=DEFENSE_DEADLINE_EXCEEDED (1,002ms)')).toBeVisible();
    await expect(page.locator('text=TIMEOUT').first()).toBeVisible();

    // 3.4 Clear fault and restore round
    const resetBtn = page.getByRole('button', { name: /Reset/i });
    await resetBtn.click();
    await expect(page.locator('text=Deadline 1,000ms exceeded')).not.toBeVisible();

    // =========================================================================
    // STEP 4: Cryptographic Evidence Export & Offline Verification
    // =========================================================================
    await page.goto('/evidence');
    // Assert the visible UI below rather than waiting for background traffic to stop.

    // 4.1 Verify Evidence Inspector header & trust anchors
    const evidenceHeading = page.locator('h1');
    await expect(evidenceHeading).toContainText('EVIDENCE INSPECTOR & OFFLINE VERIFIER');

    // 4.2 Wait for Web Worker verification to complete (VALID_WITHIN_PROFILE)
    const verdictChip = page.getByTestId('overall-verdict-chip');
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE', { timeout: 15000 });

    // 4.3 Verify 3 separate verdicts: Authenticity, Completeness, Experimental Integrity
    const authenticityChip = page.getByTestId('verdict-authenticity');
    const completenessChip = page.getByTestId('verdict-completeness');
    const integrityChip = page.getByTestId('verdict-integrity');
    await expect(authenticityChip).toContainText('PASS');
    await expect(completenessChip).toContainText('PASS');
    await expect(integrityChip).toContainText('PASS');

    // 4.4 Test Invariant 6: Switch trust anchor to bundle key -> flags UNTRUSTED_KEY
    const bundleKeyRadio = page.getByRole('radio', { name: /Bundle Key/i });
    await bundleKeyRadio.click();
    await expect(verdictChip).toContainText('REJECTED (UNTRUSTED_KEY)');

    // Restore Pinned Key anchor
    const pinnedKeyRadio = page.getByRole('radio', { name: /Pinned Anchor/i });
    await pinnedKeyRadio.click();
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE');

    // =========================================================================
    // STEP 5: Tamper Playground & Benchmark Claim Discipline
    // =========================================================================
    // 5.1 Tamper Case A: Flip a byte in digest -> CHAIN_BROKEN
    const flipByteBtn = page.getByRole('button', { name: /FLIP A BYTE/i });
    await flipByteBtn.click();
    await expect(verdictChip).toContainText('REJECTED (CHAIN_BROKEN)');

    // Reset tamper
    await page.getByTestId('restore-untampered-btn').click();
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE');

    // 5.2 Tamper Case B: Boolean Epoch True -> INVALID_EPOCH_TYPE
    const booleanEpochBtn = page.getByRole('button', { name: /BOOLEAN EPOCH TRUE/i });
    await booleanEpochBtn.click();
    await expect(verdictChip).toContainText('REJECTED (INVALID_EPOCH_TYPE)');

    // Reset tamper
    await page.getByTestId('restore-untampered-btn').click();
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE');

    // 5.3 Tamper Case C: Truncate Terminal Event -> Rejection
    const truncateBtn = page.getByRole('button', { name: /TRUNCATE CHAIN/i });
    await truncateBtn.click();
    await expect(verdictChip).toContainText('REJECTED');

    // Restore Authentic Bundle
    await page.getByTestId('restore-untampered-btn').click();
    await expect(verdictChip).toContainText('VALID_WITHIN_PROFILE');

    // 5.4 Navigate to Benchmarks and verify claim discipline
    await page.goto('/benchmarks');
    // Assert the visible UI below rather than waiting for background traffic to stop.

    await expect(page.locator('h1')).toContainText('BENCHMARK ANALYTICS & CHANNEL CAPACITY');
    // Verify Attack Success Rate panel with 95% CI is present
    await expect(page.locator('text=01 — ATTACK SUCCESS RATE')).toBeVisible();
    await expect(page.locator('text=95% CI').first()).toBeVisible();
    // Verify Cache Distinguishability ROC AUC is present
    await expect(page.locator('text=03 — CACHE DISTINGUISHABILITY · ROC AUC').first()).toBeVisible();
    // Verify Covert Channel bound card carries NOT MEASURED status
    await expect(page.locator('text=04 — COVERT-CHANNEL CAPACITY BOUND')).toBeVisible();
    await expect(page.locator('text=NOT MEASURED').first()).toBeVisible();
    // Verify ResidualRiskPanel is rendered
    await expect(page.getByRole('region', { name: /Committed Threat Scope/i })).toBeVisible();
  });
});
