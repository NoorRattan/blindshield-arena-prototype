import { test, expect } from '@playwright/test';

const CANARY_TOKENS = [
  'CANARY_RED_PROMPT_SECRET_TOKEN_98765',
  'CANARY_BLUE_DEFENSE_RULESET_INTERNAL_43210',
  'CANARY_TARGET_RAW_INTERNAL_PROMPT_11223',
  'CANARY_EMBARGOED_PREFIX_SALT_99887',
];

test.describe('P12-S2 Leak Canaries & Untrusted Text Invariance', () => {
  test('asserts complete absence of embargoed canaries from DOM, storage, and console for non-operator roles', async ({
    page,
  }) => {
    const consoleLogs: string[] = [];
    page.on('console', (msg) => {
      consoleLogs.push(msg.text());
    });

    const routes = ['/', '/overview', '/war-room', '/evidence', '/benchmarks'];
    const roles: ('Red Team' | 'Blue Team' | 'Auditor')[] = ['Red Team', 'Blue Team', 'Auditor'];

    for (const role of roles) {
      await page.goto('/');
      const roleBtn = page.getByRole('button', { name: role });
      await roleBtn.click();
      await expect(roleBtn).toHaveAttribute('aria-pressed', 'true');

      for (const route of routes) {
        await page.goto(route);
        await page.waitForLoadState('networkidle');

        // 1. Assert absence from DOM text and attributes
        const bodyContent = await page.evaluate(() => document.body.outerHTML);
        for (const token of CANARY_TOKENS) {
          expect(
            bodyContent.includes(token),
            `Embargoed canary ${token} leaked in DOM outerHTML on ${route} under ${role}`
          ).toBe(false);
        }

        // 2. Assert absence from localStorage and sessionStorage
        const storageDump = await page.evaluate(() => {
          return JSON.stringify({
            local: { ...localStorage },
            session: { ...sessionStorage },
          });
        });
        for (const token of CANARY_TOKENS) {
          expect(
            storageDump.includes(token),
            `Embargoed canary ${token} leaked in browser storage on ${route} under ${role}`
          ).toBe(false);
        }
      }
    }

    // 3. Assert absence from console output across all navigation
    const allConsole = consoleLogs.join(' ');
    for (const token of CANARY_TOKENS) {
      expect(
        allConsole.includes(token),
        `Embargoed canary ${token} leaked into browser console output`
      ).toBe(false);
    }
  });

  test('asserts hostile payloads and script tags are inertly rendered via UntrustedText', async ({
    page,
  }) => {
    // Visit component kit showcase where hostile attack payloads are rendered through UntrustedText
    await page.goto('/__kit');
    await page.waitForLoadState('networkidle');

    // 1. Verify hostile XSS string exists as plain text only
    const untrustedSink = page.locator('text=<script>alert("pwned")</script>');
    await expect(untrustedSink).toBeVisible();

    // 2. Verify NO executable <script> tags or execution occurred
    const executed = await page.evaluate(() => (window as unknown as { __pwned?: boolean }).__pwned);
    expect(executed).toBeUndefined();

    // 3. Ensure no unescaped script elements were appended to the body
    const dangerousScripts = await page.locator('body script:not([src])').count();
    expect(dangerousScripts).toBe(0);
  });
});
