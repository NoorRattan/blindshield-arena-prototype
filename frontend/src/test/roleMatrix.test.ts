import { describe, it, expect, beforeEach } from 'vitest';
import { MockArenaServer } from '../lib/mock/server';
import { CANARY_TOKENS } from '../lib/mock/fixtures';
import type { Role } from '../lib/schemas';

describe('P12-S1 Server-Layer Role Matrix & DTO Scoping', () => {
  let server: MockArenaServer;

  beforeEach(() => {
    server = new MockArenaServer();
  });

  describe('Preflight Execution Authorization', () => {
    it('permits operator and auditor roles to execute preflight', () => {
      const opReport = server.runPreflight('operator');
      expect(opReport.overall_status).toBe('PASS');
      expect(opReport.checks.length).toBeGreaterThan(0);

      const auditorReport = server.runPreflight('auditor');
      expect(auditorReport.overall_status).toBe('PASS');
    });

    it('denies red and blue roles from running preflight with UNAUTHORIZED', () => {
      expect(() => server.runPreflight('red')).toThrowError(/not permitted to execute preflight verification/i);
      expect(() => server.runPreflight('blue')).toThrowError(/not permitted to execute preflight verification/i);
    });
  });

  describe('Feedback DTO Role Scoping & Invariants', () => {
    const runningId = 'exp_running_01';
    const sealedId = 'exp_sealed_02';
    const releasedId = 'exp_released_04';

    it('operator receives complete telemetry, unbucketed latency, and visible disclosures', () => {
      const feedback = server.getFeedback(runningId, 'operator');
      expect(feedback.length).toBeGreaterThan(0);

      for (const item of feedback) {
        expect(item.latency_ms).toBeDefined();
        expect(item.latency_ms?.total).toBeGreaterThan(0);
        expect(item.model_execution).toBeDefined();
        expect(item.integrity).toBe('VALID_WITHIN_PROFILE');
        expect(item.disclosure.visible).toBe(true);
      }
    });

    it('red receives coarse 50ms latency buckets in CONTROLLED_FEEDBACK and NO exact latency_ms', () => {
      const feedback = server.getFeedback(runningId, 'red');
      expect(feedback.length).toBeGreaterThan(0);

      for (const item of feedback) {
        expect(item.latency_bucket_ms).toBeDefined();
        expect(item.latency_bucket_ms! % 50).toBe(0); // 50ms bucketed
        expect(item.latency_ms).toBeUndefined(); // Exact latency withheld
      }
    });

    it('red receives EMBARGOED feedback in SEALED_BATCH before release (C-07)', () => {
      const feedback = server.getFeedback(sealedId, 'red');
      // If any attempts exist or are queried
      for (const item of feedback) {
        expect(item.disclosure.visible).toBe(false);
        expect(item.disclosure.reason).toBe('EMBARGOED');
      }
    });

    it('blue receives NO allow/block split or model execution during ACTIVE round (C-02 / FE-D-003)', () => {
      const feedback = server.getFeedback(runningId, 'blue');
      expect(feedback.length).toBeGreaterThan(0);

      for (const item of feedback) {
        expect(item.model_execution).toBeUndefined();
        expect(item.defense_status).toBeUndefined();
        expect(item.disclosure.visible).toBe(false);
        expect(item.disclosure.reason).toBe('EMBARGOED');
      }
    });

    it('blue receives post-close evaluation telemetry once released', () => {
      const feedback = server.getFeedback(releasedId, 'blue');
      expect(feedback.length).toBeGreaterThan(0);

      for (const item of feedback) {
        expect(item.model_execution).toBeDefined();
        expect(item.defense_status).toBeDefined();
      }
    });
  });

  describe('Forensic Workshop Authorization & Phase Gating (FE-D-027)', () => {
    it('denies forensic payloads during active RUNNING round with WRONG_PHASE', () => {
      expect(() => server.getForensics('exp_running_01', 'blue')).toThrowError(
        /withheld until the epoch is cryptographically RELEASED/i
      );
      expect(() => server.getForensics('exp_running_01', 'operator')).toThrowError(
        /withheld until the epoch is cryptographically RELEASED/i
      );
    });

    it('denies red role from requesting forensic payloads even after release', () => {
      expect(() => server.getForensics('exp_released_04', 'red')).toThrowError(/Red role is prohibited/i);
    });

    it('allows blue, operator, and auditor to access forensic payloads on RELEASED experiment', () => {
      const blueForensics = server.getForensics('exp_released_04', 'blue');
      expect(blueForensics.experiment_id).toBe('exp_released_04');
      expect(blueForensics.state).toBe('RELEASED');
      expect(blueForensics.turns.length).toBeGreaterThan(0);

      const opForensics = server.getForensics('exp_released_04', 'operator');
      expect(opForensics.turns.length).toBe(blueForensics.turns.length);

      const auditorForensics = server.getForensics('exp_released_04', 'auditor');
      expect(auditorForensics.turns.length).toBe(blueForensics.turns.length);
    });
  });

  describe('Zero Canary Leakage in Server Responses across Non-Operator Roles (S2)', () => {
    const roles: Role[] = ['red', 'blue', 'auditor'];
    const canaries = Object.values(CANARY_TOKENS);

    for (const role of roles) {
      it(`guarantees zero canary leakage in DTOs for ${role}`, () => {
        const status = server.getExperimentStatus('exp_running_01', role);
        const statusStr = JSON.stringify(status);
        for (const token of canaries) {
          expect(statusStr).not.toContain(token);
        }

        const feedback = server.getFeedback('exp_running_01', role);
        const feedbackStr = JSON.stringify(feedback);
        for (const token of canaries) {
          expect(feedbackStr).not.toContain(token);
        }

        if (role === 'auditor') {
          const manifest = server.getManifest('exp_running_01', role);
          const manifestStr = JSON.stringify(manifest);
          for (const token of canaries) {
            expect(manifestStr).not.toContain(token);
          }
        } else {
          expect(() => server.getManifest('exp_running_01', role)).toThrowError(
            /not permitted to inspect raw experiment manifests/i
          );
        }
      });
    }
  });
});
