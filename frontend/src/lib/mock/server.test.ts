import { describe, it, expect, beforeEach } from 'vitest';
import { MockArenaServer } from './server';
import { CANARY_TOKENS } from './fixtures';
import type { Epoch, SubmitAttackRequest } from '../schemas';
import { sha256Digest } from '../crypto';

describe('MockArenaServer: Role filtering, Embargo & Information Flow', () => {
  let server: MockArenaServer;

  beforeEach(() => {
    server = new MockArenaServer();
  });

  it('never leaks internal canary tokens to red, blue, or auditor responses', () => {
    const roles = ['red', 'blue', 'auditor'] as const;
    const canaries = Object.values(CANARY_TOKENS);

    for (const role of roles) {
      const experiments = server.getExperiments(role);
      const experimentsStr = JSON.stringify(experiments);

      for (const canary of canaries) {
        expect(experimentsStr).not.toContain(canary);
      }

      // Check feedback across all arenas
      for (const exp of experiments) {
        const feedback = server.getFeedback(exp.experiment_id, role);
        const feedbackStr = JSON.stringify(feedback);
        for (const canary of canaries) {
          expect(feedbackStr).not.toContain(canary);
        }
      }
    }
  });

  it('asserts field absence (not emptiness) for Red in SEALED_BATCH before release', () => {
    // In server, if profile is SEALED_BATCH and not released, model_execution is absent:
    const arena = server.getRawArena('exp_running_01')!;
    arena.profile = 'SEALED_BATCH'; // Temporarily simulate SEALED_BATCH while running

    const redFeedback = server.getFeedback('exp_running_01', 'red');
    expect(redFeedback.length).toBeGreaterThan(0);

    const firstItem = redFeedback[0];
    expect(firstItem.disclosure.reason).toBe('EMBARGOED');
    expect(firstItem.disclosure.visible).toBe(false);

    // CRITICAL: Assert absence of fields, not empty strings!
    expect('model_execution' in firstItem).toBe(false);
    expect('scoring' in firstItem).toBe(false);
    expect('latency_ms' in firstItem).toBe(false);
  });

  it('withholds allow/block split from Blue during ACTIVE round (Spec correction C-02)', () => {
    const blueFeedback = server.getFeedback('exp_running_01', 'blue');
    expect(blueFeedback.length).toBeGreaterThan(0);

    for (const item of blueFeedback) {
      expect(item.disclosure.reason).toBe('EMBARGOED');
      // Assert absence of allow/block split fields
      expect('model_execution' in item).toBe(false);
      expect('defense_status' in item).toBe(false);
      // Coarse latency bucket is present
      expect(item.latency_bucket_ms).toBeDefined();
      expect(item.latency_bucket_ms! % 50).toBe(0);
    }
  });

  it('provides full telemetry to Operator without delay or masking', () => {
    const opFeedback = server.getFeedback('exp_running_01', 'operator');
    expect(opFeedback.length).toBeGreaterThan(0);

    const firstItem = opFeedback[0];
    expect(firstItem.model_execution).toBeDefined();
    expect(firstItem.defense_status).toBeDefined();
    expect(firstItem.latency_ms).toBeDefined();
    expect(firstItem.disclosure.visible).toBe(true);
  });

  it('tags non-operator telemetry as DELAYED T-30s with coarse 50ms buckets', () => {
    const redStatus = server.getExperimentStatus('exp_running_01', 'red');
    expect(redStatus.delayed).toBe(true);
    expect(redStatus.delay_label).toBe('DELAYED T-30s');

    const opStatus = server.getExperimentStatus('exp_running_01', 'operator');
    expect(opStatus.delayed).toBe(false);
    expect(opStatus.delay_label).toBeUndefined();
  });
});

describe('MockArenaServer: Idempotency & Conflict detection', () => {
  let server: MockArenaServer;

  beforeEach(() => {
    server = new MockArenaServer();
  });

  const attackPayloadA: SubmitAttackRequest = {
    text_artifact: 'System prompt extraction payload A',
    commitment: sha256Digest('attack_a'),
    nonce: 'nonce_001',
  };

  const attackPayloadB: SubmitAttackRequest = {
    text_artifact: 'Different payload B',
    commitment: sha256Digest('attack_b'),
    nonce: 'nonce_002',
  };

  it('returns identical receipt on replay with same key and same body', () => {
    const idempotencyKey = 'client-req-uuid-12345';
    const r1 = server.submitAttack(
      'exp_running_01',
      attackPayloadA,
      idempotencyKey,
      'red',
      4 as Epoch
    );

    const r2 = server.submitAttack(
      'exp_running_01',
      attackPayloadA,
      idempotencyKey,
      'red',
      4 as Epoch
    );

    expect(r1).toEqual(r2);
  });

  it('throws 409 CONFLICT on replay with same key and different body', () => {
    const idempotencyKey = 'client-req-uuid-12345';
    server.submitAttack(
      'exp_running_01',
      attackPayloadA,
      idempotencyKey,
      'red',
      4 as Epoch
    );

    expect(() =>
      server.submitAttack(
        'exp_running_01',
        attackPayloadB,
        idempotencyKey,
        'red',
        4 as Epoch
      )
    ).toThrow(/Idempotency key collision/);
  });
});

describe('MockArenaServer: Phase Gating & Stale Epoch', () => {
  let server: MockArenaServer;

  beforeEach(() => {
    server = new MockArenaServer();
  });

  const attackPayload: SubmitAttackRequest = {
    text_artifact: 'Payload',
    commitment: sha256Digest('payload'),
    nonce: 'n1',
  };

  it('rejects stale epoch < active arena epoch', () => {
    // exp_running_01 is on epoch 4
    expect(() =>
      server.submitAttack(
        'exp_running_01',
        attackPayload,
        'key-1',
        'red',
        3 as Epoch // Stale epoch 3 < 4
      )
    ).toThrow(/Rejected stale epoch/);
  });

  it('rejects attack submission in non-RUNNING phase', () => {
    // exp_sealed_02 is SEALED
    expect(() =>
      server.submitAttack(
        'exp_sealed_02',
        attackPayload,
        'key-2',
        'red',
        1 as Epoch
      )
    ).toThrow(/Cannot submit attack in phase SEALED/);
  });

  it('rejects starting an already RUNNING or CLOSED experiment', () => {
    expect(() => server.startExperiment('exp_running_01', 'operator')).toThrow(
      /must be SEALED or READY/
    );
  });
});

describe('MockArenaServer: War Room Interventions & Failure Injection Outcomes', () => {
  let server: MockArenaServer;

  beforeEach(() => {
    server = new MockArenaServer();
  });

  it('quarantine transitions lifecycle to INVALID with reason and records audit event', () => {
    const res = server.quarantineExperiment('exp_running_01', 'DEFENSE_BREACH_SUSPECTED', 'operator');
    expect(res.state).toBe('INVALID');
    expect(res.reason).toBe('DEFENSE_BREACH_SUSPECTED');

    const status = server.getExperimentStatus('exp_running_01', 'operator');
    expect(status.state).toBe('INVALID');
    expect(status.integrity_status).toBe('INVALID');
    expect(status.invalid_reason).toBe('DEFENSE_BREACH_SUSPECTED');

    const arena = server.getRawArena('exp_running_01')!;
    const lastEvent = arena.ledger[arena.ledger.length - 1];
    expect(lastEvent.action).toBe('domain_quarantined');
    expect(lastEvent.outcome).toBe('INVALID');
    expect(lastEvent.actor).toBe('operator');
  });

  it('rejects quarantine by non-operator roles', () => {
    expect(() => server.quarantineExperiment('exp_running_01', 'UNAUTHORIZED_ATTEMPT', 'red')).toThrow(
      /authorized/i
    );
    expect(() => server.quarantineExperiment('exp_running_01', 'UNAUTHORIZED_ATTEMPT', 'blue')).toThrow(
      /authorized/i
    );
  });

  it('triggers on-demand re-witness checkpoint and records audit event', () => {
    const res = server.triggerReWitness('exp_running_01', 'operator');
    expect(res.witness_status).toBe('SYNCED');
    expect(res.witness_receipt).toMatch(/^rcpt_rewitness_/);

    const arena = server.getRawArena('exp_running_01')!;
    const lastEvent = arena.ledger[arena.ledger.length - 1];
    expect(lastEvent.action).toBe('checkpoint_witnessed');
    expect(lastEvent.actor).toBe('witness');
    expect(lastEvent.outcome).toBe('SYNCED');
  });

  it('defense_timeout produces INVALID integrity, NOT_EVALUATED target, and >1000ms latency', () => {
    server.setFailureMode('defense_timeout');
    const status = server.getExperimentStatus('exp_running_01', 'operator');
    expect(status.integrity_status).toBe('INVALID');
    expect(status.invalid_reason).toBe('DEADLINE_EXCEEDED');

    const feedback = server.getFeedback('exp_running_01', 'operator');
    const timeoutAttempt = feedback[feedback.length - 1];
    expect(timeoutAttempt.model_execution).toBe('NOT_EVALUATED');
    expect(timeoutAttempt.integrity).toBe('INVALID');
    expect(timeoutAttempt.latency_ms?.defense).toBeGreaterThan(1000);
  });

  it('recorder_down causes new rounds to be rejected and marks status INVALID with AUDIT_UNAVAILABLE', () => {
    server.setFailureMode('recorder_down');
    const status = server.getExperimentStatus('exp_running_01', 'operator');
    expect(status.integrity_status).toBe('INVALID');
    expect(status.invalid_reason).toBe('AUDIT_UNAVAILABLE');

    expect(() =>
      server.createExperiment(
        { domain: 'NEW-DOMAIN', epoch: 1 as Epoch, profile: 'SEALED_BATCH' },
        'operator'
      )
    ).toThrow(/temporarily unavailable/i);

    try {
      server.createExperiment(
        { domain: 'NEW-DOMAIN', epoch: 1 as Epoch, profile: 'SEALED_BATCH' },
        'operator'
      );
    } catch (err: unknown) {
      expect((err as { apiError: { code: string } }).apiError.code).toBe('AUDIT_UNAVAILABLE');
    }
  });

  it('witness_lag turns witness status to LAGGING', () => {
    server.setFailureMode('witness_lag');
    const status = server.getExperimentStatus('exp_running_01', 'operator');
    expect(status.witness_status).toBe('LAGGING');

    const rewitnessRes = server.triggerReWitness('exp_running_01', 'operator');
    expect(rewitnessRes.witness_status).toBe('LAGGING');
  });
});

