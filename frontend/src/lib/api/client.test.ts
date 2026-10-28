import { describe, it, expect, beforeEach, vi } from 'vitest';
import { MockArenaClient } from './client';
import { useArenaStore } from '../../state/useArenaStore';
import type { Epoch, SubmitAttackRequest } from '../schemas';
import { sha256Digest } from '../crypto';

describe('ArenaClient & Mock Implementation', () => {
  let client: MockArenaClient;

  beforeEach(() => {
    useArenaStore.setState({
      role: 'operator',
      epoch: 4,
      domain: 'BAYORA-PROD-01',
      failureMode: 'none',
    });
    client = new MockArenaClient();
  });

  it('fetches experiments list with role-filtered status', async () => {
    const list = await client.getExperiments('operator');
    expect(list.length).toBeGreaterThanOrEqual(3);
    const running = list.find((e) => e.experiment_id === 'exp_running_01');
    expect(running).toBeDefined();
    expect(running?.delayed).toBe(false);

    // Red view is delayed
    const redList = await client.getExperiments('red');
    const redRunning = redList.find((e) => e.experiment_id === 'exp_running_01');
    expect(redRunning?.delayed).toBe(true);
    expect(redRunning?.delay_label).toBe('DELAYED T-30s');
  });

  it('submits attack and returns attack receipt', async () => {
    const req: SubmitAttackRequest = {
      text_artifact: 'Probing model boundaries',
      commitment: sha256Digest('attack_token'),
      nonce: 'nonce_999',
    };

    const receipt = await client.submitAttack('exp_running_01', req, 'idemp-k1', 4 as Epoch, 'red');
    expect(receipt.receipt_id).toMatch(/^rcpt_atk_/);
    expect(receipt.turn).toBeGreaterThan(0);
    expect(receipt.commitment_digest).toBe(req.commitment);
  });

  it('creates, starts, and closes an experiment with full signed checkpoint', async () => {
    // 1. Create
    const created = await client.createExperiment(
      { domain: 'BAYORA-NEW-TEST', profile: 'SEALED_BATCH' },
      'create-k1',
      'operator'
    );
    expect(created.state).toBe('SEALED');

    // 2. Start
    const started = await client.startExperiment(created.experiment_id, 'operator');
    expect(started.state).toBe('RUNNING');
    expect(started.durable_start_receipt).toMatch(/^rcpt_start_/);

    // 3. Close
    const closed = await client.closeExperiment(created.experiment_id, 'operator');
    expect(closed.state).toBe('CLOSED');
    expect(closed.checkpoint.terminal).toBe(true);
    expect(closed.checkpoint.signature).toBeDefined();
  });

  it('downloads complete evidence bundle for auditor', async () => {
    const bundle = await client.getEvidenceBundle('exp_released_04', 'auditor');
    expect(bundle.metadata).toBeDefined();
    expect(bundle.metadata.state).toBe('RELEASED');
    expect(bundle.checkpoint.terminal).toBe(true);
    expect(bundle.ledger.length).toBeGreaterThan(0);
  });
});

describe('SSE Simulator & Failure Injection Matrix', () => {
  let client: MockArenaClient;

  beforeEach(() => {
    client = new MockArenaClient();
    vi.useFakeTimers();
  });

  it('streams events to subscriber with jitter', () => {
    const onEvent = vi.fn();
    const onStatus = vi.fn();

    const unsubscribe = client.subscribeEvents(
      'exp_running_01',
      onEvent,
      undefined,
      onStatus,
      'operator'
    );

    expect(onStatus).toHaveBeenCalledWith('CONNECTED');

    // Advance time past initial tick
    vi.advanceTimersByTime(250);
    expect(onEvent).toHaveBeenCalled();

    unsubscribe();
    expect(onStatus).toHaveBeenCalledWith('CLOSED');
  });

  it('injects recorder_down failure mode and reports AUDIT_UNAVAILABLE', () => {
    client.setFailureMode('recorder_down');
    const onEvent = vi.fn();
    const onError = vi.fn();
    const onStatus = vi.fn();

    client.subscribeEvents('exp_running_01', onEvent, onError, onStatus, 'operator');

    expect(onError).toHaveBeenCalled();
    const err = onError.mock.calls[0][0];
    expect(err.message).toContain('AUDIT_UNAVAILABLE');
    expect(onStatus).toHaveBeenCalledWith('CLOSED');
  });

  it('injects witness_lag failure mode and reports LAGGING status', () => {
    client.setFailureMode('witness_lag');
    const onStatus = vi.fn();

    client.subscribeEvents('exp_running_01', () => {}, undefined, onStatus, 'operator');
    expect(onStatus).toHaveBeenCalledWith('LAGGING');
  });

  it('injects reconnect failure mode', () => {
    client.setFailureMode('reconnect');
    const onEvent = vi.fn();
    const onError = vi.fn();
    const onStatus = vi.fn();

    client.subscribeEvents('exp_running_01', onEvent, onError, onStatus, 'operator');

    // First tick
    vi.advanceTimersByTime(250);
    expect(onEvent).toHaveBeenCalledTimes(1);

    // Second tick triggers reconnect
    vi.advanceTimersByTime(2500);
    expect(onStatus).toHaveBeenCalledWith('RECONNECTING');

    // After reconnect delay, restores connection
    vi.advanceTimersByTime(1000);
    expect(onStatus).toHaveBeenCalledWith('CONNECTED');
  });
});
