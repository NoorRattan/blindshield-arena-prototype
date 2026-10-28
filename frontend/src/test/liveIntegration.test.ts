import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { LiveArenaClient, safeParseNoDuplicates } from '../lib/api/liveClient';
import { DynamicArenaClient, generateCanonicalClientKey } from '../lib/api/client';
import { useArenaStore } from '../state/useArenaStore';

/**
 * ARCHITECTURAL CONTEXT & TEST BOUNDARY FOR TASK 6:
 *
 * In production/local execution, the BlindShield Arena backend broker binds to 127.0.0.1
 * with mandatory mutual TLS (see backend/src/arena/broker/server.py: tls_context, dispatch).
 * Standard web browsers cannot initiate raw mTLS handshakes from clientside JS without
 * either a local HTTPS reverse proxy or platform-provisioned client certs.
 * Browser requests use role-scoped local proxy paths; the proxy presents the backend's
 * role-bound certificate and the backend authenticates every request from that certificate.
 *
 * This integration suite therefore tests LiveArenaClient's full protocol fidelity, wire serialization,
 * role-scoped mTLS proxy routing, fail-closed state machines, idempotency keys, duplicate-key detection,
 * and lifecycle transitions against a backend-compliant mock transport.
 */

describe('LiveArenaClient & Lifecycle Integration Test Suite (Task 2, 3, 4, 6)', () => {
  let client: LiveArenaClient;
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    useArenaStore.setState({
      connectionMode: 'live',
      liveBackendStatus: 'CONNECTED',
      epoch: 1,
      role: 'operator',
      authenticatedPrincipal: null,
    });
    client = new LiveArenaClient();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // ─── Task 2 & 3: Idempotency & mTLS role routing ─────────────────────────────

  it('generates canonical ASCII idempotency keys matching ^[!-~]{1,128}$', () => {
    for (let i = 0; i < 20; i++) {
      const key = generateCanonicalClientKey('submit-turn');
      expect(key).toMatch(/^[!-~]{1,128}$/);
      expect(key.length).toBeGreaterThan(10);
      expect(key.length).toBeLessThanOrEqual(128);
      // Non-whitespace ASCII
      expect(/\s/.test(key)).toBe(false);
    }
  });

  it('routes the registered create request through the operator certificate without identity headers', async () => {
    let capturedUrl = '';
    let capturedHeaders: Record<string, string> = {};
    let capturedBody = '';

    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      capturedUrl = url;
      capturedHeaders = (init?.headers as Record<string, string>) || {};
      capturedBody = init?.body as string;
      return {
        ok: true,
        status: 201,
        text: async () => JSON.stringify({
          domain_id: '11111111-1111-4111-8111-111111111111',
          experiment_id: '22222222-2222-4222-8222-222222222222',
          epoch: 1,
          phase: 'CREATED',
        }),
      } as Response;
    });

    const request = {
      profile_id: 'registered-profile',
      model_version_id: 'registered-model',
      defense_version_id: 'registered-defense',
      rubric_version_id: 'registered-rubric',
      disclosure_profile_id: 'SEALED_BATCH',
      interaction_mode: 'INTERACTIVE',
      defense_mode: 'INPUT',
      dataset_catalog_id: 'registered-dataset',
      strategy_version_id: 'registered-strategy',
      budget_profile_id: 'registered-budget',
    };
    const created = await client.createConfiguredExperiment(request, 'create-test-key', 'operator');
    expect(capturedUrl).toBe('/v1/operator/experiments');
    expect(capturedHeaders['Idempotency-Key']).toBe('create-test-key');
    expect(capturedHeaders['Content-Type']).toBe('application/json');
    expect(capturedHeaders['x-arena-role']).toBeUndefined();
    expect(capturedHeaders['x-client-cert-sha256']).toBeUndefined();
    expect(JSON.parse(capturedBody)).toEqual(request);
    expect(created.phase).toBe('CREATED');
  });

  // ─── Task 3: Lifecycle Methods ────────────────────────────────────────────────

  it('handles backend 202 async startExperiment and polls operation endpoint until DONE', async () => {
    let callCount = 0;

    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.includes('/start') && init?.method === 'POST') {
        return {
          ok: true,
          status: 202,
          text: async () => JSON.stringify({
            operation_id: 'op_start_999',
            status: 'PENDING',
          }),
          json: async () => ({
            operation_id: 'op_start_999',
            status: 'PENDING',
          }),
        } as Response;
      }

      if (url.includes('/operations/op_start_999')) {
        callCount++;
        if (callCount < 2) {
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({
              operation_id: 'op_start_999',
              status: 'RUNNING',
            }),
            json: async () => ({
              operation_id: 'op_start_999',
              status: 'RUNNING',
            }),
          } as Response;
        }

        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({
            operation_id: 'op_start_999',
            status: 'DONE',
            result: {
              state: 'RUNNING',
              durable_start_receipt: 'rcpt_start_canonical_sig_999',
            },
          }),
          json: async () => ({
            operation_id: 'op_start_999',
            status: 'DONE',
            result: {
              state: 'RUNNING',
              durable_start_receipt: 'rcpt_start_canonical_sig_999',
            },
          }),
        } as Response;
      }

      throw new Error(`Unexpected URL: ${url}`);
    });

    const result = await client.startExperiment('exp_live_01', 'operator');
    expect(result.state).toBe('RUNNING');
    expect(result.durable_start_receipt).toBe('rcpt_start_canonical_sig_999');
    expect(callCount).toBe(2);
  });

  it('rejects startExperiment when polled operation returns FAILED', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.includes('/start') && init?.method === 'POST') {
        return {
          ok: true,
          status: 202,
          text: async () => JSON.stringify({ operation_id: 'op_fail_111', status: 'PENDING' }),
          json: async () => ({ operation_id: 'op_fail_111', status: 'PENDING' }),
        } as Response;
      }
      if (url.includes('/operations/op_fail_111')) {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({
            operation_id: 'op_fail_111',
            status: 'FAILED',
            error: 'Sandbox creation error',
          }),
          json: async () => ({
            operation_id: 'op_fail_111',
            status: 'FAILED',
            error: 'Sandbox creation error',
          }),
        } as Response;
      }
      throw new Error(`Unexpected URL: ${url}`);
    });

    await expect(client.startExperiment('exp_live_01', 'operator')).rejects.toThrow(
      /Sandbox creation error/
    );
  });

  it('wires sealExperiment (POST /experiments/{id}/seal) returning PhaseReceipt', async () => {
    let capturedUrl = '';
    let capturedBody = '';
    let capturedHeaders: Record<string, string> = {};

    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      capturedUrl = url;
      capturedBody = init?.body as string;
      capturedHeaders = (init?.headers as Record<string, string>) || {};
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          domain_id: 'BAYORA-PROD-01',
          experiment_id: 'exp_live_01',
          epoch: 1,
          phase: 'SEALED',
          receipt_id: 'rcpt-seal-001',
        }),
      } as Response;
    });

    const receipt = await client.sealExperiment('exp_live_01', 'operator');
    expect(capturedUrl).toBe('/v1/operator/experiments/exp_live_01/seal');
    expect(capturedHeaders['Idempotency-Key']).toBeDefined();
    expect(JSON.parse(capturedBody).epoch).toBe(1);
    expect(receipt.phase).toBe('SEALED');
    expect(receipt.receipt_id).toBe('rcpt-seal-001');
  });

  it('wires finishExperiment (POST /experiments/{id}/finish) returning PhaseReceipt', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      expect(url).toBe('/v1/operator/experiments/exp_live_01/finish');
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          domain_id: 'BAYORA-PROD-01',
          experiment_id: 'exp_live_01',
          epoch: 1,
          phase: 'SCORED',
          receipt_id: 'rcpt-finish-001',
        }),
      } as Response;
    });

    const receipt = await client.finishExperiment('exp_live_01', 'operator');
    expect(receipt.phase).toBe('SCORED');
    expect(receipt.receipt_id).toBe('rcpt-finish-001');
  });

  it('wires releaseExperiment (POST /experiments/{id}/release) returning PhaseReceipt', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      expect(url).toBe('/v1/operator/experiments/exp_live_01/release');
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          domain_id: 'BAYORA-PROD-01',
          experiment_id: 'exp_live_01',
          epoch: 1,
          phase: 'RELEASED',
          receipt_id: 'rcpt-release-001',
        }),
      } as Response;
    });

    const receipt = await client.releaseExperiment('exp_live_01', 'operator');
    expect(receipt.phase).toBe('RELEASED');
    expect(receipt.receipt_id).toBe('rcpt-release-001');
  });

  it('wires createSession (POST /experiments/{id}/sessions) returning SessionCreated', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      expect(url).toBe('/v1/operator/experiments/exp_live_01/sessions');
      expect(init?.method).toBe('POST');
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          domain_id: 'BAYORA-PROD-01',
          experiment_id: 'exp_live_01',
          epoch: 1,
          session_id: 'sess-lane-01',
        }),
      } as Response;
    });

    const session = await client.createSession('exp_live_01', 'operator');
    expect(session.session_id).toBe('sess-lane-01');
    expect(session.experiment_id).toBe('exp_live_01');
  });

  it('wires submitTurn (POST /experiments/{id}/sessions/{sessionId}/turns)', async () => {
    let capturedBody = '';
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      expect(url).toBe('/v1/red/experiments/exp_live_01/sessions/sess-01/turns');
      capturedBody = init?.body as string;
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          turn_id: 'turn-999',
          session_id: 'sess-01',
          experiment_id: 'exp_live_01',
          epoch: 1,
          turn_index: 2,
          status: 'DONE',
          model_execution: 'EXECUTED',
          pipeline_disposition: 'ALLOWED',
          scoring: 'SCORED',
          integrity: 'VALID_WITHIN_PROFILE',
        }),
      } as Response;
    });

    const turn = await client.submitTurn('exp_live_01', 'sess-01', {
      epoch: 1,
      turn_index: 2,
      text: 'Admitted adversarial probe prompt',
    }, undefined, 'red');

    expect(JSON.parse(capturedBody).turn_index).toBe(2);
    expect(turn.status).toBe('DONE');
    expect(turn.model_execution).toBe('EXECUTED');
    expect(turn.integrity).toBe('VALID_WITHIN_PROFILE');
  });

  it('wires cancelSession (POST /experiments/{id}/sessions/{sessionId}/cancel)', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      expect(url).toBe('/v1/red/experiments/exp_live_01/sessions/sess-01/cancel');
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          experiment_id: 'exp_live_01',
          session_id: 'sess-01',
          status: 'CANCELLED',
        }),
      } as Response;
    });

    const res = await client.cancelSession('exp_live_01', 'sess-01', undefined, 'red');
    expect(res.status).toBe('CANCELLED');
  });

  it('wires downloadEvidenceBundleZip returning raw binary Response', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
      expect(url).toBe('/v1/auditor/experiments/exp_live_01/bundle');
      expect((init?.headers as Record<string, string>)?.Accept).toBe('application/zip');
      return {
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'application/zip' }),
      } as unknown as Response;
    });

    const rawRes = await client.downloadEvidenceBundleZip('exp_live_01', 'auditor');
    expect(rawRes.status).toBe(200);
    expect(rawRes.headers.get('Content-Type')).toBe('application/zip');
  });

  it('wires submitFeedbackRecovery to /v1/turn-feedback/recovery', async () => {
    let capturedUrl = '';
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      capturedUrl = url;
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          reconciled: true,
          turn_id: 'turn-rec-01',
          status: 'VALID_WITHIN_PROFILE',
        }),
      } as Response;
    });

    const res = await client.submitFeedbackRecovery({
      turn_id: 'turn-rec-01',
      idempotency_key: 'req-orig-123',
    }, undefined, 'red');

    expect(capturedUrl).toBe('/v1/red/turn-feedback/recovery');
    expect((res as { reconciled: boolean }).reconciled).toBe(true);
  });

  // ─── Task 4: Duplicate-Key JSON Detection ─────────────────────────────────────

  it('detects duplicate keys in JSON payload and throws (Task 4 requirement)', () => {
    const validJson = '{"epoch": 1, "domain": "BAYORA-01"}';
    expect(() => safeParseNoDuplicates(validJson)).not.toThrow();

    const dupKeyJson = '{"epoch": 1, "domain": "BAYORA-01", "epoch": 2}';
    expect(() => safeParseNoDuplicates(dupKeyJson)).toThrow(
      /Duplicate key detected in JSON payload: "epoch"/
    );
  });

  it('rejects backend responses containing duplicate keys in LiveArenaClient', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      return {
        ok: true,
        status: 200,
        text: async () => '{"domain_id": "BAYORA", "domain_id": "TAMPERED"}',
      } as Response;
    });

    await expect(client.sealExperiment('exp_live_01')).rejects.toThrow(
      /Duplicate key detected in JSON payload/
    );
  });

  // ─── Error Handling & Security ────────────────────────────────────────────────

  it('handles 409 IDEMPOTENCY_CONFLICT with typed error and conflict metadata', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      return {
        ok: false,
        status: 409,
        text: async () => JSON.stringify({
          code: 'IDEMPOTENCY_CONFLICT',
          message: 'Client key previously used with mismatched payload digest',
          conflict_key: 'submit-turn-123456',
        }),
        json: async () => ({
          code: 'IDEMPOTENCY_CONFLICT',
          message: 'Client key previously used with mismatched payload digest',
          conflict_key: 'submit-turn-123456',
        }),
      } as Response;
    });

    await expect(
      client.submitAttack(
        'exp_live_01',
        {
          text_artifact: 'test attack',
          commitment: 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          nonce: '0123456789abcdef0123456789abcdef',
        },
        'idemp-duplicate',
        1,
        'red'
      )
    ).rejects.toMatchObject({
      code: 'IDEMPOTENCY_CONFLICT',
    });
  });

  it('fails closed and updates store status to FAIL_CLOSED on 403 FORBIDDEN', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      return {
        ok: false,
        status: 403,
        text: async () => JSON.stringify({
          code: 'FORBIDDEN',
          message: 'Client certificate not authorized for operator namespace',
        }),
        json: async () => ({
          code: 'FORBIDDEN',
          message: 'Client certificate not authorized for operator namespace',
        }),
      } as Response;
    });

    await expect(client.getBackendStatus('exp_live_01', 'operator')).rejects.toMatchObject({
      code: 'FORBIDDEN',
    });

    // Store fail-closed transition
    expect(useArenaStore.getState().liveBackendStatus).toBe('FAIL_CLOSED');
  });

  it('fails closed on network connection failure and updates store', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      throw new TypeError('Failed to fetch: Connection refused');
    });

    await expect(client.getBackendStatus('exp_live_01', 'operator')).rejects.toThrow(
      /No HTTP response from the local backend/
    );

    expect(useArenaStore.getState().liveBackendStatus).toBe('FAIL_CLOSED');
  });

  it('prohibits failure injection toggles in live mode', () => {
    useArenaStore.setState({ connectionMode: 'live', failureMode: 'none' });
    const store = useArenaStore.getState();

    // In live mode, failureMode must be 'none' and throws on attempt
    expect(store.failureMode).toBe('none');
    expect(() => store.setFailureMode('witness_lag')).toThrow(
      /Failure injection is prohibited in live mode/
    );
    expect(useArenaStore.getState().failureMode).toBe('none');
  });

  it('locks role switching in live mode to mTLS certificate principal', () => {
    useArenaStore.setState({
      connectionMode: 'live',
      authenticatedPrincipal: {
        subject_id: 'blue-agent-01',
        domain_id: 'BAYORA-PROD-01',
        expires_at: '2026-10-29T12:00:00Z',
        role: 'blue',
        subject: 'CN=blue-agent-01',
        certFingerprint: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        is_mtls_verified: true,
      },
      role: 'blue',
    });

    const store = useArenaStore.getState();
    expect(() => store.setRole('operator')).toThrow(
      /Cannot switch role in live mode: bound to mTLS client certificate \(blue\)/
    );
    // Role must remain locked to certificate role
    expect(useArenaStore.getState().role).toBe('blue');
  });

  it('DynamicArenaClient delegates to LiveArenaClient when live and MockArenaClient when simulated', async () => {
    const dynamicClient = new DynamicArenaClient();

    // In simulated mode
    useArenaStore.setState({ connectionMode: 'simulated' });
    const mockExp = await dynamicClient.getExperiments('auditor');
    expect(mockExp.length).toBeGreaterThan(0);

    // Switch to live mode
    useArenaStore.setState({
      connectionMode: 'live',
      liveBackendStatus: 'CONNECTED',
      authenticatedPrincipal: {
        subject_id: 'auditor-01',
        domain_id: 'BAYORA-PROD-01',
        expires_at: '2026-10-29T12:00:00Z',
        role: 'auditor',
        subject: 'CN=auditor-01',
        certFingerprint: 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
        is_mtls_verified: true,
      },
    });

    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      expect(url).toBe('/v1/auditor/experiments/22222222-2222-4222-8222-222222222222/status');
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({
          domain_id: '33333333-3333-4333-8333-333333333333',
          experiment_id: '22222222-2222-4222-8222-222222222222',
          epoch: 2,
          phase: 'CLOSED',
          integrity: 'VALID_WITHIN_PROFILE',
        }),
      } as Response;
    });

    const liveStatus = await dynamicClient.liveClient.getBackendStatus(
      '22222222-2222-4222-8222-222222222222',
      'auditor'
    );
    expect(liveStatus).toMatchObject({ phase: 'CLOSED', integrity: 'VALID_WITHIN_PROFILE' });
  });
});
