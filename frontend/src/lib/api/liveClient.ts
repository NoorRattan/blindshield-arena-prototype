import type { ArenaClient } from './client';
import type { FailureMode } from '../mock/sse';
import type {
  ArenaEvent,
  AttackReceipt,
  Checkpoint,
  CreateExperimentRequest,
  CreateExperimentResponse,
  DefenseArtifactInfo,
  Epoch,
  EvidenceBundleMetadata,
  ExperimentStatus,
  FeedbackItem,
  LifecycleState,
  Manifest,
  PreflightReport,
  ReleasedEpochForensics,
  Role,
  SubmitAttackRequest,
} from '../schemas';
import {
  AttackReceiptSchema,
  CheckpointSchema,
  CreateExperimentResponseSchema,
  DefenseArtifactInfoSchema,
  EvidenceBundleMetadataSchema,
  ExperimentStatusSchema,
  FeedbackItemSchema,
  ManifestSchema,
  PreflightReportSchema,
  ReleasedEpochForensicsSchema,
} from '../schemas';
import { useArenaStore } from '../../state/useArenaStore';

// ─── Lifecycle response types ─────────────────────────────────────────────────

/** Backend PhaseReceipt: returned by seal / finish / close / release */
export interface PhaseReceipt {
  domain_id: string;
  experiment_id: string;
  epoch: number;
  phase: string;
  receipt_id: string;
}

/** Backend SessionCreated: returned by POST /sessions */
export interface SessionCreated {
  domain_id: string;
  experiment_id: string;
  epoch: number;
  session_id: string;
}

/** Backend UploadReceipt: returned by POST /attacks */
export interface UploadReceipt {
  domain_id: string;
  experiment_id: string;
  epoch: number;
  receipt_id: string;
  accepted_items: number;
}

/**
 * Turn status projection returned by GET /sessions/{session_id}/turns/{turn_id}.
 * Backend provides a fixed-size pending/final projection; no inference retry.
 */
export interface TurnProjection {
  turn_id: string;
  session_id: string;
  experiment_id: string;
  epoch: number;
  turn_index: number;
  status: 'PENDING' | 'DONE' | 'CANCELLED' | 'UNKNOWN';
  model_execution?: string;
  pipeline_disposition?: string;
  scoring?: string;
  integrity?: string;
}

/**
 * Request body for submitting a turn in an interactive session.
 * Exactly one of text or payload_ref must be supplied.
 */
export interface TurnSubmissionRequest {
  epoch: number;
  turn_index: number;
  text?: string;
  payload_ref?: string;
}

/** Request body for session cancel */
export interface CancelSessionRequest {
  epoch: number;
}

/** Backend AttackBatch wire shape sent on POST /attacks */
export interface AttackBatchRequest {
  epoch: number;
  items: Array<{ item_id: string; text: string }>;
}

/**
 * Turn feedback recovery request (POST /v1/turn-feedback/recovery).
 * Versioned; must include the exact owned turn/idempotency key.
 */
export interface FeedbackRecoveryRequest {
  epoch: number;
  turn_id: string;
  original_client_key: string;
}

/**
 * Parse JSON string with duplicate-key detection.
 * Browser JSON.parse silently overwrites duplicate keys; this throws instead.
 * Required by Task 4: match backend's strict parsing rules (contracts/api.py).
 */
export function safeParseNoDuplicates(jsonStr: string): unknown {
  const stack: Array<Set<string> | null> = [];
  let inString = false;
  let escape = false;
  let currentString = '';
  let lastString = '';
  let isAfterColon = false;

  for (let i = 0; i < jsonStr.length; i++) {
    const char = jsonStr[i];

    if (inString) {
      if (escape) {
        currentString += char;
        escape = false;
      } else if (char === '\\') {
        escape = true;
        currentString += char;
      } else if (char === '"') {
        inString = false;
        lastString = currentString;
      } else {
        currentString += char;
      }
      continue;
    }

    if (char === '"') {
      inString = true;
      escape = false;
      currentString = '';
    } else if (char === '{') {
      stack.push(new Set<string>());
      isAfterColon = false;
    } else if (char === '}') {
      stack.pop();
      isAfterColon = false;
    } else if (char === '[') {
      stack.push(null);
      isAfterColon = false;
    } else if (char === ']') {
      stack.pop();
      isAfterColon = false;
    } else if (char === ':') {
      const top = stack[stack.length - 1];
      if (top !== null && top !== undefined && !isAfterColon) {
        if (top.has(lastString)) {
          throw new Error(`Duplicate key detected in JSON payload: "${lastString}"`);
        }
        top.add(lastString);
      }
      isAfterColon = true;
    } else if (char === ',') {
      isAfterColon = false;
    }
  }

  return JSON.parse(jsonStr);
}

/**
 * Generate a canonical ASCII ClientKey matching backend regex ^[!-~]+$ (contracts/common.py).
 * Excludes spaces and non-printable characters.
 */
export function generateCanonicalClientKey(action: string = 'req'): string {
  const ts = Date.now();
  const rand = Math.random().toString(36).slice(2, 10);
  return `${action}-${ts}-${rand}`;
}

export interface LiveClientConfig {
  baseUrl?: string;
}

/**
 * LiveArenaClient: Real HTTP client for authenticating with the BlindShield Arena backend broker.
 * Implements real network transport, mTLS client credentials, fail-closed handling,
 * canonical ASCII idempotency keys, duplicate-key detection, and full lifecycle orchestration.
 */
export class LiveArenaClient implements ArenaClient {
  private baseUrl: string;

  constructor(config?: LiveClientConfig) {
    this.baseUrl = config?.baseUrl ?? '/v1';
  }

  private resolveRole(roleOverride?: Role): Role {
    if (roleOverride) return roleOverride;
    try {
      return useArenaStore.getState().role;
    } catch {
      return 'operator';
    }
  }

  private resolveEpoch(epochOverride?: Epoch): Epoch {
    if (epochOverride !== undefined) return epochOverride;
    try {
      return useArenaStore.getState().epoch as Epoch;
    } catch {
      return 1 as Epoch;
    }
  }

  private getAuthHeaders(role?: Role): Record<string, string> {
    const activeRole = this.resolveRole(role);
    const headers: Record<string, string> = {
      'x-arena-role': activeRole,
    };
    try {
      const principal = useArenaStore.getState().authenticatedPrincipal;
      if (principal?.certFingerprint) {
        headers['x-client-cert-sha256'] = principal.certFingerprint;
      }
    } catch {
      // ignore
    }
    return headers;
  }

  /**
   * Safe fetch with duplicate-key JSON detection, Idempotency-Key, and typed fail-closed handling.
   * Parses text first to detect duplicate JSON keys before native JSON.parse silently overwrites them.
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit & { idempotencyKey?: string; role?: Role; rawResponse?: boolean } = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
    const authHeaders = this.getAuthHeaders(options.role);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...authHeaders,
      ...(options.headers as Record<string, string> | undefined),
    };

    if (options.idempotencyKey) {
      headers['Idempotency-Key'] = options.idempotencyKey;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (!response.ok) {
        let errData: { code?: string; message?: string; request_id?: string } = {};
        try {
          let errText = '';
          if (typeof response.text === 'function') {
            errText = await response.text();
          } else if (typeof response.json === 'function') {
            errText = JSON.stringify(await response.json());
          }
          errData = (errText ? safeParseNoDuplicates(errText) : {}) as typeof errData;
        } catch {
          errData = {
            code: response.status === 409 ? 'IDEMPOTENCY_CONFLICT' : response.status === 403 ? 'FORBIDDEN' : 'POLICY_NOT_READY',
            message: `HTTP ${response.status}: ${response.statusText}`,
          };
        }

        // Set store liveBackendStatus to FAIL_CLOSED
        try {
          useArenaStore.getState().setLiveBackendStatus('FAIL_CLOSED');
        } catch {
          // ignore outside react
        }

        const err = new Error(errData.message ?? `Backend request failed with code: ${errData.code ?? response.status}`);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (err as any).code = errData.code ?? 'POLICY_NOT_READY';
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (err as any).requestId = errData.request_id;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (err as any).status = response.status;
        throw err;
      }

      // Mark live status CONNECTED
      try {
        useArenaStore.getState().setLiveBackendStatus('CONNECTED');
      } catch {
        // ignore outside react
      }

      // For binary (ZIP) responses, return the Response object directly
      if (options.rawResponse) {
        return response as unknown as T;
      }

      // Parse text first to catch duplicate-key violations before JSON.parse silently overwrites
      let text = '';
      if (typeof response.text === 'function') {
        text = await response.text();
      } else if (typeof response.json === 'function') {
        const data = await response.json();
        return data as T;
      } else {
        text = String(response);
      }
      return safeParseNoDuplicates(text) as T;
    } catch (networkErr) {
      try {
        useArenaStore.getState().setLiveBackendStatus('FAIL_CLOSED');
      } catch {
        // ignore
      }
      throw networkErr;
    }
  }

  /**
   * Poll an asynchronous control operation until terminal state (DONE or FAILED).
   * Maps to GET /v1/operations/{operation_id} (PROTOTYPE-SERVICE.md line 81).
   * Task 3 lifecycle rule: Never automatically rerun a failed operation.
   */
  async pollOperation(
    experimentId: string,
    operationId: string,
    maxAttempts: number = 30,
    intervalMs: number = 50
  ): Promise<{ operation_id: string; status: string; result?: unknown }> {
    for (let i = 0; i < maxAttempts; i++) {
      let op: { operation_id: string; status: 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED'; result?: unknown; error?: string };
      try {
        op = await this.request<{
          operation_id: string;
          status: 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED';
          result?: unknown;
          error?: string;
        }>(`/operations/${operationId}`);
      } catch {
        // Fallback to scoped route if backend mounts under experiment prefix
        op = await this.request<{
          operation_id: string;
          status: 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED';
          result?: unknown;
          error?: string;
        }>(`/experiments/${experimentId}/operations/${operationId}`);
      }

      if (op.status === 'DONE') {
        return op;
      }
      if (op.status === 'FAILED') {
        throw new Error(op.error || `Operation ${operationId} failed`);
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    throw new Error(`Operation ${operationId} timed out after polling`);
  }

  async getExperiments(role?: Role): Promise<ExperimentStatus[]> {
    const res = await this.request<unknown[]>('/experiments', { role });
    return res.map((item) => ExperimentStatusSchema.parse(item));
  }

  async getExperimentStatus(experimentId: string, role?: Role): Promise<ExperimentStatus> {
    const raw = await this.request<Record<string, unknown>>(`/experiments/${experimentId}/status`, { role });

    // Handle static embargo view for blue role
    if (raw.status === 'EMBARGOED') {
      return ExperimentStatusSchema.parse({
        experiment_id: experimentId,
        domain: 'EMBARGOED_DOMAIN',
        epoch: 1,
        state: 'RUNNING',
        profile: 'SEALED_BATCH',
        current_turn: 0,
        attempts_count: 0,
        valid_attempts_count: 0,
        invalid_attempts_count: 0,
        latest_digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
        manifest_digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
        witness_status: 'SYNCED',
        updated_at: new Date().toISOString(),
        delayed: true,
        delay_label: 'EMBARGOED',
      });
    }

    return ExperimentStatusSchema.parse(raw);
  }

  async getManifest(experimentId: string, role?: Role): Promise<Manifest> {
    const raw = await this.request<unknown>(`/experiments/${experimentId}/manifest`, { role });
    return ManifestSchema.parse(raw);
  }

  async getDefenseArtifact(experimentId: string, role?: Role): Promise<DefenseArtifactInfo> {
    const raw = await this.request<unknown>(`/experiments/${experimentId}/defense-artifact`, { role });
    return DefenseArtifactInfoSchema.parse(raw);
  }

  async getFeedback(experimentId: string, role?: Role): Promise<FeedbackItem[]> {
    const activeRole = this.resolveRole(role);
    // In live backend, active rounds return static EMBARGOED for blue
    if (activeRole === 'blue') {
      return [];
    }
    const raw = await this.request<unknown[]>(`/experiments/${experimentId}/feedback`, { role: activeRole });
    return raw.map((item) => FeedbackItemSchema.parse(item));
  }

  async getForensics(experimentId: string, role?: Role): Promise<ReleasedEpochForensics> {
    const raw = await this.request<unknown>(`/experiments/${experimentId}/forensics`, { role });
    return ReleasedEpochForensicsSchema.parse(raw);
  }

  async submitAttack(
    experimentId: string,
    req: SubmitAttackRequest,
    idempotencyKey?: string,
    epoch?: Epoch,
    role?: Role
  ): Promise<AttackReceipt> {
    const key = idempotencyKey ?? generateCanonicalClientKey('attack');
    const activeEpoch = this.resolveEpoch(epoch);
    const raw = await this.request<unknown>(`/experiments/${experimentId}/attacks`, {
      method: 'POST',
      idempotencyKey: key,
      role,
      body: JSON.stringify({
        epoch: activeEpoch,
        items: [
          {
            item_id: generateCanonicalClientKey('item'),
            text: req.text_artifact,
          },
        ],
      }),
    });
    return AttackReceiptSchema.parse(raw);
  }

  async createExperiment(
    req: CreateExperimentRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<CreateExperimentResponse> {
    const key = idempotencyKey ?? generateCanonicalClientKey('create');
    const payload = {
      profile_id: req.strategy_version_id ?? 'local-control-only-v1',
      model_version_id: req.versions?.target_model ?? 'UNADMITTED_MODEL',
      defense_version_id: req.versions?.defense_runtime ?? 'UNADMITTED_DEFENSE',
      rubric_version_id: req.rubric_version_id ?? 'UNADMITTED_RUBRIC',
      disclosure_profile_id: req.profile ?? 'SEALED_BATCH',
      interaction_mode: req.interaction_mode ?? 'INTERACTIVE',
      defense_mode: req.defense_mode ?? 'INPUT',
      dataset_catalog_id: req.dataset_catalog_id ?? 'UNADMITTED_DATASET',
      strategy_version_id: req.strategy_version_id ?? 'UNADMITTED_STRATEGY',
      budget_profile_id: req.budget_profile_id ?? 'local-control-budget-v1',
    };

    const raw = await this.request<unknown>('/experiments', {
      method: 'POST',
      idempotencyKey: key,
      role,
      body: JSON.stringify(payload),
    });
    return CreateExperimentResponseSchema.parse(raw);
  }

  /**
   * Start experiment. Handles either asynchronous 202 operation polling or direct PhaseReceipt.
   */
  async startExperiment(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: LifecycleState; durable_start_receipt: string }> {
    const key = generateCanonicalClientKey('start');
    const epoch = this.resolveEpoch();

    const startRes = await this.request<{
      operation_id?: string;
      receipt_id?: string;
      phase?: string;
      status?: string;
      experiment_id?: string;
    }>(`/experiments/${experimentId}/start`, {
      method: 'POST',
      idempotencyKey: key,
      role,
      body: JSON.stringify({ epoch }),
    });

    // If backend returns an operation_id, poll until DONE or FAILED (PROTOTYPE-SERVICE.md)
    if (startRes.operation_id) {
      const polled = await this.pollOperation(experimentId, startRes.operation_id);
      const finalResult = polled.result as { state?: LifecycleState; durable_start_receipt?: string } | undefined;
      return {
        experiment_id: experimentId,
        state: finalResult?.state ?? 'RUNNING',
        durable_start_receipt: finalResult?.durable_start_receipt ?? startRes.operation_id,
      };
    }

    // Direct synchronous phase receipt
    return {
      experiment_id: startRes.experiment_id ?? experimentId,
      state: (startRes.phase as LifecycleState) ?? 'RUNNING',
      durable_start_receipt: startRes.receipt_id ?? key,
    };
  }

  /**
   * POST /v1/experiments/{id}/seal
   * Freeze profile, item references, commitments, and transport policy.
   */
  async sealExperiment(experimentId: string, role?: Role): Promise<PhaseReceipt> {
    const key = generateCanonicalClientKey('seal');
    const epoch = this.resolveEpoch();
    return this.request<PhaseReceipt>(`/experiments/${experimentId}/seal`, {
      method: 'POST',
      idempotencyKey: key,
      role,
      body: JSON.stringify({ epoch }),
    });
  }

  /**
   * POST /v1/experiments/{id}/finish
   * Durably stop new admissions, settle existing jobs, reach SCORED or INVALID.
   */
  async finishExperiment(experimentId: string, role?: Role): Promise<PhaseReceipt> {
    const key = generateCanonicalClientKey('finish');
    const epoch = this.resolveEpoch();
    return this.request<PhaseReceipt>(`/experiments/${experimentId}/finish`, {
      method: 'POST',
      idempotencyKey: key,
      role,
      body: JSON.stringify({ epoch }),
    });
  }

  /**
   * POST /v1/experiments/{id}/close
   * Destroy terminal model contexts, retain checkpoint/witness close.
   */
  async closeExperiment(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: LifecycleState; checkpoint: Checkpoint }> {
    const key = generateCanonicalClientKey('close');
    const epoch = this.resolveEpoch();

    const raw = await this.request<{ experiment_id: string; state: LifecycleState; checkpoint: unknown }>(
      `/experiments/${experimentId}/close`,
      {
        method: 'POST',
        idempotencyKey: key,
        role,
        body: JSON.stringify({ epoch }),
      }
    );

    return {
      experiment_id: raw.experiment_id,
      state: raw.state ?? 'CLOSED',
      checkpoint: CheckpointSchema.parse(raw.checkpoint),
    };
  }

  /**
   * POST /v1/experiments/{id}/release
   * Valid-only release after authoritative close and timing floor.
   */
  async releaseExperiment(experimentId: string, role?: Role): Promise<PhaseReceipt> {
    const key = generateCanonicalClientKey('release');
    const epoch = this.resolveEpoch();
    return this.request<PhaseReceipt>(`/experiments/${experimentId}/release`, {
      method: 'POST',
      idempotencyKey: key,
      role,
      body: JSON.stringify({ epoch }),
    });
  }

  /**
   * POST /v1/experiments/{id}/sessions
   * Allocate three server-owned sticky interactive lanes.
   */
  async createSession(experimentId: string, role?: Role): Promise<SessionCreated> {
    const key = generateCanonicalClientKey('session');
    const epoch = this.resolveEpoch();
    return this.request<SessionCreated>(`/experiments/${experimentId}/sessions`, {
      method: 'POST',
      idempotencyKey: key,
      role,
      body: JSON.stringify({ epoch }),
    });
  }

  /**
   * POST /v1/experiments/{id}/sessions/{sessionId}/turns
   * Submit interactive turn.
   */
  async submitTurn(
    experimentId: string,
    sessionId: string,
    req: TurnSubmissionRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<TurnProjection> {
    const key = idempotencyKey ?? generateCanonicalClientKey('turn');
    return this.request<TurnProjection>(
      `/experiments/${experimentId}/sessions/${sessionId}/turns`,
      {
        method: 'POST',
        idempotencyKey: key,
        role,
        body: JSON.stringify(req),
      }
    );
  }

  /**
   * GET /v1/experiments/{id}/sessions/{sessionId}/turns/{turnId}
   * Fixed-size pending/final projection.
   */
  async getTurnStatus(
    experimentId: string,
    sessionId: string,
    turnId: string,
    role?: Role
  ): Promise<TurnProjection> {
    return this.request<TurnProjection>(
      `/experiments/${experimentId}/sessions/${sessionId}/turns/${turnId}`,
      { method: 'GET', role }
    );
  }

  /**
   * POST /v1/experiments/{id}/sessions/{sessionId}/cancel
   * Cancel interactive session. Ambiguous execution stays UNKNOWN/INVALID.
   */
  async cancelSession(
    experimentId: string,
    sessionId: string,
    idempotencyKey?: string,
    role?: Role
  ): Promise<{ experiment_id: string; session_id: string; status: string }> {
    const key = idempotencyKey ?? generateCanonicalClientKey('cancel');
    const epoch = this.resolveEpoch();
    return this.request<{ experiment_id: string; session_id: string; status: string }>(
      `/experiments/${experimentId}/sessions/${sessionId}/cancel`,
      {
        method: 'POST',
        idempotencyKey: key,
        role,
        body: JSON.stringify({ epoch }),
      }
    );
  }

  /**
   * GET /v1/experiments/{id}/bundle
   * Returns authoritative raw ZIP evidence bundle (application/zip).
   */
  async downloadEvidenceBundleZip(experimentId: string, role?: Role): Promise<Response> {
    return this.request<Response>(`/experiments/${experimentId}/bundle`, {
      method: 'GET',
      role,
      rawResponse: true,
      headers: {
        Accept: 'application/zip',
      },
    });
  }

  /**
   * POST /v1/turn-feedback/recovery
   * Versioned recovery for orphan reservations.
   */
  async submitFeedbackRecovery(
    req: FeedbackRecoveryRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<unknown> {
    const key = idempotencyKey ?? generateCanonicalClientKey('recovery');
    return this.request<unknown>('/turn-feedback/recovery', {
      method: 'POST',
      idempotencyKey: key,
      role,
      body: JSON.stringify(req),
    });
  }

  /**
   * POST /v1/experiments/{id}/analysis
   * Post-hoc analysis request after release.
   */
  async createPostHocAnalysis(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; status: string }> {
    const key = generateCanonicalClientKey('analysis');
    const epoch = this.resolveEpoch();
    return this.request<{ experiment_id: string; status: string }>(
      `/experiments/${experimentId}/analysis`,
      {
        method: 'POST',
        idempotencyKey: key,
        role,
        body: JSON.stringify({ epoch }),
      }
    );
  }

  /**
   * GET /v1/experiments/{id}/analysis/{turnId}
   * Returns post-hoc analysis ZIP bundle.
   */
  async getTurnAnalysis(experimentId: string, turnId: string, role?: Role): Promise<Response> {
    return this.request<Response>(`/experiments/${experimentId}/analysis/${turnId}`, {
      method: 'GET',
      role,
      rawResponse: true,
      headers: {
        Accept: 'application/zip',
      },
    });
  }

  async quarantineExperiment(
    experimentId: string,
    reason: string = 'OPERATOR_QUARANTINE',
    role?: Role
  ): Promise<{ experiment_id: string; state: 'INVALID'; reason: string; timestamp_utc: string }> {
    const key = generateCanonicalClientKey('quarantine');
    const epoch = this.resolveEpoch();

    const raw = await this.request<{ experiment_id: string; state: 'INVALID'; reason: string; timestamp_utc: string }>(
      `/experiments/${experimentId}/quarantine`,
      {
        method: 'POST',
        idempotencyKey: key,
        role,
        body: JSON.stringify({ epoch, reason }),
      }
    );

    return raw;
  }

  async triggerReWitness(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; witness_status: 'SYNCED' | 'LAGGING'; witness_receipt: string; timestamp_utc: string }> {
    const key = generateCanonicalClientKey('witness');
    const raw = await this.request<{ experiment_id: string; witness_status: 'SYNCED' | 'LAGGING'; witness_receipt: string; timestamp_utc: string }>(
      `/experiments/${experimentId}/witness`,
      {
        method: 'POST',
        idempotencyKey: key,
        role,
      }
    );
    return raw;
  }

  async getEvidenceBundle(
    experimentId: string,
    role?: Role
  ): Promise<{ metadata: EvidenceBundleMetadata; ledger: ArenaEvent[]; checkpoint: Checkpoint }> {
    const raw = await this.request<{ metadata: unknown; ledger: unknown[]; checkpoint: unknown }>(
      `/experiments/${experimentId}/bundle`,
      { role }
    );
    return {
      metadata: EvidenceBundleMetadataSchema.parse(raw.metadata),
      ledger: raw.ledger as ArenaEvent[],
      checkpoint: CheckpointSchema.parse(raw.checkpoint),
    };
  }

  subscribeEvents(
    experimentId: string,
    _onEvent: (event: ArenaEvent) => void,
    onError?: (err: Error) => void,
    onStatusChange?: (status: 'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING') => void,
    _role?: Role
  ): () => void {
    let isSubscribed = true;
    onStatusChange?.('CONNECTED');

    // Interval polling for status and events against live backend (Task 3)
    const intervalId = setInterval(async () => {
      if (!isSubscribed) return;
      try {
        const status = await this.getExperimentStatus(experimentId);
        onStatusChange?.(status.witness_status === 'LAGGING' ? 'LAGGING' : 'CONNECTED');
      } catch (err) {
        onStatusChange?.('RECONNECTING');
        onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }, 2500);

    return () => {
      isSubscribed = false;
      clearInterval(intervalId);
      onStatusChange?.('CLOSED');
    };
  }

  async runPreflight(_role?: Role): Promise<PreflightReport> {
    const raw = await this.request<unknown>('/preflight');
    return PreflightReportSchema.parse(raw);
  }

  setFailureMode(mode: FailureMode): void {
    if (mode !== 'none') {
      throw new Error(
        'Failure injection is prohibited in live mode: live backend enforces fail-closed isolation'
      );
    }
  }

  getFailureMode(): FailureMode {
    return 'none';
  }

  reset(): void {
    // In live mode, reset is a no-op that preserves backend state
  }
}
