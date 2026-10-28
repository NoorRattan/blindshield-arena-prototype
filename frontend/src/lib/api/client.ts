import { useArenaStore } from '../../state/useArenaStore';
import { MockArenaServer } from '../mock/server';
import { SseSimulator, type FailureMode } from '../mock/sse';
import {
  LiveArenaClient,
  generateCanonicalClientKey,
  type PhaseReceipt,
  type SessionCreated,
  type TurnProjection,
  type TurnSubmissionRequest,
  type FeedbackRecoveryRequest,
} from './liveClient';
export {
  LiveArenaClient,
  generateCanonicalClientKey,
  type PhaseReceipt,
  type SessionCreated,
  type TurnProjection,
  type TurnSubmissionRequest,
  type FeedbackRecoveryRequest,
};
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

/**
 * Standard typed ArenaClient interface.
 * All UI feature components interact with the backend exclusively via this interface.
 */
export interface ArenaClient {
  getExperiments(role?: Role): Promise<ExperimentStatus[]>;
  getExperimentStatus(experimentId: string, role?: Role): Promise<ExperimentStatus>;
  getManifest(experimentId: string, role?: Role): Promise<Manifest>;
  getDefenseArtifact(experimentId: string, role?: Role): Promise<DefenseArtifactInfo>;
  getFeedback(experimentId: string, role?: Role): Promise<FeedbackItem[]>;
  getForensics(experimentId: string, role?: Role): Promise<ReleasedEpochForensics>;
  submitAttack(
    experimentId: string,
    req: SubmitAttackRequest,
    idempotencyKey?: string,
    epoch?: Epoch,
    role?: Role
  ): Promise<AttackReceipt>;
  createExperiment(
    req: CreateExperimentRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<CreateExperimentResponse>;
  startExperiment(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: LifecycleState; durable_start_receipt: string }>;
  closeExperiment(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: LifecycleState; checkpoint: Checkpoint }>;
  quarantineExperiment(
    experimentId: string,
    reason?: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: 'INVALID'; reason: string; timestamp_utc: string }>;
  triggerReWitness(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; witness_status: 'SYNCED' | 'LAGGING'; witness_receipt: string; timestamp_utc: string }>;
  getEvidenceBundle(
    experimentId: string,
    role?: Role
  ): Promise<{ metadata: EvidenceBundleMetadata; ledger: ArenaEvent[]; checkpoint: Checkpoint }>;
  subscribeEvents(
    experimentId: string,
    onEvent: (event: ArenaEvent) => void,
    onError?: (err: Error) => void,
    onStatusChange?: (status: 'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING') => void,
    role?: Role
  ): () => void;
  runPreflight(role?: Role): Promise<PreflightReport>;
  setFailureMode(mode: FailureMode): void;
  getFailureMode(): FailureMode;
  reset(): void;

  // Lifecycle & Interactive Session Methods (Task 3)
  sealExperiment(experimentId: string, role?: Role): Promise<PhaseReceipt>;
  finishExperiment(experimentId: string, role?: Role): Promise<PhaseReceipt>;
  releaseExperiment(experimentId: string, role?: Role): Promise<PhaseReceipt>;
  createSession(experimentId: string, role?: Role): Promise<SessionCreated>;
  submitTurn(
    experimentId: string,
    sessionId: string,
    req: TurnSubmissionRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<TurnProjection>;
  getTurnStatus(
    experimentId: string,
    sessionId: string,
    turnId: string,
    role?: Role
  ): Promise<TurnProjection>;
  cancelSession(
    experimentId: string,
    sessionId: string,
    idempotencyKey?: string,
    role?: Role
  ): Promise<{ experiment_id: string; session_id: string; status: string }>;
  downloadEvidenceBundleZip(experimentId: string, role?: Role): Promise<Response>;
  submitFeedbackRecovery(
    req: FeedbackRecoveryRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<unknown>;
  createPostHocAnalysis(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; status: string }>;
  getTurnAnalysis(experimentId: string, turnId: string, role?: Role): Promise<Response>;
}

/**
 * MockArenaClient: Local mock platform adapter implementing ArenaClient.
 * Seamlessly swappable for real HTTP/REST backend when Noor's API is deployed (FE-D-001).
 */
export class MockArenaClient implements ArenaClient {
  private server: MockArenaServer;
  private sse: SseSimulator;

  constructor(server?: MockArenaServer) {
    this.server = server ?? new MockArenaServer();
    this.sse = new SseSimulator(this.server);
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

  private async delay(ms: number = 25): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async getExperiments(role?: Role): Promise<ExperimentStatus[]> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const list = this.server.getExperiments(activeRole);
    return list.map((item) => ExperimentStatusSchema.parse(item));
  }

  async getExperimentStatus(experimentId: string, role?: Role): Promise<ExperimentStatus> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const status = this.server.getExperimentStatus(experimentId, activeRole);
    return ExperimentStatusSchema.parse(status);
  }

  async getManifest(experimentId: string, role?: Role): Promise<Manifest> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const manifest = this.server.getManifest(experimentId, activeRole);
    return ManifestSchema.parse(manifest);
  }

  async getDefenseArtifact(experimentId: string, role?: Role): Promise<DefenseArtifactInfo> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const artifact = this.server.getDefenseArtifact(experimentId, activeRole);
    return DefenseArtifactInfoSchema.parse(artifact);
  }

  async getFeedback(experimentId: string, role?: Role): Promise<FeedbackItem[]> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const items = this.server.getFeedback(experimentId, activeRole);
    return items.map((item) => FeedbackItemSchema.parse(item));
  }

  async getForensics(experimentId: string, role?: Role): Promise<ReleasedEpochForensics> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const forensics = this.server.getForensics(experimentId, activeRole);
    return ReleasedEpochForensicsSchema.parse(forensics);
  }

  async submitAttack(
    experimentId: string,
    req: SubmitAttackRequest,
    idempotencyKey?: string,
    epoch?: Epoch,
    role?: Role
  ): Promise<AttackReceipt> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const activeEpoch = this.resolveEpoch(epoch);
    const key = idempotencyKey ?? generateCanonicalClientKey('attack');
    const receipt = this.server.submitAttack(experimentId, req, key, activeRole, activeEpoch);
    return AttackReceiptSchema.parse(receipt);
  }

  async createExperiment(
    req: CreateExperimentRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<CreateExperimentResponse> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const key = idempotencyKey ?? generateCanonicalClientKey('create');
    const res = this.server.createExperiment(req, activeRole, key);
    return CreateExperimentResponseSchema.parse(res);
  }

  async startExperiment(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: LifecycleState; durable_start_receipt: string }> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    return this.server.startExperiment(experimentId, activeRole);
  }

  async closeExperiment(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: LifecycleState; checkpoint: Checkpoint }> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const res = this.server.closeExperiment(experimentId, activeRole);
    return {
      experiment_id: res.experiment_id,
      state: res.state,
      checkpoint: CheckpointSchema.parse(res.checkpoint),
    };
  }

  async quarantineExperiment(
    experimentId: string,
    reason: string = 'OPERATOR_QUARANTINE',
    role?: Role
  ): Promise<{ experiment_id: string; state: 'INVALID'; reason: string; timestamp_utc: string }> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    return this.server.quarantineExperiment(experimentId, reason, activeRole);
  }

  async triggerReWitness(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; witness_status: 'SYNCED' | 'LAGGING'; witness_receipt: string; timestamp_utc: string }> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    return this.server.triggerReWitness(experimentId, activeRole);
  }

  async getEvidenceBundle(
    experimentId: string,
    role?: Role
  ): Promise<{ metadata: EvidenceBundleMetadata; ledger: ArenaEvent[]; checkpoint: Checkpoint }> {
    const activeRole = this.resolveRole(role);
    const bundle = this.server.getEvidenceBundle(experimentId, activeRole);
    return {
      metadata: EvidenceBundleMetadataSchema.parse(bundle.metadata),
      ledger: bundle.ledger as ArenaEvent[],
      checkpoint: CheckpointSchema.parse(bundle.checkpoint),
    };
  }

  subscribeEvents(
    experimentId: string,
    onEvent: (event: ArenaEvent) => void,
    onError?: (err: Error) => void,
    onStatusChange?: (status: 'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING') => void,
    role?: Role
  ): () => void {
    const activeRole = this.resolveRole(role);
    return this.sse.subscribe({
      experimentId,
      role: activeRole,
      onEvent,
      onError,
      onStatusChange,
    });
  }

  async runPreflight(role?: Role): Promise<PreflightReport> {
    await this.delay();
    const activeRole = this.resolveRole(role);
    const report = this.server.runPreflight(activeRole);
    return PreflightReportSchema.parse(report);
  }

  setFailureMode(mode: FailureMode): void {
    this.sse.setFailureMode(mode);
    this.server.setFailureMode(mode);
    try {
      useArenaStore.getState().setFailureMode(mode);
    } catch {
      // ignore outside React environment
    }
  }

  getFailureMode(): FailureMode {
    return this.sse.getFailureMode();
  }

  reset(): void {
    this.server.reset();
    this.setFailureMode('none');
  }

  async sealExperiment(experimentId: string, _role?: Role): Promise<PhaseReceipt> {
    await this.delay();
    return {
      domain_id: 'BAYORA-PROD-01',
      experiment_id: experimentId,
      epoch: this.resolveEpoch(),
      phase: 'SEALED',
      receipt_id: generateCanonicalClientKey('rcpt-seal'),
    };
  }

  async finishExperiment(experimentId: string, _role?: Role): Promise<PhaseReceipt> {
    await this.delay();
    return {
      domain_id: 'BAYORA-PROD-01',
      experiment_id: experimentId,
      epoch: this.resolveEpoch(),
      phase: 'SCORED',
      receipt_id: generateCanonicalClientKey('rcpt-finish'),
    };
  }

  async releaseExperiment(experimentId: string, _role?: Role): Promise<PhaseReceipt> {
    await this.delay();
    return {
      domain_id: 'BAYORA-PROD-01',
      experiment_id: experimentId,
      epoch: this.resolveEpoch(),
      phase: 'RELEASED',
      receipt_id: generateCanonicalClientKey('rcpt-release'),
    };
  }

  async createSession(experimentId: string, _role?: Role): Promise<SessionCreated> {
    await this.delay();
    return {
      domain_id: 'BAYORA-PROD-01',
      experiment_id: experimentId,
      epoch: this.resolveEpoch(),
      session_id: generateCanonicalClientKey('sess'),
    };
  }

  async submitTurn(
    experimentId: string,
    sessionId: string,
    req: TurnSubmissionRequest,
    _idempotencyKey?: string,
    _role?: Role
  ): Promise<TurnProjection> {
    await this.delay();
    return {
      turn_id: generateCanonicalClientKey('turn'),
      session_id: sessionId,
      experiment_id: experimentId,
      epoch: this.resolveEpoch(req.epoch as Epoch),
      turn_index: req.turn_index,
      status: 'DONE',
      model_execution: 'EXECUTED',
      pipeline_disposition: 'ALLOWED',
      scoring: 'SCORED',
      integrity: 'VALID_WITHIN_PROFILE',
    };
  }

  async getTurnStatus(
    experimentId: string,
    sessionId: string,
    turnId: string,
    _role?: Role
  ): Promise<TurnProjection> {
    await this.delay();
    return {
      turn_id: turnId,
      session_id: sessionId,
      experiment_id: experimentId,
      epoch: this.resolveEpoch(),
      turn_index: 1,
      status: 'DONE',
      model_execution: 'EXECUTED',
      pipeline_disposition: 'ALLOWED',
      scoring: 'SCORED',
      integrity: 'VALID_WITHIN_PROFILE',
    };
  }

  async cancelSession(
    experimentId: string,
    sessionId: string,
    _idempotencyKey?: string,
    _role?: Role
  ): Promise<{ experiment_id: string; session_id: string; status: string }> {
    await this.delay();
    return {
      experiment_id: experimentId,
      session_id: sessionId,
      status: 'CANCELLED',
    };
  }

  async downloadEvidenceBundleZip(_experimentId: string, _role?: Role): Promise<Response> {
    throw new Error('ZIP binary bundle download is available only from the live broker; in simulated mode use getEvidenceBundle()');
  }

  async submitFeedbackRecovery(_req: FeedbackRecoveryRequest, _idempotencyKey?: string, _role?: Role): Promise<unknown> {
    throw new Error('Turn feedback recovery is available only from the live broker');
  }

  async createPostHocAnalysis(experimentId: string, _role?: Role): Promise<{ experiment_id: string; status: string }> {
    await this.delay();
    return {
      experiment_id: experimentId,
      status: 'ANALYSIS_SCHEDULED',
    };
  }

  async getTurnAnalysis(_experimentId: string, _turnId: string, _role?: Role): Promise<Response> {
    throw new Error('Analysis ZIP bundles are available only from the live broker');
  }
}

/**
 * DynamicArenaClient: Dynamic routing facade implementing ArenaClient.
 * Automatically delegates to LiveArenaClient when connectionMode === 'live',
 * or MockArenaClient when connectionMode === 'simulated' (Task 1 & Task 2).
 */
export class DynamicArenaClient implements ArenaClient {
  public readonly mockClient: MockArenaClient;
  public readonly liveClient: LiveArenaClient;

  constructor(mockClient?: MockArenaClient, liveClient?: LiveArenaClient) {
    this.mockClient = mockClient ?? new MockArenaClient();
    this.liveClient = liveClient ?? new LiveArenaClient();
  }

  private get active(): ArenaClient {
    try {
      const mode = useArenaStore.getState().connectionMode;
      return mode === 'live' ? this.liveClient : this.mockClient;
    } catch {
      return this.mockClient;
    }
  }

  getExperiments(role?: Role): Promise<ExperimentStatus[]> {
    return this.active.getExperiments(role);
  }

  getExperimentStatus(experimentId: string, role?: Role): Promise<ExperimentStatus> {
    return this.active.getExperimentStatus(experimentId, role);
  }

  getManifest(experimentId: string, role?: Role): Promise<Manifest> {
    return this.active.getManifest(experimentId, role);
  }

  getDefenseArtifact(experimentId: string, role?: Role): Promise<DefenseArtifactInfo> {
    return this.active.getDefenseArtifact(experimentId, role);
  }

  getFeedback(experimentId: string, role?: Role): Promise<FeedbackItem[]> {
    return this.active.getFeedback(experimentId, role);
  }

  getForensics(experimentId: string, role?: Role): Promise<ReleasedEpochForensics> {
    return this.active.getForensics(experimentId, role);
  }

  submitAttack(
    experimentId: string,
    req: SubmitAttackRequest,
    idempotencyKey?: string,
    epoch?: Epoch,
    role?: Role
  ): Promise<AttackReceipt> {
    return this.active.submitAttack(experimentId, req, idempotencyKey, epoch, role);
  }

  createExperiment(
    req: CreateExperimentRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<CreateExperimentResponse> {
    return this.active.createExperiment(req, idempotencyKey, role);
  }

  startExperiment(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: LifecycleState; durable_start_receipt: string }> {
    return this.active.startExperiment(experimentId, role);
  }

  closeExperiment(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: LifecycleState; checkpoint: Checkpoint }> {
    return this.active.closeExperiment(experimentId, role);
  }

  quarantineExperiment(
    experimentId: string,
    reason?: string,
    role?: Role
  ): Promise<{ experiment_id: string; state: 'INVALID'; reason: string; timestamp_utc: string }> {
    return this.active.quarantineExperiment(experimentId, reason, role);
  }

  triggerReWitness(
    experimentId: string,
    role?: Role
  ): Promise<{
    experiment_id: string;
    witness_status: 'SYNCED' | 'LAGGING';
    witness_receipt: string;
    timestamp_utc: string;
  }> {
    return this.active.triggerReWitness(experimentId, role);
  }

  getEvidenceBundle(
    experimentId: string,
    role?: Role
  ): Promise<{ metadata: EvidenceBundleMetadata; ledger: ArenaEvent[]; checkpoint: Checkpoint }> {
    return this.active.getEvidenceBundle(experimentId, role);
  }

  subscribeEvents(
    experimentId: string,
    onEvent: (event: ArenaEvent) => void,
    onError?: (err: Error) => void,
    onStatusChange?: (status: 'CONNECTED' | 'RECONNECTING' | 'CLOSED' | 'LAGGING') => void,
    role?: Role
  ): () => void {
    return this.active.subscribeEvents(experimentId, onEvent, onError, onStatusChange, role);
  }

  runPreflight(role?: Role): Promise<PreflightReport> {
    return this.active.runPreflight(role);
  }

  setFailureMode(mode: FailureMode): void {
    this.active.setFailureMode(mode);
  }

  getFailureMode(): FailureMode {
    return this.active.getFailureMode();
  }

  reset(): void {
    this.active.reset();
  }

  sealExperiment(experimentId: string, role?: Role): Promise<PhaseReceipt> {
    return this.active.sealExperiment(experimentId, role);
  }

  finishExperiment(experimentId: string, role?: Role): Promise<PhaseReceipt> {
    return this.active.finishExperiment(experimentId, role);
  }

  releaseExperiment(experimentId: string, role?: Role): Promise<PhaseReceipt> {
    return this.active.releaseExperiment(experimentId, role);
  }

  createSession(experimentId: string, role?: Role): Promise<SessionCreated> {
    return this.active.createSession(experimentId, role);
  }

  submitTurn(
    experimentId: string,
    sessionId: string,
    req: TurnSubmissionRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<TurnProjection> {
    return this.active.submitTurn(experimentId, sessionId, req, idempotencyKey, role);
  }

  getTurnStatus(
    experimentId: string,
    sessionId: string,
    turnId: string,
    role?: Role
  ): Promise<TurnProjection> {
    return this.active.getTurnStatus(experimentId, sessionId, turnId, role);
  }

  cancelSession(
    experimentId: string,
    sessionId: string,
    idempotencyKey?: string,
    role?: Role
  ): Promise<{ experiment_id: string; session_id: string; status: string }> {
    return this.active.cancelSession(experimentId, sessionId, idempotencyKey, role);
  }

  downloadEvidenceBundleZip(experimentId: string, role?: Role): Promise<Response> {
    return this.active.downloadEvidenceBundleZip(experimentId, role);
  }

  submitFeedbackRecovery(
    req: FeedbackRecoveryRequest,
    idempotencyKey?: string,
    role?: Role
  ): Promise<unknown> {
    return this.active.submitFeedbackRecovery(req, idempotencyKey, role);
  }

  createPostHocAnalysis(
    experimentId: string,
    role?: Role
  ): Promise<{ experiment_id: string; status: string }> {
    return this.active.createPostHocAnalysis(experimentId, role);
  }

  getTurnAnalysis(experimentId: string, turnId: string, role?: Role): Promise<Response> {
    return this.active.getTurnAnalysis(experimentId, turnId, role);
  }
}

/**
 * Singleton client instance used throughout the frontend.
 * Dynamically dispatches to LiveArenaClient or MockArenaClient according to connectionMode.
 */
export const arenaClient: ArenaClient = new LiveArenaClient();
