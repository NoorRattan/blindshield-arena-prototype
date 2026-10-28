import { useArenaStore } from '../../state/useArenaStore';
import { MockArenaServer } from '../mock/server';
import { SseSimulator, type FailureMode } from '../mock/sse';
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
    const key = idempotencyKey ?? `idemp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
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
    const res = this.server.createExperiment(req, activeRole, idempotencyKey);
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
    await this.delay();
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
}

/**
 * Singleton client instance used throughout the frontend
 */
export const arenaClient: ArenaClient = new MockArenaClient();
