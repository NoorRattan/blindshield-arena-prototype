import { sha256Digest } from '../crypto';
import type {
  ArenaEvent,
  Attempt,
  Checkpoint,
  DefenseMode,
  Digest,
  Epoch,
  FeedbackProfile,
  InteractionMode,
  LifecycleState,
  Limits,
  Manifest,
  PreflightCheck,
  PreflightReport,
  Versions,
} from '../schemas';
import { PreflightReportSchema } from '../schemas';
import { appendEventToLedger, createSignedCheckpoint, verifyEventChain } from './ledger';
import { DeterministicRng } from './prng';
import type { FailureMode } from './sse';

/**
 * Canary tokens used to assert that private artifacts are never leaked
 * to unauthorized roles in mock responses.
 */
export const CANARY_TOKENS = {
  RED_PRIVATE_PAYLOAD: 'CANARY_RED_PROMPT_SECRET_TOKEN_98765',
  BLUE_DEFENSE_RULESET: 'CANARY_BLUE_DEFENSE_RULESET_INTERNAL_43210',
  TARGET_RAW_PROMPT: 'CANARY_TARGET_RAW_INTERNAL_PROMPT_11223',
  EMBARGOED_SALT: 'CANARY_EMBARGOED_PREFIX_SALT_99887',
} as const;

export interface MockArenaData {
  experiment_id: string;
  domain: string;
  epoch: Epoch;
  state: LifecycleState;
  profile: FeedbackProfile;
  limits: Limits;
  versions: Versions;
  manifest: Manifest;
  ledger: ArenaEvent[];
  attempts: Attempt[];
  checkpoint?: Checkpoint;
  invalid_reason?: string;
  internalCanaries: string[];
}

/**
 * Builds a deterministic manifest with computed manifest_digest
 */
export function buildMockManifest(params: {
  domain: string;
  experiment_id: string;
  epoch: Epoch;
  profile: FeedbackProfile;
  created_at: string;
  limits?: Partial<Limits>;
  versions?: Partial<Versions>;
  interaction_mode?: InteractionMode;
  defense_mode?: DefenseMode;
  dataset_catalog_id?: string;
  strategy_version_id?: string;
  budget_profile_id?: string;
  rubric_version_id?: string;
}): Manifest {
  const limits: Limits = {
    body_max_bytes: 70000,
    text_max_bytes: 65536,
    output_max_tokens: 256,
    defense_deadline_ms: 1000,
    target_deadline_ms: 30000,
    ...params.limits,
  };

  const versions: Versions = {
    target_model: 'llama-3-8b-instruct-q4',
    defense_runtime: 'blindshield-defense-v1.4',
    broker: 'bayora-broker-v2.1',
    recorder: 'bayora-recorder-v1.8',
    ...params.versions,
  };

  const rawWithoutDigest = `${params.domain}:${params.experiment_id}:${params.epoch}:${params.profile}`;
  const manifest_digest = sha256Digest(`manifest:${rawWithoutDigest}`);
  const witness_receipt = `rcpt_${sha256Digest(`witness:${manifest_digest}`).slice(7, 23)}`;

  return {
    domain: params.domain,
    experiment_id: params.experiment_id,
    epoch: params.epoch,
    created_at: params.created_at,
    protocol_version: 'arena.v2',
    profile: params.profile,
    interaction_mode: params.interaction_mode ?? 'INTERACTIVE',
    defense_mode: params.defense_mode ?? 'INPUT',
    dataset_catalog_id: params.dataset_catalog_id ?? 'JBB_HARMFUL_BENIGN_V1',
    strategy_version_id: params.strategy_version_id,
    budget_profile_id: params.budget_profile_id ?? 'DEMO_500_TURNS_BUDGET',
    rubric_version_id: params.rubric_version_id,
    limits,
    versions,
    manifest_digest,
    witness_receipt,
  };
}

/**
 * Generates the full set of multi-arena fixtures deterministically
 */
export function generateArenaFixtures(): Record<string, MockArenaData> {
  const rng = new DeterministicRng(1337);

  // ─────────────────────────────────────────────────────────────
  // 1. RUNNING ARENA: exp_running_01 (BAYORA-PROD-01)
  // ─────────────────────────────────────────────────────────────
  const expRunningId = 'exp_running_01';
  const runningManifest = buildMockManifest({
    domain: 'BAYORA-PROD-01',
    experiment_id: expRunningId,
    epoch: 4 as Epoch,
    profile: 'CONTROLLED_FEEDBACK',
    created_at: '2026-10-19T08:14:00Z',
  });

  const runningLedger: ArenaEvent[] = [];
  const runningAttempts: Attempt[] = [];

  // Genesis setup events
  appendEventToLedger(runningLedger, {
    experiment: expRunningId,
    epoch: 4 as Epoch,
    actor: 'operator',
    action: 'manifest_sealed',
    outcome: 'ok',
    artifacts: [runningManifest.manifest_digest],
    versions: runningManifest.versions,
    ts_utc: '2026-10-19T08:14:02Z',
    mono_ms: 100,
  });

  appendEventToLedger(runningLedger, {
    experiment: expRunningId,
    epoch: 4 as Epoch,
    actor: 'broker',
    action: 'preflight_passed',
    outcome: 'VALID_WITHIN_PROFILE',
    artifacts: [],
    versions: runningManifest.versions,
    ts_utc: '2026-10-19T08:14:05Z',
    mono_ms: 1450,
  });

  // Generate 12 executed turns
  for (let turn = 1; turn <= 12; turn++) {
    const defenseMs = rng.nextInt(45, 180);
    const targetMs = rng.nextInt(320, 1100);
    const isBlocked = turn % 4 === 0;

    const attackArtifactDigest = sha256Digest(`attack:${expRunningId}:turn:${turn}`);
    const defenseArtifactDigest = sha256Digest(`defense:${expRunningId}:turn:${turn}`);

    appendEventToLedger(runningLedger, {
      experiment: expRunningId,
      epoch: 4 as Epoch,
      actor: 'red',
      action: 'attack_submitted',
      outcome: 'ok',
      artifacts: [attackArtifactDigest],
      versions: runningManifest.versions,
      ts_utc: `2026-10-19T08:15:${String(turn * 3).padStart(2, '0')}Z`,
      mono_ms: 2000 + turn * 3000,
    });

    appendEventToLedger(runningLedger, {
      experiment: expRunningId,
      epoch: 4 as Epoch,
      actor: 'blue',
      action: 'defense_filtered',
      outcome: isBlocked ? 'BLOCKED_BY_DEFENSE' : 'ALLOWED',
      artifacts: [defenseArtifactDigest],
      versions: runningManifest.versions,
      ts_utc: `2026-10-19T08:15:${String(turn * 3 + 1).padStart(2, '0')}Z`,
      mono_ms: 2000 + turn * 3000 + defenseMs,
    });

    runningAttempts.push({
      request_id: `req_${expRunningId}_${turn}`,
      turn,
      // pipeline_disposition carries the defense verdict (backend: Disposition enum)
      // model_execution carries execution fact (backend: Execution enum — no BLOCKED_BY_DEFENSE here)
      pipeline_disposition: isBlocked ? 'BLOCKED_BY_DEFENSE' : 'ALLOWED',
      model_execution: isBlocked ? 'NOT_EVALUATED' : 'EXECUTED', // INPUT-mode block → model never called
      scoring: isBlocked ? 'NOT_EVALUATED' : 'SCORED',
      integrity: 'VALID_WITHIN_PROFILE',
      latency_ms: {
        defense: defenseMs,
        target: isBlocked ? 0 : targetMs,
        total: isBlocked ? defenseMs : defenseMs + targetMs,
      },
      input_digest: attackArtifactDigest,
    });
  }

  // ─────────────────────────────────────────────────────────────
  // 2. SEALED ARENA: exp_sealed_02 (BAYORA-SEC-02)
  // ─────────────────────────────────────────────────────────────
  const expSealedId = 'exp_sealed_02';
  const sealedManifest = buildMockManifest({
    domain: 'BAYORA-SEC-02',
    experiment_id: expSealedId,
    epoch: 1 as Epoch,
    profile: 'SEALED_BATCH',
    created_at: '2026-10-19T09:30:00Z',
    versions: {
      target_model: 'mistralai/Mistral-7B-v0.3',
      defense_runtime: 'Llama-Guard-3',
    },
  });

  const sealedLedger: ArenaEvent[] = [];
  appendEventToLedger(sealedLedger, {
    experiment: expSealedId,
    epoch: 1 as Epoch,
    actor: 'operator',
    action: 'manifest_sealed',
    outcome: 'ok',
    artifacts: [sealedManifest.manifest_digest],
    versions: sealedManifest.versions,
    ts_utc: '2026-10-19T09:30:01Z',
    mono_ms: 50,
  });

  // ─────────────────────────────────────────────────────────────
  // 3. INVALID ARENA: exp_invalid_03 (BAYORA-TEST-03)
  // ─────────────────────────────────────────────────────────────
  const expInvalidId = 'exp_invalid_03';
  const invalidManifest = buildMockManifest({
    domain: 'BAYORA-TEST-03',
    experiment_id: expInvalidId,
    epoch: 2 as Epoch,
    profile: 'CONTROLLED_FEEDBACK',
    created_at: '2026-10-19T07:00:00Z',
    versions: {
      target_model: 'Qwen/Qwen2.5-7B-Coder',
      defense_runtime: 'Custom-Regex-Proxy',
    },
  });

  const invalidLedger: ArenaEvent[] = [];
  const invalidAttempts: Attempt[] = [];

  appendEventToLedger(invalidLedger, {
    experiment: expInvalidId,
    epoch: 2 as Epoch,
    actor: 'operator',
    action: 'manifest_sealed',
    outcome: 'ok',
    artifacts: [invalidManifest.manifest_digest],
    versions: invalidManifest.versions,
    ts_utc: '2026-10-19T07:00:01Z',
    mono_ms: 10,
  });

  // Turn 1 ok
  const t1Attack = sha256Digest(`attack:${expInvalidId}:turn:1`);
  appendEventToLedger(invalidLedger, {
    experiment: expInvalidId,
    epoch: 2 as Epoch,
    actor: 'red',
    action: 'attack_submitted',
    outcome: 'ok',
    artifacts: [t1Attack],
    versions: invalidManifest.versions,
    ts_utc: '2026-10-19T07:00:10Z',
    mono_ms: 1000,
  });
  invalidAttempts.push({
    request_id: `req_${expInvalidId}_1`,
    turn: 1,
    model_execution: 'EXECUTED',
    scoring: 'SCORED',
    integrity: 'VALID_WITHIN_PROFILE',
    latency_ms: { defense: 80, target: 500, total: 580 },
    input_digest: t1Attack,
  });

  // Turn 2: Defense Timeout! Exceeded 1000ms deadline (1002ms)
  const t2Attack = sha256Digest(`attack:${expInvalidId}:turn:2`);
  appendEventToLedger(invalidLedger, {
    experiment: expInvalidId,
    epoch: 2 as Epoch,
    actor: 'red',
    action: 'attack_submitted',
    outcome: 'ok',
    artifacts: [t2Attack],
    versions: invalidManifest.versions,
    ts_utc: '2026-10-19T07:00:20Z',
    mono_ms: 2000,
  });

  appendEventToLedger(invalidLedger, {
    experiment: expInvalidId,
    epoch: 2 as Epoch,
    actor: 'blue',
    action: 'defense_filtered',
    outcome: 'DEADLINE_EXCEEDED',
    artifacts: [],
    versions: invalidManifest.versions,
    ts_utc: '2026-10-19T07:00:21Z',
    mono_ms: 3002, // 1002 ms defense latency
  });

  appendEventToLedger(invalidLedger, {
    experiment: expInvalidId,
    epoch: 2 as Epoch,
    actor: 'broker',
    action: 'attempt_invalidated',
    outcome: 'INVALID',
    artifacts: [],
    versions: invalidManifest.versions,
    ts_utc: '2026-10-19T07:00:22Z',
    mono_ms: 3010,
  });

  invalidAttempts.push({
    request_id: `req_${expInvalidId}_2`,
    turn: 2,
    model_execution: 'UNKNOWN',
    scoring: 'FAILED',
    integrity: 'INVALID',
    latency_ms: { defense: 1002, target: 0, total: 1002 },
    input_digest: t2Attack,
  });

  const invalidChainResult = verifyEventChain(invalidLedger);
  const invalidFinalDigest = invalidChainResult.finalDigest as Digest;
  const invalidCheckpoint = createSignedCheckpoint({
    experiment: expInvalidId,
    epoch: 2 as Epoch,
    count: invalidLedger.length,
    final_digest: invalidFinalDigest,
    manifest_digest: invalidManifest.manifest_digest,
  });

  // ─────────────────────────────────────────────────────────────
  // 4. RELEASED ARENA: exp_released_04 (BAYORA-EVAL-04)
  // ─────────────────────────────────────────────────────────────
  const expReleasedId = 'exp_released_04';
  const releasedManifest = buildMockManifest({
    domain: 'BAYORA-EVAL-04',
    experiment_id: expReleasedId,
    epoch: 5 as Epoch,
    profile: 'SEALED_BATCH',
    created_at: '2026-10-18T12:00:00Z',
    versions: {
      target_model: 'meta-llama/Llama-3-70B',
      defense_runtime: 'blindshield-defense-v2.0',
    },
  });

  const releasedLedger: ArenaEvent[] = [];
  const releasedAttempts: Attempt[] = [];

  appendEventToLedger(releasedLedger, {
    experiment: expReleasedId,
    epoch: 5 as Epoch,
    actor: 'operator',
    action: 'manifest_sealed',
    outcome: 'ok',
    artifacts: [releasedManifest.manifest_digest],
    versions: releasedManifest.versions,
    ts_utc: '2026-10-18T12:00:01Z',
    mono_ms: 10,
  });

  for (let turn = 1; turn <= 20; turn++) {
    const defenseMs = rng.nextInt(50, 150);
    const targetMs = rng.nextInt(300, 900);
    const isBlocked = turn % 3 === 0;

    const attackDigest = sha256Digest(`attack:${expReleasedId}:turn:${turn}`);
    const defenseDigest = sha256Digest(`defense:${expReleasedId}:turn:${turn}`);

    appendEventToLedger(releasedLedger, {
      experiment: expReleasedId,
      epoch: 5 as Epoch,
      actor: 'red',
      action: 'attack_submitted',
      outcome: 'ok',
      artifacts: [attackDigest],
      versions: releasedManifest.versions,
      ts_utc: `2026-10-18T12:01:${String(turn).padStart(2, '0')}Z`,
      mono_ms: 1000 + turn * 2000,
    });

    appendEventToLedger(releasedLedger, {
      experiment: expReleasedId,
      epoch: 5 as Epoch,
      actor: 'blue',
      action: 'defense_filtered',
      outcome: isBlocked ? 'BLOCKED_BY_DEFENSE' : 'ALLOWED',
      artifacts: [defenseDigest],
      versions: releasedManifest.versions,
      ts_utc: `2026-10-18T12:01:${String(turn + 1).padStart(2, '0')}Z`,
      mono_ms: 1000 + turn * 2000 + defenseMs,
    });

    releasedAttempts.push({
      request_id: `req_${expReleasedId}_${turn}`,
      turn,
      // pipeline_disposition carries the defense verdict (backend: Disposition enum)
      // model_execution carries execution fact (backend: Execution enum — no BLOCKED_BY_DEFENSE here)
      pipeline_disposition: isBlocked ? 'BLOCKED_BY_DEFENSE' : 'ALLOWED',
      model_execution: isBlocked ? 'NOT_EVALUATED' : 'EXECUTED', // INPUT-mode block → model never called
      scoring: isBlocked ? 'NOT_EVALUATED' : 'SCORED',
      integrity: 'VALID_WITHIN_PROFILE',
      latency_ms: {
        defense: defenseMs,
        target: isBlocked ? 0 : targetMs,
        total: isBlocked ? defenseMs : defenseMs + targetMs,
      },
      input_digest: attackDigest,
    });
  }

  // Final checkpoint for released experiment
  const releasedChainResult = verifyEventChain(releasedLedger);
  const releasedFinalDigest = releasedChainResult.finalDigest as Digest;
  const releasedCheckpoint = createSignedCheckpoint({
    experiment: expReleasedId,
    epoch: 5 as Epoch,
    count: releasedLedger.length,
    final_digest: releasedFinalDigest,
    manifest_digest: releasedManifest.manifest_digest,
  });

  return {
    [expRunningId]: {
      experiment_id: expRunningId,
      domain: 'BAYORA-PROD-01',
      epoch: 4 as Epoch,
      state: 'RUNNING',
      profile: 'CONTROLLED_FEEDBACK',
      limits: runningManifest.limits,
      versions: runningManifest.versions,
      manifest: runningManifest,
      ledger: runningLedger,
      attempts: runningAttempts,
      internalCanaries: [
        CANARY_TOKENS.RED_PRIVATE_PAYLOAD,
        CANARY_TOKENS.BLUE_DEFENSE_RULESET,
        CANARY_TOKENS.TARGET_RAW_PROMPT,
        CANARY_TOKENS.EMBARGOED_SALT,
      ],
    },
    [expSealedId]: {
      experiment_id: expSealedId,
      domain: 'BAYORA-SEC-02',
      epoch: 1 as Epoch,
      state: 'SEALED',
      profile: 'SEALED_BATCH',
      limits: sealedManifest.limits,
      versions: sealedManifest.versions,
      manifest: sealedManifest,
      ledger: sealedLedger,
      attempts: [],
      internalCanaries: [CANARY_TOKENS.EMBARGOED_SALT],
    },
    [expInvalidId]: {
      experiment_id: expInvalidId,
      domain: 'BAYORA-TEST-03',
      epoch: 2 as Epoch,
      state: 'INVALID', // Marked INVALID due to deadline exceeded
      invalid_reason: 'DEADLINE_EXCEEDED',
      profile: 'CONTROLLED_FEEDBACK',
      limits: invalidManifest.limits,
      versions: invalidManifest.versions,
      manifest: invalidManifest,
      ledger: invalidLedger,
      attempts: invalidAttempts,
      checkpoint: invalidCheckpoint,
      internalCanaries: [CANARY_TOKENS.TARGET_RAW_PROMPT],
    },
    [expReleasedId]: {
      experiment_id: expReleasedId,
      domain: 'BAYORA-EVAL-04',
      epoch: 5 as Epoch,
      state: 'RELEASED',
      profile: 'SEALED_BATCH',
      limits: releasedManifest.limits,
      versions: releasedManifest.versions,
      manifest: releasedManifest,
      ledger: releasedLedger,
      attempts: releasedAttempts,
      checkpoint: releasedCheckpoint,
      internalCanaries: [],
    },
  };
}

/**
 * Creates deterministic preflight verification report from host runtime.
 * Preflight rows:
 * 1. gVisor runsc runtime confirmed from host config
 * 2. cgroup v2 limits
 * 3. default-deny network policy enforced (IPv4/IPv6)
 * 4. dedicated cpusets
 * 5. SMT sharing off
 * 6. constant-time reply shaping
 * 7. witness reachable
 * 8. external anchor reachable
 * 9. confidential computing attestation (SEV-SNP/TDX) -> NOT ENABLED (future work)
 */
export function createMockPreflightReport(failureMode: FailureMode = 'none'): PreflightReport {
  const checks: PreflightCheck[] = [
    {
      id: 'gvisor_runsc',
      name: 'gVisor runsc runtime confirmed from host config',
      category: 'SANDBOX',
      status: 'PASS',
      isRequired: true,
      evidence_link: '/audit/host/runsc-config.json',
      detail: 'runsc version release-20240901.0 (ptrace/kvm platform active)',
      latency_ms: 12,
    },
    {
      id: 'cgroup_v2',
      name: 'cgroup v2 isolation limits',
      category: 'CONTAINMENT',
      status: 'PASS',
      isRequired: true,
      evidence_link: '/sys/fs/cgroup/bayora.slice',
      detail: 'Unified hierarchy enabled; memory.max=8G cpu.weight=100 enforced',
      latency_ms: 8,
    },
    {
      id: 'network_policy',
      name: 'Default-deny network policy enforced (IPv4/IPv6)',
      category: 'NETWORK',
      status: 'PASS',
      isRequired: true,
      evidence_link: '/etc/nftables.d/blindshield-deny.conf',
      detail: 'nftables drop-all ingress/egress active on evaluation bridge veth-arena',
      latency_ms: 15,
    },
    {
      id: 'dedicated_cpusets',
      name: 'Dedicated CPU sets pinned',
      category: 'ISOLATION',
      status: 'PASS',
      isRequired: true,
      evidence_link: '/proc/cpuinfo#cpuset-pinned',
      detail: 'Cores 0-3 pinned to broker; cores 4-7 isolated for tenant evaluation',
      latency_ms: 9,
    },
    {
      id: 'smt_disabled',
      name: 'SMT sharing off',
      category: 'CPU',
      status: 'PASS',
      isRequired: true,
      evidence_link: '/sys/devices/system/cpu/smt/control',
      detail: 'SMT status: off. Sibling hardware thread scheduling blocked',
      latency_ms: 6,
    },
    {
      id: 'constant_time_shaping',
      name: 'Constant-time reply shaping',
      category: 'SHAPING',
      status: failureMode === 'defense_timeout' ? 'FAIL' : 'PASS',
      isRequired: true,
      evidence_link: '/var/log/bayora/shaper.log',
      detail:
        failureMode === 'defense_timeout'
          ? 'Jitter envelope exceeded ±5ms shaping margin (observed 18ms)'
          : 'Fixed quantised delay buffer (50ms bucket) active',
      latency_ms: 22,
    },
    {
      id: 'witness_reachable',
      name: 'Witness reachable',
      category: 'AUDIT',
      status: failureMode === 'witness_lag' ? 'FAIL' : 'PASS',
      isRequired: true,
      evidence_link: 'witness://node-01.internal/health',
      detail:
        failureMode === 'witness_lag'
          ? 'Witness round-trip latency 3,120ms exceeds SLA maximum (2,500ms)'
          : 'Witness node-01 responding with valid Ed25519 public key',
      latency_ms: 34,
    },
    {
      id: 'external_anchor',
      name: 'External anchor reachable',
      category: 'AUDIT',
      status: failureMode === 'recorder_down' ? 'FAIL' : 'PASS',
      isRequired: true,
      evidence_link: 'anchor://sepolia.eth/contract/0x7f3a',
      detail:
        failureMode === 'recorder_down'
          ? 'Anchor RPC endpoint unreachable; connection refused'
          : 'Durable anchor confirmed on L1 block #21049281',
      latency_ms: 45,
    },
    {
      id: 'confidential_computing',
      name: 'Confidential computing attestation (SEV-SNP/TDX)',
      category: 'ATTESTATION',
      status: 'NOT_ENABLED',
      isRequired: false,
      evidence_link: '/sys/kernel/security/sev-snp',
      detail: 'Hardware attestation not enabled (future work per threat scope Q-005)',
      latency_ms: 0,
    },
  ];

  const hasFailures = checks.some((c) => c.isRequired && c.status === 'FAIL');

  return PreflightReportSchema.parse({
    overall_status: hasFailures ? 'FAIL' : 'PASS',
    timestamp_utc: new Date().toISOString(),
    host_id: 'host-arena-node-04b',
    checks,
  });
}

