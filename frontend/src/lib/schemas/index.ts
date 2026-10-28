import { z } from 'zod';

/**
 * Roles supported in BlindShield Arena demo console.
 * Backend canonical (contracts/common.py):
 *   Role = operator | red | blue-human | blue-runtime | broker | target | recorder | witness | auditor
 * Frontend mock maps the selectable user role 'blue' to the blue-human perspective.
 */
export const RoleSchema = z.enum(['operator', 'red', 'blue', 'auditor']);
export type Role = z.infer<typeof RoleSchema>;

/**
 * Invariant 5: Epoch is an exact positive integer.
 * Rejects booleans, strings, floats, zero, negative numbers, NaN.
 */
export const EpochSchema = z
  .number({
    required_error: 'Epoch is required',
    invalid_type_error: 'Epoch must be a number',
  })
  .int('Epoch must be an exact integer')
  .positive('Epoch must be a positive integer')
  // Backend common.py: MAX_INT = 2_147_483_647; enforce same bound here.
  .max(2_147_483_647, 'Epoch must be within [1, 2147483647]');
export type Epoch = z.infer<typeof EpochSchema>;

/**
 * Hex SHA-256 Digest format: sha256:<64 lowercase hex chars>
 * Note: Backend canonical wire format is raw 64 hex chars (^[0-9a-f]{64}$).
 * Frontend mock/demo uses the prefixed sha256:<64 hex> format.
 */
export const DigestSchema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/, 'Must be formatted as sha256:<64 hex chars>');
export type Digest = z.infer<typeof DigestSchema>;

/**
 * Lifecycle states from Bayora Research Playbook state machine
 */
export const LifecycleStateSchema = z.enum([
  'CREATED',
  'SEALED',
  'READY',
  'RUNNING',
  'SCORED',
  'CLOSED',
  'RELEASED',
  'INVALID',
]);
export type LifecycleState = z.infer<typeof LifecycleStateSchema>;

/**
 * Arena.v2 Pipeline Disposition (MEM-003 §4)
 * Distinct from model_execution and scoring
 */
export const PipelineDispositionSchema = z.enum([
  'PENDING',
  'ALLOWED',
  'SANITIZED',
  'BLOCKED_BY_DEFENSE',
  'INFRASTRUCTURE_FAILED',
]);
export type PipelineDisposition = z.infer<typeof PipelineDispositionSchema>;

/**
 * Arena.v2 Interaction Modes (MEM-003 §2a)
 */
export const InteractionModeSchema = z.enum(['INTERACTIVE', 'SEALED_BATCH']);
export type InteractionMode = z.infer<typeof InteractionModeSchema>;

/**
 * Arena.v2 Defense Modes (MEM-003 §2a)
 */
export const DefenseModeSchema = z.enum(['INPUT', 'FEATURES', 'OUTPUT', 'POST_HOC']);
export type DefenseMode = z.infer<typeof DefenseModeSchema>;

/**
 * Arena.v2 Blue Defense finite symbol channel (MEM-003 §2a, §5, §Bounded collusion analysis)
 * Exactly 9 allowed combinations:
 * - ALLOW / NONE / null
 * - BLOCK with 5 reasons / null
 * - SANITIZE with 3 reasons / REDACT_REGISTERED_MATCHES_V1
 */
export const BlueDefenseVerdictSchema = z.enum(['ALLOW', 'BLOCK', 'SANITIZE']);
export type BlueDefenseVerdict = z.infer<typeof BlueDefenseVerdictSchema>;

export const BlueDefenseReasonSchema = z.enum([
  'NONE',
  'INJECTION_PATTERN',
  'TOXICITY_PATTERN',
  'SCHEMA_POLICY',
  'UNSUPPORTED',
  'BUDGET_POLICY',
]);
export type BlueDefenseReason = z.infer<typeof BlueDefenseReasonSchema>;

export const BlueDefenseTransformSchema = z.literal('REDACT_REGISTERED_MATCHES_V1');
export type BlueDefenseTransform = z.infer<typeof BlueDefenseTransformSchema>;

export const BlueDefenseDecisionTupleSchema = z.discriminatedUnion('verdict', [
  z.object({
    verdict: z.literal('ALLOW'),
    reason_code: z.literal('NONE'),
    transform_id: z.null(),
  }),
  z.object({
    verdict: z.literal('BLOCK'),
    reason_code: z.enum([
      'INJECTION_PATTERN',
      'TOXICITY_PATTERN',
      'SCHEMA_POLICY',
      'UNSUPPORTED',
      'BUDGET_POLICY',
    ]),
    transform_id: z.null(),
  }),
  z.object({
    verdict: z.literal('SANITIZE'),
    reason_code: z.enum([
      'INJECTION_PATTERN',
      'TOXICITY_PATTERN',
      'SCHEMA_POLICY',
    ]),
    transform_id: BlueDefenseTransformSchema,
  }),
]);
export type BlueDefenseDecisionTuple = z.infer<typeof BlueDefenseDecisionTupleSchema>;

/**
 * Two verdicts: Model Execution Outcome
 * Backend canonical (contracts/common.py): Execution = NOT_EVALUATED | EXECUTED | UNKNOWN
 * NOTE: BLOCKED_BY_DEFENSE is a pipeline_disposition value, NOT a model_execution value.
 * When pipeline_disposition === BLOCKED_BY_DEFENSE, model_execution is either:
 *   NOT_EVALUATED (INPUT/FEATURES block — model never called)
 *   EXECUTED      (OUTPUT block — model already ran before blue decision)
 */
export const ModelExecutionStatusSchema = z.enum([
  'NOT_EVALUATED',
  'EXECUTED',
  'UNKNOWN',
]);
export type ModelExecutionStatus = z.infer<typeof ModelExecutionStatusSchema>;

/**
 * Scoring status
 */
export const ScoringStatusSchema = z.enum([
  'SCORED',
  'UNCERTAIN',
  'FAILED',
  'NOT_EVALUATED',
]);
export type ScoringStatus = z.infer<typeof ScoringStatusSchema>;

/**
 * Two verdicts: Evaluation Integrity Outcome
 */
export const IntegrityStatusSchema = z.enum([
  'PENDING',
  'VALID_WITHIN_PROFILE',
  'INVALID',
]);
export type IntegrityStatus = z.infer<typeof IntegrityStatusSchema>;

/**
 * Disclosure and access classification
 */
export const AccessStatusSchema = z.enum([
  'EMBARGOED',
  'UNAVAILABLE',
  'DELAYED',
  'RELEASED',
]);
export type AccessStatus = z.infer<typeof AccessStatusSchema>;

/**
 * Feedback Profile (Spec correction C-07)
 */
export const FeedbackProfileSchema = z.enum([
  'SEALED_BATCH',
  'CONTROLLED_FEEDBACK',
]);
export type FeedbackProfile = z.infer<typeof FeedbackProfileSchema>;

/**
 * Standard API error codes matching backend ErrorCode (contracts/common.py).
 * Backend canonical set: INVALID_SCHEMA | UNAUTHORIZED | FORBIDDEN | NOT_FOUND |
 *   WRONG_PHASE | STALE_EPOCH | VERSION_MISMATCH | IDEMPOTENCY_CONFLICT |
 *   BODY_TOO_LARGE | RESOURCE_BUDGET_EXCEEDED | AUDIT_UNAVAILABLE |
 *   MODEL_UNAVAILABLE | POLICY_NOT_READY | DEADLINE_EXCEEDED
 */
export const ErrorCodeSchema = z.enum([
  'INVALID_SCHEMA',
  'UNAUTHORIZED',
  'FORBIDDEN',
  'NOT_FOUND',
  'WRONG_PHASE',
  'STALE_EPOCH',
  'VERSION_MISMATCH',
  'IDEMPOTENCY_CONFLICT',
  'BODY_TOO_LARGE',
  'RESOURCE_BUDGET_EXCEEDED',
  'AUDIT_UNAVAILABLE',
  'MODEL_UNAVAILABLE',
  'POLICY_NOT_READY',
  'DEADLINE_EXCEEDED',
]);
export type ErrorCode = z.infer<typeof ErrorCodeSchema>;

/**
 * Api Error Response DTO
 */
export const ApiErrorSchema = z
  .object({
    code: ErrorCodeSchema,
    message: z.string(),
    request_id: z.string().min(1),
  })
  .strict();
export type ApiError = z.infer<typeof ApiErrorSchema>;

/**
 * Latency breakdown in milliseconds
 */
export const LatencyMsSchema = z
  .object({
    defense: z.number().nonnegative(),
    target: z.number().nonnegative(),
    total: z.number().nonnegative(),
  })
  .strict();
export type LatencyMs = z.infer<typeof LatencyMsSchema>;

/**
 * Single evaluation attempt inside an experiment
 */
export const AttemptSchema = z
  .object({
    request_id: z.string().min(1),
    turn: z.number().int().positive(),
    pipeline_disposition: PipelineDispositionSchema.optional(),
    model_execution: ModelExecutionStatusSchema,
    scoring: ScoringStatusSchema,
    integrity: IntegrityStatusSchema,
    latency_ms: LatencyMsSchema,
    input_digest: DigestSchema.optional(), // Operator/Auditor only post-release
  })
  .strict();
export type Attempt = z.infer<typeof AttemptSchema>;

/**
 * Disclosure metadata for field visibility
 */
export const DisclosureSchema = z
  .object({
    visible: z.boolean(),
    reason: z.enum(['EMBARGOED', 'DELAYED', 'RELEASED', 'ROLE']),
    release_at: z.string().optional(),
  })
  .strict();
export type Disclosure = z.infer<typeof DisclosureSchema>;

/**
 * Event in the tamper-evident hash chain ledger
 */
export const EventSchema = z
  .object({
    schema: z.literal('v1'),
    experiment: z.string().min(1),
    epoch: EpochSchema,
    seq: z.number().int().min(1),
    prev: z.union([DigestSchema, z.literal('genesis')]),
    actor: z.string().min(1),
    action: z.string().min(1),
    outcome: z.string().min(1),
    artifacts: z.array(DigestSchema),
    versions: z.record(z.string()),
    ts_utc: z.string().min(1),
    mono_ms: z.number().nonnegative(),
  })
  .strict();
export type ArenaEvent = z.infer<typeof EventSchema>;

/**
 * Terminal Checkpoint signed by the recorder/witness
 */
export const CheckpointSchema = z
  .object({
    experiment: z.string().min(1),
    epoch: EpochSchema,
    count: z.number().int().nonnegative(),
    final_digest: DigestSchema,
    manifest_digest: DigestSchema,
    protocol: z.string().min(1),
    key_id: z.string().min(1),
    signature: z.string().min(1),
    witness_receipt: z.string().min(1),
    terminal: z.literal(true),
  })
  .strict();
export type Checkpoint = z.infer<typeof CheckpointSchema>;

/**
 * Arena runtime limits configuration
 */
export const LimitsSchema = z
  .object({
    body_max_bytes: z.number().int().positive(),
    text_max_bytes: z.number().int().positive(),
    output_max_tokens: z.number().int().positive(),
    defense_deadline_ms: z.number().int().positive(),
    target_deadline_ms: z.number().int().positive(),
  })
  .strict();
export type Limits = z.infer<typeof LimitsSchema>;

/**
 * Pinned system component versions
 */
export const VersionsSchema = z
  .object({
    target_model: z.string().min(1),
    defense_runtime: z.string().min(1),
    broker: z.string().min(1),
    recorder: z.string().min(1),
  })
  .strict();
export type Versions = z.infer<typeof VersionsSchema>;

/**
 * Immutable Experiment Manifest
 */
export const AssuranceLaneSchema = z.enum(['shared_host_gvisor', 'separated_host']);
export type AssuranceLane = z.infer<typeof AssuranceLaneSchema>;

/**
 * Preflight check verification status
 */
export const PreflightStatusSchema = z.enum(['PASS', 'FAIL', 'PENDING', 'NOT_ENABLED']);
export type PreflightStatus = z.infer<typeof PreflightStatusSchema>;

/**
 * Individual preflight verification item
 */
export const PreflightCheckSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    category: z.string().min(1),
    status: PreflightStatusSchema,
    isRequired: z.boolean(),
    evidence_link: z.string().min(1),
    detail: z.string(),
    latency_ms: z.number().nonnegative().optional(),
  })
  .strict();
export type PreflightCheck = z.infer<typeof PreflightCheckSchema>;

/**
 * Complete preflight verification report from host runtime
 */
export const PreflightReportSchema = z
  .object({
    overall_status: z.enum(['PASS', 'FAIL', 'PENDING']),
    timestamp_utc: z.string().min(1),
    host_id: z.string().min(1),
    checks: z.array(PreflightCheckSchema),
  })
  .strict();
export type PreflightReport = z.infer<typeof PreflightReportSchema>;

/**
 * Immutable Experiment Manifest
 */
export const ManifestSchema = z
  .object({
    domain: z.string().min(1),
    experiment_id: z.string().min(1),
    epoch: EpochSchema,
    created_at: z.string().min(1),
    protocol_version: z.string().min(1),
    profile: FeedbackProfileSchema,
    interaction_mode: InteractionModeSchema.optional().default('INTERACTIVE'),
    defense_mode: DefenseModeSchema.optional().default('INPUT'),
    dataset_catalog_id: z.string().optional(),
    strategy_version_id: z.string().optional(),
    budget_profile_id: z.string().optional(),
    rubric_version_id: z.string().optional(),
    limits: LimitsSchema,
    versions: VersionsSchema,
    manifest_digest: DigestSchema,
    witness_receipt: z.string().min(1),
    assurance_lane: AssuranceLaneSchema.optional(),
  })
  .strict();
export type Manifest = z.infer<typeof ManifestSchema>;

/**
 * Request payload to create an experiment
 */
export const CreateExperimentRequestSchema = z
  .object({
    domain: z.string().min(1),
    epoch: EpochSchema.optional().default(1),
    profile: FeedbackProfileSchema.optional().default('SEALED_BATCH'),
    interaction_mode: InteractionModeSchema.optional().default('INTERACTIVE'),
    defense_mode: DefenseModeSchema.optional().default('INPUT'),
    dataset_catalog_id: z.string().optional(),
    strategy_version_id: z.string().optional(),
    budget_profile_id: z.string().optional(),
    rubric_version_id: z.string().optional(),
    limits: LimitsSchema.partial().optional(),
    versions: VersionsSchema.partial().optional(),
    assurance_lane: AssuranceLaneSchema.optional().default('shared_host_gvisor'),
    manifest_draft: z.record(z.unknown()).optional(),
  })
  .strict();
export type CreateExperimentRequest = z.input<typeof CreateExperimentRequestSchema>;

/**
 * Response payload from creating an experiment
 */
export const CreateExperimentResponseSchema = z
  .object({
    experiment_id: z.string().min(1),
    epoch: EpochSchema,
    state: LifecycleStateSchema,
    manifest_digest: DigestSchema,
    witness_receipt: z.string().min(1).optional(),
    created_at: z.string().optional(),
  })
  .strict();
export type CreateExperimentResponse = z.infer<typeof CreateExperimentResponseSchema>;

/**
 * Attack submission request
 */
export const SubmitAttackRequestSchema = z
  .object({
    text_artifact: z.string().min(1),
    commitment: DigestSchema,
    nonce: z.string().min(1),
  })
  .strict();
export type SubmitAttackRequest = z.infer<typeof SubmitAttackRequestSchema>;

/**
 * Receipt returned on attack submission
 */
export const AttackReceiptSchema = z
  .object({
    receipt_id: z.string().min(1),
    experiment_id: z.string().min(1),
    turn: z.number().int().positive(),
    timestamp_utc: z.string().min(1),
    commitment_digest: DigestSchema,
  })
  .strict();
export type AttackReceipt = z.infer<typeof AttackReceiptSchema>;

/**
 * Response payload on starting an experiment
 */
export const StartExperimentResponseSchema = z
  .object({
    experiment_id: z.string().min(1),
    state: LifecycleStateSchema,
    durable_start_receipt: z.string().min(1),
  })
  .strict();
export type StartExperimentResponse = z.infer<typeof StartExperimentResponseSchema>;

/**
 * Response payload on closing an experiment
 */
export const CloseExperimentResponseSchema = z
  .object({
    experiment_id: z.string().min(1),
    state: LifecycleStateSchema,
    checkpoint: CheckpointSchema,
  })
  .strict();
export type CloseExperimentResponse = z.infer<typeof CloseExperimentResponseSchema>;

/**
 * Role-filtered experiment status summary
 */
export const ExperimentStatusSchema = z
  .object({
    experiment_id: z.string().min(1),
    domain: z.string().min(1),
    epoch: EpochSchema,
    state: LifecycleStateSchema,
    profile: FeedbackProfileSchema,
    current_turn: z.number().int().nonnegative(),
    attempts_count: z.number().int().nonnegative(),
    valid_attempts_count: z.number().int().nonnegative(),
    invalid_attempts_count: z.number().int().nonnegative(),
    blocked_attempts_count: z.number().int().nonnegative().optional(),
    target_model: z.string().optional(),
    defense_guardrail: z.string().optional(),
    integrity_status: IntegrityStatusSchema.optional(),
    invalid_reason: z.string().optional(),
    p95_broker_latency_ms: z.number().optional(),
    latest_digest: DigestSchema,
    manifest_digest: DigestSchema,
    witness_status: z.enum(['SYNCED', 'LAGGING', 'OFFLINE']),
    updated_at: z.string().min(1),
    delayed: z.boolean().default(false),
    delay_label: z.string().optional(),
  })
  .strict();
export type ExperimentStatus = z.infer<typeof ExperimentStatusSchema>;

/**
 * Role-filtered feedback item
 */
export const FeedbackItemSchema = z
  .object({
    turn: z.number().int().positive(),
    request_id: z.string().min(1),
    pipeline_disposition: PipelineDispositionSchema.optional(),
    model_execution: ModelExecutionStatusSchema.optional(),
    scoring: ScoringStatusSchema.optional(),
    integrity: IntegrityStatusSchema.optional(),
    latency_bucket_ms: z.number().optional(), // Coarse 50ms bucket for non-operators
    latency_ms: LatencyMsSchema.optional(), // Full breakdown for operators
    defense_status: z.string().optional(),
    disclosure: DisclosureSchema,
  })
  .strict();
export type FeedbackItem = z.infer<typeof FeedbackItemSchema>;

/**
 * Full Evidence Bundle Metadata (Auditor inspection)
 */
export const EvidenceBundleMetadataSchema = z
  .object({
    experiment_id: z.string().min(1),
    domain: z.string().min(1),
    epoch: EpochSchema,
    state: LifecycleStateSchema,
    manifest: ManifestSchema,
    checkpoint: CheckpointSchema,
    events_count: z.number().int().nonnegative(),
    generated_at: z.string().min(1),
    auditor_key_id: z.string().min(1),
  })
  .strict();
export type EvidenceBundleMetadata = z.infer<typeof EvidenceBundleMetadataSchema>;

/**
 * Post-release forensic turn inspection record (Blue Console §5.7 / P09 / MEM-003 §2a)
 */
export const ForensicTurnRecordSchema = z
  .object({
    turn: z.number().int().positive(),
    request_id: z.string().min(1),
    attack_payload: z.string().min(1),
    matched_rule: z.string().min(1),
    confidence: z.number().min(0).max(1),
    decision: z.enum(['BLOCKED_BY_DEFENSE', 'ALLOWED', 'SANITIZED']),
    transform_id: z.string().nullable().optional(),
    scorer_ground_truth: z.enum(['UNSAFE', 'SAFE', 'BENIGN']),
    model_response: z.string().optional(),
    latency_ms: LatencyMsSchema,
    defense_digest: DigestSchema,
  })
  .strict();
export type ForensicTurnRecord = z.infer<typeof ForensicTurnRecordSchema>;

/**
 * Forensics report for a released epoch (Forensics Workshop §5.7)
 */
export const ReleasedEpochForensicsSchema = z
  .object({
    experiment_id: z.string().min(1),
    epoch: EpochSchema,
    state: LifecycleStateSchema,
    total_turns: z.number().int().nonnegative(),
    blocked_count: z.number().int().nonnegative(),
    allowed_count: z.number().int().nonnegative(),
    turns: z.array(ForensicTurnRecordSchema),
  })
  .strict();
export type ReleasedEpochForensics = z.infer<typeof ReleasedEpochForensicsSchema>;

/**
 * Blue defense readiness probe status
 */
export const DefenseProbeSchema = z
  .object({
    id: z.string().min(1),
    name: z.string().min(1),
    status: z.enum(['PASS', 'FAIL', 'PENDING']),
    latency_ms: z.number().nonnegative(),
    detail: z.string(),
  })
  .strict();
export type DefenseProbe = z.infer<typeof DefenseProbeSchema>;

/**
 * Blue defense artifact envelope & status
 */
export const DefenseArtifactInfoSchema = z
  .object({
    name: z.string().min(1),
    version: z.string().min(1),
    digest: DigestSchema,
    runtime_lane: z.string().min(1),
    memory_limit_mb: z.number().int().positive(),
    status: z.enum(['FROZEN & SEALED', 'INVALID', 'UNSEALED']),
    probes: z.array(DefenseProbeSchema),
  })
  .strict();
export type DefenseArtifactInfo = z.infer<typeof DefenseArtifactInfoSchema>;
