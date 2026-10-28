import { z } from 'zod';

// ─── Wilson 95% CI helper ────────────────────────────────────────────────────
/**
 * Wilson score interval for a proportion p = k/n at 95% confidence.
 * Returns [lo, hi] clamped to [0, 1].
 * Never call with n = 0 — use INSUFFICIENT_DATA state instead.
 */
export function wilsonCI(k: number, n: number): [number, number] {
  if (n === 0) return [0, 0];
  const z = 1.96; // z_{0.975}
  const p = k / n;
  const denom = 1 + (z * z) / n;
  const centre = (p + z * z / (2 * n)) / denom;
  const spread = (z * Math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)) / denom;
  return [Math.max(0, centre - spread), Math.min(1, centre + spread)];
}

// ─── Attack family ────────────────────────────────────────────────────────────
export const AttackFamilySchema = z.enum([
  'PROMPT_INJECTION',
  'JAILBREAK',
  'ROLE_ESCALATION',
  'DENY_ALL_BASELINE', // The negative "always-block" reference baseline
]);
export type AttackFamily = z.infer<typeof AttackFamilySchema>;

// ─── Per-arm attack rate row ──────────────────────────────────────────────────
export const AttackRateRowSchema = z
  .object({
    family: AttackFamilySchema,
    n_total: z.number().int().nonnegative(),
    n_blocked: z.number().int().nonnegative(),
    n_invalid: z.number().int().nonnegative(),
    /** Number that reached the model (n_total - n_blocked - n_invalid) */
    n_passed: z.number().int().nonnegative(),
    /** Raw model success rate with defence disabled (reference arm) */
    raw_success_rate: z.number().min(0).max(1),
    /** Defended success rate (post-defense) */
    defended_success_rate: z.number().min(0).max(1),
    /** Wilson 95% CI for defended_success_rate */
    ci_lo: z.number().min(0).max(1),
    ci_hi: z.number().min(0).max(1),
  })
  .strict();
export type AttackRateRow = z.infer<typeof AttackRateRowSchema>;

// ─── Latency measurement path ─────────────────────────────────────────────────
export const LatencyPathSchema = z
  .object({
    label: z.string().min(1),
    /** Measured p95 in ms for this path */
    p95_ms: z.number().nonnegative(),
    /** Measured median in ms */
    p50_ms: z.number().nonnegative(),
    /** Target gate in ms — display as TARGET not a promise */
    target_gate_ms: z.number().nonnegative(),
    /** Whether p95 is within the gate */
    within_gate: z.boolean(),
    n_samples: z.number().int().nonnegative(),
  })
  .strict();
export type LatencyPath = z.infer<typeof LatencyPathSchema>;

// ─── Cache distinguishability arm ────────────────────────────────────────────
export const CacheArmSchema = z.enum(['cache_off', 'salted_shared', 'dedicated']);
export type CacheArm = z.infer<typeof CacheArmSchema>;

export const RocArmSchema = z
  .object({
    arm: CacheArmSchema,
    auc: z.number().min(0).max(1),
    ci_lo: z.number().min(0).max(1),
    ci_hi: z.number().min(0).max(1),
    n_samples: z.number().int().nonnegative(),
    /** If true, the weak-baseline AUC shows no signal — render INCONCLUSIVE */
    inconclusive: z.boolean(),
  })
  .strict();
export type RocArm = z.infer<typeof RocArmSchema>;

// ─── Covert-channel capacity card ────────────────────────────────────────────
export const CovertChannelCardSchema = z
  .object({
    bound_bits_per_query: z.number().nonnegative().nullable(), // null → NOT MEASURED
    n_queries: z.number().int().nonnegative().nullable(),
    method: z.string().nullable(),
    microarch_status: z.enum(['NOT MEASURED', 'PARTIAL', 'BOUNDED']),
  })
  .strict();
export type CovertChannelCard = z.infer<typeof CovertChannelCardSchema>;

// ─── Summary counts ───────────────────────────────────────────────────────────
export const InvalidReasonSchema = z.enum([
  'DEADLINE_EXCEEDED',
  'RECORDER_DOWN',
  'STALE_EPOCH',
  'WITNESS_LAG',
  'SCHEMA_VIOLATION',
  'OTHER',
]);
export type InvalidReason = z.infer<typeof InvalidReasonSchema>;

export const SummaryTableSchema = z
  .object({
    n_admitted: z.number().int().nonnegative(),
    n_valid: z.number().int().nonnegative(),
    n_invalid: z.number().int().nonnegative(),
    invalid_by_reason: z.record(InvalidReasonSchema, z.number().int().nonnegative()),
    deny_all_score: z.number().min(0).max(1).nullable(), // null → insufficient data
  })
  .strict();
export type SummaryTable = z.infer<typeof SummaryTableSchema>;

// ─── Full BenchmarkDataset (importable via JSON dropzone) ────────────────────
export const BenchmarkDatasetSchema = z
  .object({
    schema_version: z.literal('benchmarks.v1'),
    experiment_id: z.string().min(1),
    generated_at: z.string().min(1),
    illustrative: z.boolean(),
    attack_rates: z.array(AttackRateRowSchema).min(1),
    latency_paths: z.array(LatencyPathSchema).min(1),
    roc_arms: z.array(RocArmSchema).min(1),
    covert_channel: CovertChannelCardSchema,
    summary: SummaryTableSchema,
  })
  .strict();
export type BenchmarkDataset = z.infer<typeof BenchmarkDatasetSchema>;
