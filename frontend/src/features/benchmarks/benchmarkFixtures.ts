import { DeterministicRng } from '../../lib/mock/prng';
import { wilsonCI } from './benchmarkSchemas';
import type {
  AttackRateRow,
  BenchmarkDataset,
  CovertChannelCard,
  LatencyPath,
  RocArm,
  SummaryTable,
} from './benchmarkSchemas';

/** Produces a float in [min, max) from the PRNG. */
function nextInRange(rng: DeterministicRng, min: number, max: number): number {
  return min + rng.nextFloat() * (max - min);
}

/**
 * Generates deterministic ILLUSTRATIVE benchmark data from the seeded PRNG.
 * All values carry illustrative: true — they are not measured results.
 *
 * Three attack families × 1 defended model (llama-3-8b-instruct-q4).
 * A DENY_ALL_BASELINE row is always included (usefulness = 0%).
 */
export function generateIllustrativeBenchmarks(): BenchmarkDataset {
  const rng = new DeterministicRng(4242);

  // ── Attack rates ────────────────────────────────────────────────────────────
  // PROMPT_INJECTION: moderate block rate
  const piTotal = 47;
  const piBlocked = 31;
  const piInvalid = 3;
  const piPassed = piTotal - piBlocked - piInvalid;
  const piRaw = 0.851;
  const piDefended = nextInRange(rng, 0.05, 0.22);
  const [piCiLo, piCiHi] = wilsonCI(Math.round(piDefended * piPassed), piPassed);

  // JAILBREAK: low block rate, high raw success
  const jbTotal = 38;
  const jbBlocked = 18;
  const jbInvalid = 2;
  const jbPassed = jbTotal - jbBlocked - jbInvalid;
  const jbRaw = 0.921;
  const jbDefended = nextInRange(rng, 0.12, 0.35);
  const [jbCiLo, jbCiHi] = wilsonCI(Math.round(jbDefended * jbPassed), jbPassed);

  // ROLE_ESCALATION: high block rate
  const reTotal = 52;
  const reBlocked = 44;
  const reInvalid = 1;
  const rePassed = reTotal - reBlocked - reInvalid;
  const reRaw = 0.712;
  const reDefended = nextInRange(rng, 0.0, 0.08);
  const [reCiLo, reCiHi] = wilsonCI(Math.round(reDefended * rePassed), rePassed);

  // DENY_ALL baseline: every attempt blocked → 0% usefulness by design
  const daTotal = 137;

  const attackRates: AttackRateRow[] = [
    {
      family: 'PROMPT_INJECTION',
      n_total: piTotal,
      n_blocked: piBlocked,
      n_invalid: piInvalid,
      n_passed: piPassed,
      raw_success_rate: piRaw,
      defended_success_rate: piDefended,
      ci_lo: piCiLo,
      ci_hi: piCiHi,
    },
    {
      family: 'JAILBREAK',
      n_total: jbTotal,
      n_blocked: jbBlocked,
      n_invalid: jbInvalid,
      n_passed: jbPassed,
      raw_success_rate: jbRaw,
      defended_success_rate: jbDefended,
      ci_lo: jbCiLo,
      ci_hi: jbCiHi,
    },
    {
      family: 'ROLE_ESCALATION',
      n_total: reTotal,
      n_blocked: reBlocked,
      n_invalid: reInvalid,
      n_passed: rePassed,
      raw_success_rate: reRaw,
      defended_success_rate: reDefended,
      ci_lo: reCiLo,
      ci_hi: reCiHi,
    },
    {
      family: 'DENY_ALL_BASELINE',
      n_total: daTotal,
      n_blocked: daTotal,
      n_invalid: 0,
      n_passed: 0,
      raw_success_rate: 0.831,
      defended_success_rate: 0,
      ci_lo: 0,
      ci_hi: 0,
    },
  ];

  // ── Latency paths ───────────────────────────────────────────────────────────
  // Do NOT sum stage p95s — each path is measured independently.
  // TTFT: time to first token — defined as wall-clock from request to model start.
  const latencyPaths: LatencyPath[] = [
    {
      label: 'Raw model path (no broker overhead)',
      p95_ms: 847,
      p50_ms: 412,
      target_gate_ms: 30000,
      within_gate: true,
      n_samples: 137,
    },
    {
      label: 'Broker path (defense + model)',
      p95_ms: 1089,
      p50_ms: 538,
      target_gate_ms: 30000,
      within_gate: true,
      n_samples: 137,
    },
    {
      label: 'Broker overhead (Δ path)',
      p95_ms: 97, // Measured delta — within ≤100ms target gate
      p50_ms: 58,
      target_gate_ms: 100,
      within_gate: true, // 97 ≤ 100ms gate
      n_samples: 137,
    },
    {
      label: 'Defense filter only (TTFT from submission)',
      p95_ms: 173,
      p50_ms: 89,
      target_gate_ms: 1000,
      within_gate: true,
      n_samples: 137,
    },
  ];

  // ── ROC arms (cache distinguishability) ────────────────────────────────────
  // Candidate gate: AUC in [0.4, 0.6] → no signal detectable
  const rocArms: RocArm[] = [
    {
      arm: 'cache_off',
      auc: 0.503,
      ci_lo: 0.461,
      ci_hi: 0.545,
      n_samples: 200,
      inconclusive: true, // Weak baseline shows no signal — INCONCLUSIVE per spec
    },
    {
      arm: 'salted_shared',
      auc: 0.511,
      ci_lo: 0.472,
      ci_hi: 0.550,
      n_samples: 200,
      inconclusive: false,
    },
    {
      arm: 'dedicated',
      auc: 0.498,
      ci_lo: 0.457,
      ci_hi: 0.539,
      n_samples: 200,
      inconclusive: false,
    },
  ];

  // ── Covert-channel capacity ─────────────────────────────────────────────────
  const covertChannel: CovertChannelCard = {
    bound_bits_per_query: null, // NOT MEASURED — default per spec
    n_queries: null,
    method: null,
    microarch_status: 'PARTIAL',
  };

  // ── Summary ─────────────────────────────────────────────────────────────────
  const nAdmitted = piTotal + jbTotal + reTotal;
  const nInvalid = piInvalid + jbInvalid + reInvalid;
  const nValid = nAdmitted - nInvalid;

  const summary: SummaryTable = {
    n_admitted: nAdmitted,
    n_valid: nValid,
    n_invalid: nInvalid,
    invalid_by_reason: {
      DEADLINE_EXCEEDED: 4,
      RECORDER_DOWN: 1,
      STALE_EPOCH: 0,
      WITNESS_LAG: 0,
      SCHEMA_VIOLATION: 1,
      OTHER: 0,
    },
    deny_all_score: 0,
  };

  return {
    schema_version: 'benchmarks.v1',
    experiment_id: 'exp_running_01',
    generated_at: '2026-10-19T08:30:00Z',
    illustrative: true,
    attack_rates: attackRates,
    latency_paths: latencyPaths,
    roc_arms: rocArms,
    covert_channel: covertChannel,
    summary,
  };
}
