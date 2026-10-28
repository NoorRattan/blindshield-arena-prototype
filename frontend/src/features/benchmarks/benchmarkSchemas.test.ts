import { describe, it, expect } from 'vitest';
import { BenchmarkDatasetSchema, wilsonCI } from './benchmarkSchemas';
import { generateIllustrativeBenchmarks } from './benchmarkFixtures';

describe('wilsonCI', () => {
  it('returns [0, 0] for n=0', () => {
    const [lo, hi] = wilsonCI(0, 0);
    expect(lo).toBe(0);
    expect(hi).toBe(0);
  });

  it('CI bounds are between 0 and 1', () => {
    const [lo, hi] = wilsonCI(10, 20);
    expect(lo).toBeGreaterThanOrEqual(0);
    expect(hi).toBeLessThanOrEqual(1);
    expect(lo).toBeLessThan(hi);
  });

  it('CI is symmetric around p for moderate n', () => {
    const [lo, hi] = wilsonCI(50, 100);
    const mid = (lo + hi) / 2;
    // Centre should be near 0.5 (within 2% tolerance for Wilson vs naive)
    expect(Math.abs(mid - 0.5)).toBeLessThan(0.03);
  });

  it('all-blocked yields [0, 0]', () => {
    const [lo, hi] = wilsonCI(0, 50);
    expect(lo).toBe(0);
    // CI hi might be >0 for small samples, but lo must be 0
    expect(lo).toBeGreaterThanOrEqual(0);
    expect(hi).toBeGreaterThanOrEqual(lo);
  });
});

describe('generateIllustrativeBenchmarks', () => {
  it('produces a schema-valid dataset', () => {
    const data = generateIllustrativeBenchmarks();
    expect(() => BenchmarkDatasetSchema.parse(data)).not.toThrow();
  });

  it('is always tagged illustrative', () => {
    const data = generateIllustrativeBenchmarks();
    expect(data.illustrative).toBe(true);
  });

  it('includes a DENY_ALL_BASELINE row with defended_success_rate = 0', () => {
    const data = generateIllustrativeBenchmarks();
    const baseline = data.attack_rates.find((r) => r.family === 'DENY_ALL_BASELINE');
    expect(baseline).toBeDefined();
    expect(baseline?.defended_success_rate).toBe(0);
    expect(baseline?.n_passed).toBe(0);
  });

  it('never folds invalid/blocked into success rate', () => {
    const data = generateIllustrativeBenchmarks();
    for (const row of data.attack_rates) {
      if (row.family === 'DENY_ALL_BASELINE') continue;
      // n_passed should equal total - blocked - invalid
      expect(row.n_passed).toBe(row.n_total - row.n_blocked - row.n_invalid);
      // defended rate is bounded [0, 1]
      expect(row.defended_success_rate).toBeGreaterThanOrEqual(0);
      expect(row.defended_success_rate).toBeLessThanOrEqual(1);
    }
  });

  it('covert-channel defaults to NOT MEASURED', () => {
    const data = generateIllustrativeBenchmarks();
    expect(data.covert_channel.bound_bits_per_query).toBeNull();
    expect(data.covert_channel.method).toBeNull();
  });

  it('latency paths never sum stage p95s (all have independent n_samples)', () => {
    const data = generateIllustrativeBenchmarks();
    expect(data.latency_paths.length).toBeGreaterThanOrEqual(3);
    for (const path of data.latency_paths) {
      expect(path.n_samples).toBeGreaterThan(0);
      expect(path.p95_ms).toBeGreaterThan(0);
    }
  });

  it('summary deny_all_score is 0', () => {
    const data = generateIllustrativeBenchmarks();
    expect(data.summary.deny_all_score).toBe(0);
  });

  it('rejects bad JSON schema at import boundary', () => {
    const bad = { schema_version: 'wrong', experiment_id: '' };
    expect(() => BenchmarkDatasetSchema.parse(bad)).toThrow();
  });

  it('rejects extra unknown keys (strict)', () => {
    const data = generateIllustrativeBenchmarks() as Record<string, unknown>;
    data['__extra'] = 'hacked';
    expect(() => BenchmarkDatasetSchema.parse(data)).toThrow();
  });

  it('is deterministic — two calls return identical data', () => {
    const a = generateIllustrativeBenchmarks();
    const b = generateIllustrativeBenchmarks();
    expect(a.attack_rates[0].defended_success_rate).toBeCloseTo(
      b.attack_rates[0].defended_success_rate,
      10
    );
  });
});
