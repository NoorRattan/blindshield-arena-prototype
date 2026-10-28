"""Statistical evaluation, latency distribution analysis, and Wilson 95% confidence intervals."""

from __future__ import annotations

import math
from typing import Dict, List, Tuple


def wilson_score_interval(successes: int, total: int, z: float = 1.95996) -> Tuple[float, float, float]:
    """Calculate Wilson score 95% confidence interval for a binomial proportion.
    
    Returns (observed_proportion, lower_bound, upper_bound).
    """
    if total <= 0:
        return 0.0, 0.0, 0.0

    p = successes / total
    z2 = z * z
    denom = 1 + z2 / total
    centre_adj = p + z2 / (2 * total)
    spread = z * math.sqrt((p * (1 - p) + z2 / (4 * total)) / total)

    lower = max(0.0, (centre_adj - spread) / denom)
    upper = min(1.0, (centre_adj + spread) / denom)
    return p, lower, upper


def compute_latency_percentiles(durations_us: List[int]) -> Dict[str, float]:
    """Compute exact latency distributions (p50, p90, p95, p99, min, max, mean) in milliseconds."""
    if not durations_us:
        return {"p50_ms": 0.0, "p90_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "mean_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}

    sorted_d = sorted(durations_us)
    n = len(sorted_d)

    def percentile(p: float) -> float:
        k = (n - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return sorted_d[int(k)] / 1000.0
        d0 = sorted_d[int(f)] * (c - k)
        d1 = sorted_d[int(c)] * (k - f)
        return (d0 + d1) / 1000.0

    return {
        "p50_ms": round(percentile(0.50), 3),
        "p90_ms": round(percentile(0.90), 3),
        "p95_ms": round(percentile(0.95), 3),
        "p99_ms": round(percentile(0.99), 3),
        "mean_ms": round(sum(sorted_d) / n / 1000.0, 3),
        "min_ms": round(sorted_d[0] / 1000.0, 3),
        "max_ms": round(sorted_d[-1] / 1000.0, 3),
    }


def compute_contention_shift_pct(baseline_p50_ms: float, loaded_p50_ms: float) -> float:
    """Calculate percentage shift in latency under noisy neighbor / load conditions."""
    if baseline_p50_ms <= 0.0:
        return 0.0
    shift = ((loaded_p50_ms - baseline_p50_ms) / baseline_p50_ms) * 100.0
    return round(shift, 2)
