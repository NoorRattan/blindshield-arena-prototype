"""Automated test for BAR-10 multi-lane contention and isolation benchmark."""

import asyncio
from arena.adapters.benchmark import run_contention_and_isolation_benchmark
from arena.adapters.llama_adapter import LlamaModelAdapter


def test_contention_benchmark_execution():
    adapter = LlamaModelAdapter(synthetic_mode=True, simulate_base_latency_us=2_000)
    result = asyncio.run(run_contention_and_isolation_benchmark(turns_per_lane=10, adapter=adapter))

    assert result.total_turns >= 20
    assert result.concurrent_sessions == 3
    assert result.canary_leakage_detected is False
    assert result.post_reset_leakage_detected is False
    assert result.latency_p50_us >= 2_000
    assert result.latency_p95_us >= result.latency_p50_us
    assert len(result.lane_distribution) == 3
