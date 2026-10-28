"""Tests for multi-lane contention and KV cache isolation benchmark (T-005, T-019, P-010)."""

import asyncio
import unittest
from uuid import uuid4

from arena.adapters.benchmark import (
    run_full_isolation_suite,
    run_kv_cache_isolation_probe,
    run_lane_contention_benchmark,
)
from arena.adapters.llama_adapter import LlamaModelAdapter
from arena.contracts.api import TargetRequest


class TestLaneBenchmarkAndIsolation(unittest.TestCase):
    def test_run_lane_contention_benchmark(self):
        adapter = LlamaModelAdapter(synthetic_mode=True, simulate_base_latency_us=5_000)
        result = asyncio.run(run_lane_contention_benchmark(adapter, requests_per_lane=10))

        self.assertEqual(result["test_id"], "T-019")
        self.assertEqual(result["lanes_evaluated"], 3)
        self.assertEqual(result["baseline_requests"], 10)
        self.assertEqual(result["contention_requests"], 30)
        self.assertEqual(result["status"], "COMPONENT_MEASUREMENT_ONLY")
        self.assertFalse(result["arena_acceptance"])

        # Percentiles monotonic property
        self.assertLessEqual(result["baseline_p50_us"], result["baseline_p90_us"])
        self.assertLessEqual(result["baseline_p90_us"], result["baseline_p95_us"])
        self.assertLessEqual(result["baseline_p95_us"], result["baseline_p99_us"])

        self.assertLessEqual(result["contention_p50_us"], result["contention_p90_us"])
        self.assertLessEqual(result["contention_p90_us"], result["contention_p95_us"])
        self.assertLessEqual(result["contention_p95_us"], result["contention_p99_us"])

    def test_run_kv_cache_isolation_probe(self):
        adapter = LlamaModelAdapter(synthetic_mode=True, simulate_base_latency_us=5_000)
        result = asyncio.run(run_kv_cache_isolation_probe(adapter))

        self.assertEqual(result["test_id"], "P-010")
        self.assertEqual(result["status"], "SYNTHETIC_COMPONENT_ONLY")
        self.assertFalse(result["arena_acceptance"])
        self.assertEqual(result["cross_lane_leaks"], 0)
        self.assertEqual(result["post_reset_leaks"], 0)
        self.assertEqual(result["leak_rate"], 0.0)
        self.assertTrue(result["reset_verified"])
        self.assertGreater(result["lane_a_turns_before_reset"], 0)
        self.assertEqual(result["lane_a_turns_after_reset"], 0)

    def test_full_isolation_suite(self):
        adapter = LlamaModelAdapter(synthetic_mode=True, simulate_base_latency_us=5_000)
        result = asyncio.run(run_full_isolation_suite(adapter))

        self.assertTrue(result["component_checks_passed"])
        self.assertFalse(result["arena_acceptance"])
        self.assertEqual(result["contention_benchmark"]["status"], "COMPONENT_MEASUREMENT_ONLY")
        self.assertEqual(result["kv_cache_isolation"]["status"], "SYNTHETIC_COMPONENT_ONLY")

    def test_multi_session_sticky_lane_assignment(self):
        adapter = LlamaModelAdapter(synthetic_mode=True)
        sid_0 = str(uuid4())
        sid_1 = str(uuid4())
        sid_2 = str(uuid4())

        lane_0 = adapter._assign_lane(sid_0)
        lane_1 = adapter._assign_lane(sid_1)
        lane_2 = adapter._assign_lane(sid_2)

        # All 3 lanes assigned distinctly
        self.assertEqual(len({lane_0, lane_1, lane_2}), 3)
        self.assertEqual(set([lane_0, lane_1, lane_2]), {"lane-0", "lane-1", "lane-2"})

        # Sticky assignment preserves lane
        self.assertEqual(adapter._assign_lane(sid_0), lane_0)
        self.assertEqual(adapter._assign_lane(sid_1), lane_1)
        self.assertEqual(adapter._assign_lane(sid_2), lane_2)
