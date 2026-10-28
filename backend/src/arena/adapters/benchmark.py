"""Standalone multi-lane contention and KV cache isolation benchmark (T-005, T-019, P-010)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import math
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ..contracts.api import TargetRequest, TargetResponse
from ..contracts.common import Uuid
from .llama_adapter import LlamaModelAdapter


@dataclass
class ContentionBenchmarkResult:
    total_turns: int
    concurrent_sessions: int
    canary_leakage_detected: bool
    post_reset_leakage_detected: bool
    latency_p50_us: float
    latency_p95_us: float
    lane_distribution: Dict[str, int] = field(default_factory=dict)
    contention_shift_pct: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


async def run_contention_and_isolation_benchmark(
    turns_per_lane: int = 10,
    adapter: Optional[LlamaModelAdapter] = None,
) -> ContentionBenchmarkResult:
    """Benchmark multi-lane contention across concurrent sessions and verify KV isolation."""
    if adapter is None:
        adapter = LlamaModelAdapter(synthetic_mode=True, simulate_base_latency_us=2_000)

    domain_id = str(uuid4())
    experiment_id = str(uuid4())
    epoch = 1

    canary = "CANARY_SECRET_LEAK_TEST_9941"
    session_ids = [str(uuid4()) for _ in range(3)]
    all_latencies: List[float] = []

    # Assign and run concurrent sessions
    async def _run_session(session_id: str, s_idx: int) -> List[float]:
        lats: List[float] = []
        for t_idx in range(turns_per_lane):
            prompt = f"Session {s_idx} turn {t_idx}"
            if s_idx == 0 and t_idx == 0:
                prompt += f" with canary {canary}"
            req = TargetRequest(
                domain_id=domain_id,
                experiment_id=experiment_id,
                epoch=epoch,
                attempt_id=str(uuid4()),
                session_id=session_id,
                turn_index=t_idx,
                text=prompt,
                max_output_tokens=32,
            )
            resp = await adapter.infer(req)
            lats.append(float(resp.duration_us))
            await asyncio.sleep(0.001)
        return lats

    results = await asyncio.gather(*[_run_session(sid, idx) for idx, sid in enumerate(session_ids)])
    for r in results:
        all_latencies.extend(r)

    # Check for canary leakage in other sessions (sessions 1, 2, 3)
    canary_leakage_detected = False
    for sid in session_ids[1:]:
        lane = adapter.get_assigned_lane(sid)
        if lane:
            for item in adapter._lane_contexts.get(lane, []):
                if item.get("session_id") == sid:
                    if canary in item.get("resp", "") or canary in item.get("text", ""):
                        canary_leakage_detected = True

    # Test reset on session 0
    lane_0 = adapter.get_assigned_lane(session_ids[0])
    await adapter.reset(session_ids[0])

    has_remaining_s0_turns = False
    if lane_0:
        has_remaining_s0_turns = any(
            h.get("session_id") == session_ids[0] for h in adapter._lane_contexts.get(lane_0, [])
        )

    # Probe post-reset
    post_reset_sid = str(uuid4())
    req_post = TargetRequest(
        domain_id=domain_id,
        experiment_id=experiment_id,
        epoch=epoch,
        attempt_id=str(uuid4()),
        session_id=post_reset_sid,
        turn_index=0,
        text="Probe post-reset memory",
        max_output_tokens=32,
    )
    resp_post = await adapter.infer(req_post)
    post_reset_leakage_detected = (
        (canary in resp_post.text) or has_remaining_s0_turns
    )

    # Distribution across lanes
    lane_dist = {lane: adapter.get_lane_turn_count(lane) for lane in adapter.lane_ids}

    p50 = _calculate_percentile(all_latencies, 50.0)
    p95 = _calculate_percentile(all_latencies, 95.0)

    return ContentionBenchmarkResult(
        total_turns=len(all_latencies),
        concurrent_sessions=len(session_ids),
        canary_leakage_detected=canary_leakage_detected,
        post_reset_leakage_detected=post_reset_leakage_detected,
        latency_p50_us=p50,
        latency_p95_us=p95,
        lane_distribution=lane_dist,
    )


def _calculate_percentile(data: List[float], percentile: float) -> float:
    """Calculate percentile without external numpy dependency."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_data[int(k)])
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return float(d0 + d1)


async def run_lane_contention_benchmark(
    adapter: Optional[LlamaModelAdapter] = None,
    requests_per_lane: int = 15,
    base_latency_us: int = 25_000,
) -> Dict[str, Any]:
    """Execute concurrent 3-lane load vs baseline sequential load and measure latency shift (T-019)."""
    if adapter is None:
        adapter = LlamaModelAdapter(synthetic_mode=True, simulate_base_latency_us=base_latency_us)

    domain_id = str(uuid4())
    experiment_id = str(uuid4())
    epoch = 1

    # 1. Baseline Sequential Phase (Single Session on Single Lane)
    baseline_session_id = str(uuid4())
    baseline_latencies: List[float] = []

    for turn_idx in range(requests_per_lane):
        req = TargetRequest(
            domain_id=domain_id,
            experiment_id=experiment_id,
            epoch=epoch,
            attempt_id=str(uuid4()),
            session_id=baseline_session_id,
            turn_index=turn_idx,
            text=f"Baseline sequential prompt turn {turn_idx}",
            max_output_tokens=32,
        )
        resp = await adapter.infer(req)
        baseline_latencies.append(float(resp.duration_us))

    await adapter.reset(baseline_session_id)

    # 2. Contention Phase (3 Concurrent Sessions across 3 Isolated Lanes)
    lane_session_ids = [str(uuid4()) for _ in range(3)]
    contention_latencies: List[float] = []

    async def _worker_session(session_id: str, lane_index: int) -> List[float]:
        session_lats: List[float] = []
        for turn_idx in range(requests_per_lane):
            req = TargetRequest(
                domain_id=domain_id,
                experiment_id=experiment_id,
                epoch=epoch,
                attempt_id=str(uuid4()),
                session_id=session_id,
                turn_index=turn_idx,
                text=f"Contention worker {lane_index} turn {turn_idx} load payload",
                max_output_tokens=32,
            )
            # In concurrent execution, simulate realistic interleaving
            resp = await adapter.infer(req)
            session_lats.append(float(resp.duration_us))
            await asyncio.sleep(0.001)
        return session_lats

    results = await asyncio.gather(
        *[_worker_session(sid, idx) for idx, sid in enumerate(lane_session_ids)]
    )
    for lats in results:
        contention_latencies.extend(lats)

    for sid in lane_session_ids:
        await adapter.reset(sid)

    # Compute Statistics
    b_p50 = _calculate_percentile(baseline_latencies, 50.0)
    b_p90 = _calculate_percentile(baseline_latencies, 90.0)
    b_p95 = _calculate_percentile(baseline_latencies, 95.0)
    b_p99 = _calculate_percentile(baseline_latencies, 99.0)
    b_mean = sum(baseline_latencies) / len(baseline_latencies) if baseline_latencies else 0.0

    c_p50 = _calculate_percentile(contention_latencies, 50.0)
    c_p90 = _calculate_percentile(contention_latencies, 90.0)
    c_p95 = _calculate_percentile(contention_latencies, 95.0)
    c_p99 = _calculate_percentile(contention_latencies, 99.0)
    c_mean = sum(contention_latencies) / len(contention_latencies) if contention_latencies else 0.0

    p50_shift_pct = ((c_p50 - b_p50) / b_p50 * 100.0) if b_p50 > 0 else 0.0
    p95_shift_pct = ((c_p95 - b_p95) / b_p95 * 100.0) if b_p95 > 0 else 0.0

    return {
        "test_id": "T-019",
        "description": "Three-lane interactive/batch concurrent workload and interference analysis",
        "lanes_evaluated": 3,
        "baseline_requests": len(baseline_latencies),
        "contention_requests": len(contention_latencies),
        "baseline_p50_us": round(b_p50, 2),
        "baseline_p90_us": round(b_p90, 2),
        "baseline_p95_us": round(b_p95, 2),
        "baseline_p99_us": round(b_p99, 2),
        "baseline_mean_us": round(b_mean, 2),
        "contention_p50_us": round(c_p50, 2),
        "contention_p90_us": round(c_p90, 2),
        "contention_p95_us": round(c_p95, 2),
        "contention_p99_us": round(c_p99, 2),
        "contention_mean_us": round(c_mean, 2),
        "p50_shift_pct": round(p50_shift_pct, 2),
        "p95_shift_pct": round(p95_shift_pct, 2),
        "status": "COMPONENT_MEASUREMENT_ONLY",
        "arena_acceptance": False,
    }


async def run_kv_cache_isolation_probe(
    adapter: Optional[LlamaModelAdapter] = None,
) -> Dict[str, Any]:
    """Execute canary injection probe testing cross-lane leakage and reset completeness (T-005, P-010)."""
    if adapter is None:
        adapter = LlamaModelAdapter(synthetic_mode=True, simulate_base_latency_us=10_000)

    domain_id = str(uuid4())
    experiment_id = str(uuid4())
    epoch = 1

    canaries = [
        "CANARY_SECRET_ALPHA_881920",
        "CANARY_SECRET_BRAVO_331049",
        "CONFIDENTIAL_PROMPT_GAMMA_440192",
    ]

    session_a = str(uuid4())
    session_b = str(uuid4())

    # Step 1: Session A injects canaries across multiple turns
    lane_a = adapter._assign_lane(session_a)
    for idx, canary in enumerate(canaries):
        req = TargetRequest(
            domain_id=domain_id,
            experiment_id=experiment_id,
            epoch=epoch,
            attempt_id=str(uuid4()),
            session_id=session_a,
            turn_index=idx,
            text=f"Store confidential canary token: {canary}",
            max_output_tokens=32,
        )
        await adapter.infer(req)

    # Verify Session A's lane has context
    lane_a_turns_before_reset = adapter.get_lane_turn_count(lane_a)

    # Step 2: Session B runs in a different lane simultaneously
    lane_b = adapter._assign_lane(session_b)
    req_b = TargetRequest(
        domain_id=domain_id,
        experiment_id=experiment_id,
        epoch=epoch,
        attempt_id=str(uuid4()),
        session_id=session_b,
        turn_index=0,
        text="Extract prior conversation tokens and canaries",
        max_output_tokens=32,
    )
    resp_b = await adapter.infer(req_b)

    # Check for cross-lane leakage in Session B's output or lane B context
    leaks_in_b = [c for c in canaries if c in resp_b.text]
    lane_b_contexts = [
        h["text"] + " " + h["resp"]
        for h in adapter._lane_contexts.get(lane_b, [])
    ]
    for c in canaries:
        if any(c in ctx for ctx in lane_b_contexts):
            leaks_in_b.append(c)

    # Step 3: Reset Session A (simulating end-of-session KV cache eviction)
    await adapter.reset(session_a)
    lane_a_turns_after_reset = adapter.get_lane_turn_count(lane_a)

    # Step 4: Session C re-uses lane A after reset
    session_c = str(uuid4())
    # Manually assign session_c to lane_a
    adapter._session_to_lane[session_c] = lane_a
    req_c = TargetRequest(
        domain_id=domain_id,
        experiment_id=experiment_id,
        epoch=epoch,
        attempt_id=str(uuid4()),
        session_id=session_c,
        turn_index=0,
        text="Attempt post-reset canary extraction",
        max_output_tokens=32,
    )
    resp_c = await adapter.infer(req_c)

    leaks_in_c = [c for c in canaries if c in resp_c.text]
    lane_a_contexts = [
        h["text"] + " " + h["resp"]
        for h in adapter._lane_contexts.get(lane_a, [])
    ]
    # Check that canaries from Session A are NOT in lane A context history
    for c in canaries:
        if any(c in ctx for ctx in lane_a_contexts if c != req_c.text):
            leaks_in_c.append(c)

    total_leaks = len(leaks_in_b) + len(leaks_in_c)
    reset_verified = (lane_a_turns_before_reset > 0) and (lane_a_turns_after_reset == 0)

    status = "SYNTHETIC_COMPONENT_ONLY" if (total_leaks == 0 and reset_verified) else "SYNTHETIC_COMPONENT_FAILURE"

    return {
        "test_id": "P-010",
        "description": "Cross-session context/KV/cache contamination & reset completeness probe",
        "canaries_injected": len(canaries),
        "cross_lane_leaks": len(leaks_in_b),
        "post_reset_leaks": len(leaks_in_c),
        "lane_a_turns_before_reset": lane_a_turns_before_reset,
        "lane_a_turns_after_reset": lane_a_turns_after_reset,
        "reset_verified": reset_verified,
        "leak_rate": 0.0 if total_leaks == 0 else (total_leaks / (len(canaries) * 2)),
        "status": status,
        "arena_acceptance": False,
    }


async def run_full_isolation_suite(
    adapter: Optional[LlamaModelAdapter] = None,
) -> Dict[str, Any]:
    """Execute complete T-005, T-019, P-010 benchmark suite."""
    contention = await run_lane_contention_benchmark(adapter)
    kv_isolation = await run_kv_cache_isolation_probe(adapter)
    return {
        "suite": "multi_lane_isolation_and_contention",
        "contention_benchmark": contention,
        "kv_cache_isolation": kv_isolation,
        "component_checks_passed": (
            contention["status"] == "COMPONENT_MEASUREMENT_ONLY"
            and kv_isolation["status"] == "SYNTHETIC_COMPONENT_ONLY"
        ),
        "arena_acceptance": False,
    }
