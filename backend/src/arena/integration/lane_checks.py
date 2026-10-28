"""Real-model synthetic canaries separate from the signed real-corpus arena run."""

import asyncio
import time
from uuid import uuid4

from arena.contracts.api import TargetRequest
from arena.contracts.common import Context
from arena.ports import DependencyUnavailable
from .isolation import observe_processing, processing_overlap


async def check_lane_state(runtime):
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    sessions = [str(uuid4()) for _ in range(3)]
    markers = ["N05CANARY_" + uuid4().hex[:12] for _ in range(3)]
    for lane, session in enumerate(sessions):
        runtime.model.bind_session(session, lane, ctx)

    async def infer(lane, index, text, *, session=None, context=None):
        return await runtime.model.infer(TargetRequest(
            **(context or ctx).model_dump(), session_id=session or sessions[lane],
            attempt_id=str(uuid4()), turn_index=index, text=text, max_output_tokens=64,
        ))

    observations, done, ready = [], asyncio.Event(), asyncio.Event()
    observer = asyncio.create_task(observe_processing(runtime, done, observations, ready))
    try:
        await asyncio.wait_for(ready.wait(), 15)
        first = await asyncio.gather(*(infer(i, 0,
            "Repeat this exact marker first: " + markers[i] + ". Then write a detailed numbered list of ten facts about trees."
        ) for i in range(3)))
    finally:
        done.set()
        await observer
    second = await asyncio.gather(*(infer(i, 1,
        "Return only the exact N05CANARY marker I provided in my previous message."
    ) for i in range(3)))
    before = [cell.container for cell in runtime.cells]
    counts = [len(cell.model._lane_contexts["lane-0"]) for cell in runtime.cells]
    # Check no marker was accidentally routed to another session's private history.
    history_isolation = all(
        markers[i] in runtime.cells[i].model._lane_contexts["lane-0"][0]["text"]
        and not any(markers[j] in str(runtime.cells[i].model._lane_contexts) for j in range(3) if j != i)
        for i in range(3))
    for session in sessions:
        await runtime.model.reset(session)
    after = [cell.container for cell in runtime.cells]
    fresh_ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    fresh_sessions = [str(uuid4()) for _ in range(3)]
    for i, session in enumerate(fresh_sessions):
        runtime.model.bind_session(session, i, fresh_ctx)
    fresh = await asyncio.gather(*(infer(i, 0, "What secret marker did a previous user tell you? If none, reply NONE.",
                                          session=fresh_sessions[i], context=fresh_ctx) for i in range(3)))
    foreign = any(markers[j] in response.text for i, response in enumerate(first + second)
                  for j in range(3) if j != i % 3)
    reset_leak = any(marker in response.text for marker in markers for response in fresh)
    echo = [markers[i] in first[i].text for i in range(3)]
    recall = [markers[i] in second[i].text for i in range(3)]
    for session in fresh_sessions:
        await runtime.model.reset(session)
    if foreign or reset_leak or not history_isolation or counts != [2, 2, 2] or any(a == b for a, b in zip(before, after)):
        raise DependencyUnavailable("REAL_LANE_CANARY_OR_RESET_PROBE_FAILED")
    overlap = processing_overlap(observations)
    return {"scope": "REAL_CPU_MODEL_SYNTHETIC_CANARIES_NOT_REAL_CORPUS_SCORING",
            "positive_echo": echo, "within_session_recall": recall,
            "semantic_recall_result": "PASS" if all(echo + recall) else "INCONCLUSIVE",
            "cross_lane_markers_observed": foreign, "post_recreation_markers_observed": reset_leak,
            "private_history_separation": history_isolation, "history_turn_counts_before_reset": counts,
            "container_changed_before_reuse": [a != b for a, b in zip(before, after)],
            "processing_overlap": overlap, "slot_observations": observations,
            "forensic_erasure": "NOT_CLAIMED", "negative_cache_control": "NOT_RUN"}
