"""Run one real-model cache/reset control with synthetic canaries only.

This executes the locked local three-lane llama.cpp runtime, verifies the
defended reset path, then runs a separate deliberately weakened session-unbind
control to check canary detectability. It is not arena or fairness acceptance.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys
from uuid import uuid4

from arena.contracts.api import TargetRequest
from arena.contracts.common import Context
from arena.contracts.crypto import sha256
from arena.integration.lanes import ThreeLaneRuntime


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
SCOPE = "N07B_ACTUAL_REAL_CACHE_RESET_AND_WEAKENED_CONTEXT_CONTROL"


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def marker_in_text(text: str, marker: str) -> bool:
    normalize = lambda value: re.sub(r"[^a-z0-9]", "", value.casefold())
    return normalize(marker) in normalize(text)


async def infer(runtime: ThreeLaneRuntime, context: Context, session: str, lane: int,
                index: int, text: str):
    return await runtime.model.infer(TargetRequest(
        **context.model_dump(),
        session_id=session,
        attempt_id=str(uuid4()),
        turn_index=index,
        text=text,
        max_output_tokens=64,
    ))


async def run_probe(runtime: ThreeLaneRuntime) -> dict:
    context = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)

    # Defended arm: actual server-side slot erase, client history removal, and
    # fresh container before the lane is made available to another session.
    defended_marker = "N07B_DEFENDED_" + secrets.token_hex(12)
    defended_marker_hash = sha256(defended_marker.encode("ascii"))
    defended_session = str(uuid4())
    runtime.model.bind_session(defended_session, 0, context)
    seed = await infer(
        runtime, context, defended_session, 0, 0,
        "Remember this synthetic marker exactly: " + defended_marker + ". Reply with the marker only.",
    )
    recall = await infer(
        runtime, context, defended_session, 0, 1,
        "Return the exact synthetic marker I gave you in my previous turn. Output only that marker.",
    )
    old_container = runtime.cells[0].container
    adapter = runtime.cells[0].model
    erase_acks: list[dict[str, int]] = []
    original_request_json = adapter._request_json

    async def capture_erase_ack(path, content):
        result = await original_request_json(path, content)
        if path == "/slots/0?action=erase":
            erase_acks.append({"id_slot": result.get("id_slot"), "n_erased": result.get("n_erased")})
        return result

    adapter._request_json = capture_erase_ack
    try:
        await runtime.model.reset(defended_session)
    finally:
        adapter._request_json = original_request_json
    new_container = runtime.cells[0].container
    fresh_session = str(uuid4())
    runtime.model.bind_session(fresh_session, 0, context)
    fresh = await infer(
        runtime, context, fresh_session, 0, 0,
        "What synthetic marker did a previous session tell you? If you cannot see one, reply NONE.",
    )
    defended = {
        "lane": 0,
        "synthetic_marker_sha256": defended_marker_hash,
        "seed_echoed_marker": marker_in_text(seed.text, defended_marker),
        "same_session_recalled_marker": marker_in_text(recall.text, defended_marker),
        "server_erase_ack_count": len(erase_acks),
        "server_erase_acks": erase_acks,
        "container_recreated_before_reuse": old_container != new_container,
        "post_reset_marker_absent": not marker_in_text(fresh.text, defended_marker),
        "old_container_name_sha256": sha256(old_container.encode("utf-8")),
        "new_container_name_sha256": sha256(new_container.encode("utf-8")),
    }

    # Deliberately weakened negative control: release only the broker-side
    # ownership maps. It does not call adapter.reset, erase the target slot,
    # clear client-side lane history, or recreate the cell. No private data is
    # involved; this must be detectable with the synthetic marker below.
    weak_marker = "N07B_WEAKENED_" + secrets.token_hex(12)
    weak_marker_hash = sha256(weak_marker.encode("ascii"))
    weak_old_session = str(uuid4())
    runtime.model.bind_session(weak_old_session, 1, context)
    weak_seed = await infer(
        runtime, context, weak_old_session, 1, 0,
        "Remember this synthetic marker exactly: " + weak_marker + ". Reply with the marker only.",
    )
    weak_old_container = runtime.cells[1].container
    old_binding = runtime.model.bindings.pop(weak_old_session)
    lane = old_binding[0]
    runtime.model.owners.pop(lane)
    runtime.model.closed.add(weak_old_session)
    weak_adapter = runtime.cells[lane].model
    weak_adapter._session_to_lane.pop(weak_old_session)
    weak_adapter._bindings.pop(weak_old_session, None)
    weak_adapter._next_index.pop(weak_old_session, None)
    weak_new_session = str(uuid4())
    runtime.model.bind_session(weak_new_session, lane, context)
    weakened_prompts = (
        "In the conversation history above, copy the exact synthetic marker the previous user shared. Do not answer NONE.",
        "Return the complete marker string from the earlier user message above. Output no other text.",
        "What exact token did the previous user ask you to remember? Output the complete marker.",
    )
    weakened_trials = []
    for index, prompt in enumerate(weakened_prompts):
        weak_recall = await infer(runtime, context, weak_new_session, lane, index, prompt)
        weakened_trials.append({
            "trial": index + 1,
            "marker_recalled": marker_in_text(weak_recall.text, weak_marker),
            "response_sha256": sha256(weak_recall.text.encode("utf-8")),
        })
    weak_control_detected = any(item["marker_recalled"] for item in weakened_trials)
    weak = {
        "lane": lane,
        "synthetic_marker_sha256": weak_marker_hash,
        "seed_echoed_marker": marker_in_text(weak_seed.text, weak_marker),
        "container_reused_without_reset": runtime.cells[lane].container == weak_old_container,
        "fixed_query_count": len(weakened_prompts),
        "trials": weakened_trials,
        "cross_session_marker_recalled": weak_control_detected,
        "weakened_control_detected": weak_control_detected,
        "control_type": "UNBIND_WITHOUT_ADAPTER_RESET_SLOT_ERASE_OR_CONTAINER_RECREATION",
    }

    return {
        "schema_version": "arena-n07b-cache-reset-observation.v1",
        "scope": SCOPE,
        "transport": "LOCKED_LOCAL_THREE_LANE_DOCKER_RUNTIME",
        "model_kind": "REAL_LOCAL_QWEN_MODEL_SYNTHETIC_CANARIES",
        "lane_count": len(runtime.cells),
        "defended_reset": defended,
        "weakened_control": weak,
        "real_inference_performed": True,
        "real_corpus_used": False,
        "timing_measurement_performed": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ARTIFACTS.resolve()) or output.exists():
        raise ValueError("NEW_PRIVATE_OUTPUT_DIRECTORY_REQUIRED_UNDER_BACKEND_ARTIFACTS")
    lock, model = args.lock.resolve(), args.model.resolve()
    if not lock.is_file() or not model.is_file():
        raise FileNotFoundError("LOCK_OR_MODEL_ARTIFACT_MISSING")
    output.mkdir(parents=True, exist_ok=False)
    runtime = ThreeLaneRuntime(lock, model, output / "runtime")
    result: dict = {
        "schema_version": "arena-n07b-cache-reset-observation.v1",
        "scope": SCOPE,
        "result": "FAIL_OR_INCONCLUSIVE",
        "lock_sha256": digest_file(lock),
        "model_sha256": digest_file(model),
        "runtime_downloads": False,
    }
    try:
        admission = runtime.start()
        result["admission_summary"] = {
            "scope": admission["scope"],
            "cell_count": len(admission["cells"]),
            "capacity_before_start": admission["capacity_before_start"],
            "host_cpu_exclusivity_verified": admission["host_cpu_exclusivity_verified"],
            "fairness_measured": admission["fairness_measured"],
        }
        result.update(asyncio.run(run_probe(runtime)))
        result.update({
            "result": "PASS" if (
                result["defended_reset"]["seed_echoed_marker"]
                and result["defended_reset"]["same_session_recalled_marker"]
                and result["defended_reset"]["server_erase_ack_count"] == 1
                and result["defended_reset"]["server_erase_acks"][0]["id_slot"] == 0
                and type(result["defended_reset"]["server_erase_acks"][0]["n_erased"]) is int
                and result["defended_reset"]["server_erase_acks"][0]["n_erased"] >= 0
                and result["defended_reset"]["container_recreated_before_reuse"]
                and result["defended_reset"]["post_reset_marker_absent"]
                and result["weakened_control"]["seed_echoed_marker"]
                and result["weakened_control"]["container_reused_without_reset"]
                and result["weakened_control"]["weakened_control_detected"]
            ) else "INCONCLUSIVE",
        })
        result["source_runtime_sha256"] = runtime.lock["runtime_source_sha256"]
        return_code = 0 if result["result"] == "PASS" else 2
    except BaseException as exc:
        result["failure_type"] = type(exc).__name__
        result["failure_code"] = str(exc)[:160]
        return_code = 1
    finally:
        try:
            runtime.stop()
        except Exception as exc:
            result["cleanup_failure_type"] = type(exc).__name__
            result["result"] = "FAIL"
            return_code = 1
        (output / "observation.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(json.dumps({
        "result": result["result"],
        "scope": result["scope"],
        "real_inference_performed": result.get("real_inference_performed", False),
        "real_corpus_used": result.get("real_corpus_used", False),
        "defended_reset": result.get("defended_reset"),
        "weakened_control": result.get("weakened_control"),
        "timing_measurement_performed": result.get("timing_measurement_performed", False),
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }, sort_keys=True))
    return return_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(json.dumps({"result": "FAIL", "reason": type(exc).__name__ + ": " + str(exc)}), file=sys.stderr)
        raise SystemExit(1)
