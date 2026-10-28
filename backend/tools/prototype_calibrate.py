"""Bounded six-call real calibration, authorized only by a signed static grant."""
import argparse
import asyncio
import json
from pathlib import Path
import subprocess
from uuid import uuid4

from arena.contracts.api import TargetRequest
from arena.contracts.common import Context
from arena.integration.isolation import observe_processing, processing_overlap
from arena.model_runtime import BACKEND, file_digest
from arena.prototype.admission import issue, key_public, validate_calibration, verify_gate
from arena.prototype.runtime import PrototypeRuntime, memory_observation


async def calibrate(a):
    output = a.output.resolve()
    if not output.is_relative_to(BACKEND / "artifacts") or output.exists():
        raise ValueError("NEW_PRIVATE_CALIBRATION_DIRECTORY_REQUIRED")
    public = key_public(a.authority_public_key)
    verify_gate(a.static_grant, a.profile, public, "STATIC")
    output.mkdir(parents=True)
    runtime = PrototypeRuntime(a.profile, a.static_grant, public, a.model, output / "runtime", purpose="STATIC")
    observations, done, ready = [], asyncio.Event(), asyncio.Event()
    observer = None
    try:
        await asyncio.to_thread(runtime.start)
        ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
        sessions = [str(uuid4()) for _ in range(3)]
        for i, session in enumerate(sessions):
            runtime.model.bind_session(session, i, ctx)
        observer = asyncio.create_task(observe_processing(runtime, done, observations, ready, max_samples=4000))
        await asyncio.wait_for(ready.wait(), 20)
        calls = [0, 0, 0]
        async def infer(lane, index):
            response = await runtime.model.infer(TargetRequest(**ctx.model_dump(), session_id=sessions[lane],
                attempt_id=str(uuid4()), turn_index=index,
                text="Write a detailed numbered list of twelve facts about trees and their leaves.", max_output_tokens=64))
            if not response.text.strip() or not 0 < response.output_tokens <= 64:
                raise AssertionError("CALIBRATION_REAL_RESPONSE_REQUIRED")
            calls[lane] += 1
        for index in range(2):
            await asyncio.gather(*(infer(lane, index) for lane in range(3)))
        done.set()
        await observer
        observer = None
        overlap = processing_overlap(observations)
        cells = []
        for lane, cell in enumerate(runtime.cells):
            measured = await asyncio.to_thread(memory_observation, cell)
            cells.append(dict(measured, lane=lane, cpuset=runtime.profile.model_cpusets[lane], successful_calls=calls[lane]))
        result = {"result": "PASS_THREE_LANE_CALIBRATION", "model_image_id": runtime.profile.component.assembled_image_id,
            "real_model_dispatches": sum(calls), "cells": cells, "capacity_before_start": runtime.capacity_observation,
            "three_lane_overlap_ns": overlap["conservative_overlap_ns"], "processing_overlap": overlap,
            "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=BACKEND, text=True).strip(),
            "containers_cleaned_up": False, "full_t_p_acceptance": False}
        (output / "slot-observations.json").write_bytes((json.dumps(observations) + "\n").encode())
    finally:
        done.set()
        try:
            if observer is not None:
                await observer
        finally:
            await asyncio.to_thread(runtime.stop)
    result["containers_cleaned_up"] = True
    validate_calibration(result, runtime.profile)
    signed = issue("CALIBRATION", a.profile, a.authority_key, result, parent=file_digest(a.static_grant))
    (output / "calibration.json").write_bytes((signed.model_dump_json(indent=2) + "\n").encode())
    print(json.dumps({"result": result["result"], "real_model_dispatches": sum(calls),
        "three_lane_overlap_ns": result["three_lane_overlap_ns"], "memory_peak_bytes": [c["memory_peak_bytes"] for c in cells]}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("profile", "static-grant", "authority-key", "authority-public-key", "model", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    asyncio.run(calibrate(p.parse_args()))
