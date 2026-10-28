"""Run real, bounded model-component load/infer/reset/failure acceptance.

Uses only synthetic functional prompts and the actually assembled image.
Does not open a participant listener or grant global N08 admission.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import subprocess
import time
from uuid import uuid4

from arena.contracts.api import TargetRequest
from arena.contracts.jsonwire import load_wire
from arena.integration.runtime import docker, runtime_source_hashes
from arena.model_runtime import BACKEND, ModelCellRuntime, ModelProfile, file_digest, host_available_memory
from arena.ports import DependencyUnavailable, TargetNotDispatched


async def check(profile_path: Path, model: Path, output: Path) -> dict:
    output = output.resolve()
    if not output.is_relative_to((BACKEND / "artifacts").resolve()) or output.exists():
        raise ValueError("NEW_PRIVATE_COMPONENT_CHECK_DIRECTORY_REQUIRED")
    output.mkdir(parents=True)
    profile = load_wire(ModelProfile, profile_path.read_bytes())
    results = []
    created = []
    started = time.time_ns()

    def runtime(name, model_path=model, selected_profile=profile_path):
        cell = ModelCellRuntime(selected_profile, model_path, output / name)
        created.append(cell)
        return cell

    def refusal(name, path, expected):
        cell = runtime(name, path)
        try:
            cell.start()
        except DependencyUnavailable as exc:
            if expected not in str(exc):
                raise
            results.append({"check":name,"result":"PASS","observed":expected,"model_dispatched":False})
        else:
            raise AssertionError("Required pre-dispatch refusal did not occur")
        finally:
            cell.stop()

    refusal("missing-model", output / "missing.gguf", "MODEL_FILE_MISSING")
    bad = output / "corrupt.gguf"
    bad.write_bytes(b"corrupt model")
    refusal("corrupt-model", bad, "MODEL_BYTES_CHANGED")

    context = {"domain_id":str(uuid4()),"experiment_id":str(uuid4()),"epoch":1}
    session = str(uuid4())

    def request(index, text, session_id=session):
        return TargetRequest(**context,attempt_id=str(uuid4()),session_id=session_id,
                             turn_index=index,text=text,max_output_tokens=16)

    cell = runtime("functional")
    try:
        load_start = time.perf_counter_ns()
        observation = cell.start()
        results.append({"check":"load-and-effective-controls","result":"PASS",
                        "load_ns":time.perf_counter_ns()-load_start,
                        "actual_image_id":observation["image_id"],
                        "expected_image_id":profile.assembled_image_id,
                        "network_mode":observation["network_mode"],
                        "effective_uid":observation["effective_uid"],
                        "memory_limit_bytes":observation["memory_limit_bytes"]})
        if observation["image_id"] != profile.assembled_image_id:
            raise AssertionError("Functional check did not use the assembled image")
        response = await cell.model.infer(request(0,"Reply with the single word READY."))
        if not response.text.strip() or not 0 < response.output_tokens <= 16:
            raise AssertionError("Real model produced no bounded response")
        results.append({"check":"real-inference","result":"PASS","output_sha256":__import__('hashlib').sha256(response.text.encode()).hexdigest(),
                        "input_tokens":response.input_tokens,"output_tokens":response.output_tokens,"duration_us":response.duration_us})
        continuation = await cell.model.infer(request(1,"Reply with the single word DONE."))
        if not continuation.text.strip():
            raise AssertionError("Continuation produced no response")
        results.append({"check":"same-session-continuation","result":"PASS","output_tokens":continuation.output_tokens})
        # The real tokenizer must reject an excessive request before completion.
        try:
            await cell.model.infer(request(2," word"*4000))
        except TargetNotDispatched as exc:
            if str(exc) != "MODEL_INPUT_TOKEN_CAP_EXCEEDED":
                raise
            results.append({"check":"real-tokenizer-input-cap","result":"PASS","completion_dispatched":False})
        else:
            raise AssertionError("Oversize input was not refused")
        await cell.model.reset(session)
        if cell.model.get_assigned_lane(session) is not None:
            raise AssertionError("Reset did not release session assignment")
        results.append({"check":"real-slot-erase-acknowledged","result":"PASS"})
        old_id = json.loads(docker("inspect",cell.container))[0]["Id"]
    finally:
        cell.stop()

    restarted = runtime("restart")
    try:
        restarted.start()
        new_id = json.loads(docker("inspect",restarted.container))[0]["Id"]
        if old_id == new_id:
            raise AssertionError("Restart reused the prior model process")
        fresh_session = str(uuid4())
        fresh = await restarted.model.infer(request(0,"Reply with the single word FRESH.",fresh_session))
        if not fresh.text.strip():
            raise AssertionError("Fresh process failed inference")
        results.append({"check":"stop-recreate-fresh-session","result":"PASS","distinct_container":True,"output_tokens":fresh.output_tokens})
        # Kill only this check's own cell; a lost reset ACK must quarantine it.
        docker("stop","--time","1",restarted.container,timeout=15)
        try:
            await restarted.model.reset(fresh_session)
        except DependencyUnavailable:
            pass
        else:
            raise AssertionError("Dead cell incorrectly acknowledged reset")
        try:
            await restarted.model.infer(request(1,"Must never dispatch.",fresh_session))
        except (TargetNotDispatched,DependencyUnavailable):
            results.append({"check":"failed-reset-quarantines-no-retry","result":"PASS"})
        else:
            raise AssertionError("Quarantined session was dispatched")
    finally:
        restarted.stop()
    for item in created:
        item.stop()
    # stop() is deliberately best effort during exception unwinding. A passing
    # receipt needs a separate, successful inventory proving our cells absent.
    remaining = docker("ps", "--all", "--format", "{{.Names}}").decode().splitlines()
    if any(item.container in remaining for item in created):
        raise AssertionError("Owned model container cleanup was not confirmed")
    receipt = {"schema_version":"arena-model-component-check.v1","result":"PASS_MODEL_COMPONENT_ONLY",
               "artifact_label":"OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE",
               "started_at_unix_ns":started,"completed_at_unix_ns":time.time_ns(),
               "source_commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=BACKEND,text=True).strip(),
               "profile_sha256":file_digest(profile_path),"image_id":profile.assembled_image_id,
               "model_sha256":profile.admission.model_sha256,"runtime_source_sha256":runtime_source_hashes(),
               "real_model_dispatches":3,"checks":results,"containers_cleaned_up":True,
               "n08_workload_authorized":False,"three_lane_peak_measured":False,"full_t_p_acceptance":False,
               "host_available_memory_after_bytes":host_available_memory()}
    (output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile",required=True,type=Path)
    parser.add_argument("--model",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    receipt=asyncio.run(check(args.profile,args.model,args.output))
    print(json.dumps({"result":receipt["result"],"checks":len(receipt["checks"]),"real_model_dispatches":receipt["real_model_dispatches"],"image_id":receipt["image_id"]}))


if __name__=="__main__":
    main()
