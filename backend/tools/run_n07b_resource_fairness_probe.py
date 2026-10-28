"""Measure bounded CPU load on the existing local three-lane model.

The probe uses four fixed admitted public JBB records, real local Qwen inference,
and a capped no-network CPU burner sharing one model lane's cpuset at a time. It
records aggregate token/timing and cgroup counters only. It does not run the
defense pipeline or emit a verdict, and it is not full N07/P-011 acceptance.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from uuid import uuid4

from arena.contracts.api import TargetRequest
from arena.contracts.common import Context
from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire
from arena.integration.corpus import PreparedPublicCorpus
from arena.integration.lanes import LaneAdmission, ThreeLaneRuntime, cpu_set
from arena.integration.runtime import docker, ensure_local_docker


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
SCOPE = "N07B_BOUNDED_REAL_LOCAL_CPU_LOAD_RESOURCE_OBSERVATION"
RECORDS_PER_SPLIT = 2
OUTPUT_TOKEN_CAP = 32
PHASE_TIMEOUT_SECONDS = 240
MINIMUM_STRESSOR_CPU_CORES = 0.50
CPU_PRECHECK_SCRIPT = "import os; print('{\"python\":true,\"fork\":'+str(hasattr(os,'fork')).lower()+'}')"
CPU_BURN_SCRIPT = """import os,time
for _ in range(2):
    if os.fork() == 0:
        while True:
            pass
while True:
    time.sleep(30)
"""
CGROUP_READ_SCRIPT = r"""for f in cpu.stat cpu.max cpuset.cpus.effective memory.current memory.max memory.peak memory.events pids.current pids.max pids.peak io.stat; do
  printf 'FILE:%s\n' "$f"
  if [ -r "/sys/fs/cgroup/$f" ]; then cat "/sys/fs/cgroup/$f"; else printf 'UNSUPPORTED\n'; fi
done"""
CGROUP_READ_PY_SCRIPT = """import json
from pathlib import Path
names = "cpu.stat cpu.max cpuset.cpus.effective memory.current memory.max memory.peak memory.events pids.current pids.max pids.peak io.stat".split()
values = {}
for name in names:
    try:
        values[name] = Path('/sys/fs/cgroup', name).read_text().strip()
    except OSError:
        values[name] = 'UNSUPPORTED'
print(json.dumps(values, sort_keys=True))
"""


def digest_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def running_containers() -> list[str]:
    return [
        item
        for item in docker("ps", "--format", "{{.Names}}").decode().splitlines()
        if item
    ]


def parse_cpu_stat(value: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isascii() and fields[1].isdecimal():
            result[fields[0]] = int(fields[1])
    return result


def parse_event_file(value: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isascii() and fields[1].isdecimal():
            result[fields[0]] = int(fields[1])
    return result


def parse_scalar(value: str) -> int | None:
    value = value.strip()
    return int(value) if value.isascii() and value.isdecimal() else None


def parse_io_stat(value: str) -> dict[str, int] | None:
    totals: dict[str, int] = {}
    found = False
    for line in value.splitlines():
        fields = line.split()
        if not fields or ":" not in fields[0]:
            continue
        found = True
        for field in fields[1:]:
            key, separator, number = field.partition("=")
            if separator and number.isascii() and number.isdecimal():
                totals[key] = totals.get(key, 0) + int(number)
    return totals if found else None


def cgroup_snapshot(container: str, *, python_image: bool = False) -> dict:
    if python_image:
        files = json.loads(
            docker("exec", container, "python", "-I", "-c", CGROUP_READ_PY_SCRIPT)
        )
    else:
        text = docker("exec", container, "/bin/sh", "-c", CGROUP_READ_SCRIPT).decode(
            "utf-8", errors="strict"
        )
        files: dict[str, str] = {}
        current: str | None = None
        lines: list[str] = []
        for line in text.splitlines():
            if line.startswith("FILE:"):
                if current is not None:
                    files[current] = "\n".join(lines).strip()
                current, lines = line[5:], []
            elif current is not None:
                lines.append(line)
        if current is not None:
            files[current] = "\n".join(lines).strip()
    if "UNSUPPORTED" in files.get("cpu.stat", ""):
        raise RuntimeError("CGROUP_CPU_STAT_UNAVAILABLE")
    cpu_stat = parse_cpu_stat(files.get("cpu.stat", ""))
    cpu_max = files.get("cpu.max", "")
    cpuset = files.get("cpuset.cpus.effective", "")
    memory_current = parse_scalar(files.get("memory.current", ""))
    memory_max = parse_scalar(files.get("memory.max", ""))
    pids_current = parse_scalar(files.get("pids.current", ""))
    pids_max = parse_scalar(files.get("pids.max", ""))
    if (
        not {"usage_usec", "nr_periods", "nr_throttled", "throttled_usec"} <= set(cpu_stat)
        or not cpu_max
        or not cpuset
        or memory_current is None
        or memory_max is None
        or pids_current is None
        or pids_max is None
    ):
        raise RuntimeError("CGROUP_REQUIRED_COUNTER_UNAVAILABLE")
    return {
        "cpu_stat": cpu_stat,
        "cpu_max": cpu_max,
        "cpuset_cpus_effective": cpuset,
        "memory_current_bytes": memory_current,
        "memory_limit_bytes": memory_max,
        "memory_peak_bytes": parse_scalar(files.get("memory.peak", "")),
        "memory_events": parse_event_file(files.get("memory.events", "")),
        "pids_current": pids_current,
        "pids_limit": pids_max,
        "pids_peak": parse_scalar(files.get("pids.peak", "")),
        "io_totals": parse_io_stat(files.get("io.stat", "")),
        "optional_files_supported": {
            "memory.peak": parse_scalar(files.get("memory.peak", "")) is not None,
            "memory.events": bool(parse_event_file(files.get("memory.events", ""))),
            "pids.peak": parse_scalar(files.get("pids.peak", "")) is not None,
            "io.stat": parse_io_stat(files.get("io.stat", "")) is not None,
        },
    }


def delta_map(after: dict[str, int], before: dict[str, int]) -> dict[str, int]:
    return {
        key: after[key] - before.get(key, 0)
        for key in after
        if after[key] >= before.get(key, 0)
    }


def counter_delta(before: dict, after: dict) -> dict:
    for key in (
        "cpu_max",
        "cpuset_cpus_effective",
        "memory_limit_bytes",
        "pids_limit",
    ):
        if before[key] != after[key]:
            raise RuntimeError("CGROUP_CONFIGURATION_CHANGED_DURING_PHASE")
    return {
        "cpu_stat": delta_map(after["cpu_stat"], before["cpu_stat"]),
        "memory_current_bytes_before": before["memory_current_bytes"],
        "memory_current_bytes_after": after["memory_current_bytes"],
        "memory_limit_bytes": after["memory_limit_bytes"],
        "memory_peak_bytes": max(
            (value for value in (before["memory_peak_bytes"], after["memory_peak_bytes"]) if value is not None),
            default=None,
        ),
        "memory_events_delta": delta_map(after["memory_events"], before["memory_events"]),
        "pids_current_before": before["pids_current"],
        "pids_current_after": after["pids_current"],
        "pids_limit": after["pids_limit"],
        "pids_peak": max(
            (value for value in (before["pids_peak"], after["pids_peak"]) if value is not None),
            default=None,
        ),
        "io_totals_delta": (
            delta_map(after["io_totals"], before["io_totals"])
            if before["io_totals"] is not None and after["io_totals"] is not None
            else None
        ),
        "optional_files_supported": after["optional_files_supported"],
        "cpu_max": after["cpu_max"],
        "cpuset_cpus_effective": after["cpuset_cpus_effective"],
    }


def pick_records(corpus: PreparedPublicCorpus) -> list[dict]:
    selected = []
    for split in ("benign", "harmful"):
        candidates = []
        for reference, payload in corpus.records.items():
            if (
                corpus.split.get(reference) == split
                and payload.provenance.source_id == "JBB-Behaviors"
                and payload.provenance.run_label == "REAL_PUBLIC"
            ):
                record = payload.provenance.record_id.rsplit(":", 1)[-1]
                if record.isascii() and record.isdecimal():
                    candidates.append((int(record), reference, payload))
        candidates.sort(key=lambda item: item[0])
        if len(candidates) < RECORDS_PER_SPLIT:
            raise RuntimeError("ADMITTED_JBB_SPLIT_TOO_SMALL")
        for index, reference, payload in candidates[:RECORDS_PER_SPLIT]:
            selected.append(
                {
                    "split": split,
                    "record_ordinal_sha256": sha256(payload.provenance.record_id.encode("utf-8")),
                    "prompt_sha256": sha256(payload.text.encode("utf-8")),
                    "payload_reference_sha256": sha256(reference.encode("ascii")),
                    "ordinal": index,
                    "text": payload.text,
                }
            )
    return selected


def preflight_burner(image: str) -> None:
    result = docker(
        "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt",
        "no-new-privileges", "--memory", "64m", "--memory-swap", "64m",
        "--cpus", "0.25", "--pids-limit", "4", "--log-driver", "none",
        "--entrypoint", "python", image, "-I", "-c", CPU_PRECHECK_SCRIPT,
    )
    values = json.loads(result)
    if values != {"python": True, "fork": True}:
        raise RuntimeError("PINNED_LOCAL_IMAGE_CANNOT_RUN_CPU_CONTROL")


def start_burner(image: str, cpuset: str) -> str:
    name = "arena-n07b-resource-cpu-" + uuid4().hex
    names_before = set(
        docker("ps", "--all", "--format", "{{.Names}}").decode().splitlines()
    )
    if name in names_before:
        raise RuntimeError("CPU_STRESSOR_NAME_COLLISION")
    try:
        docker(
            "run", "--detach", "--pull", "never", "--name", name,
            "--label", "arena.n07b.resource-cpu=true",
            "--network", "none", "--read-only", "--user", "65534:65534",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "256m", "--memory-swap", "256m", "--cpus", "2",
            "--cpuset-cpus", cpuset, "--pids-limit", "32", "--log-driver", "none",
            "--entrypoint", "python", image, "-I", "-c", CPU_BURN_SCRIPT,
        )
        item = json.loads(docker("inspect", name))[0]
        host = item["HostConfig"]
        if not (
            item["State"]["Running"]
            and item["Config"]["User"] == "65534:65534"
            and host["ReadonlyRootfs"]
            and not host["Privileged"]
            and host["CapDrop"] == ["ALL"]
            and "no-new-privileges" in host["SecurityOpt"]
            and host["Memory"] == 256 * 1024 * 1024
            and host["MemorySwap"] == 256 * 1024 * 1024
            and host["NanoCpus"] == 2_000_000_000
            and host["PidsLimit"] == 32
            and host["NetworkMode"] == "none"
            and cpu_set(host["CpusetCpus"]) == cpu_set(cpuset)
            and item["Config"]["Labels"].get("arena.n07b.resource-cpu") == "true"
        ):
            raise RuntimeError("CPU_STRESSOR_CONTAINER_POLICY_MISMATCH")
        status = json.loads(
            docker(
                "exec",
                name,
                "python",
                "-I",
                "-c",
                "import json,os,pathlib; print(json.dumps({'uid':os.getuid(),'status':pathlib.Path('/proc/self/status').read_text()}))",
            )
        )
        if (
            status.get("uid") != 65534
            or "NoNewPrivs:\t1" not in status.get("status", "")
            or "Seccomp:\t2" not in status.get("status", "")
        ):
            raise RuntimeError("CPU_STRESSOR_EFFECTIVE_CONFINEMENT_MISMATCH")
        return name
    except BaseException:
        try:
            remove_owned_container(name)
        except Exception:
            raise RuntimeError("OWNED_CPU_STRESSOR_CLEANUP_UNCONFIRMED") from None
        raise


def remove_owned_container(name: str) -> None:
    removed = subprocess.run(
        ["docker", "rm", "--force", name], capture_output=True, timeout=15
    )
    absent = b"No such container" in removed.stderr
    if removed.returncode and not absent:
        raise RuntimeError("OWNED_CPU_STRESSOR_CLEANUP_UNCONFIRMED")
    try:
        remaining = docker("ps", "--all", "--format", "{{.Names}}").decode().splitlines()
    except Exception:
        if removed.returncode == 0 or absent:
            return
        raise RuntimeError("OWNED_CPU_STRESSOR_CLEANUP_UNCONFIRMED") from None
    if name in remaining:
        raise RuntimeError("OWNED_CPU_STRESSOR_CLEANUP_FAILED")


def check_model_limits(runtime: ThreeLaneRuntime, inspect: dict) -> None:
    if (
        inspect.get("scope") != "N05_THREE_PROCESS_BASELINE"
        or inspect.get("fairness_measured") is not False
        or inspect.get("host_cpu_exclusivity_verified") is not False
        or len(inspect.get("cells", [])) != 3
    ):
        raise RuntimeError("N05_RUNTIME_INSPECTION_SCOPE_MISMATCH")
    for lane, cell in enumerate(runtime.cells):
        item = json.loads(docker("inspect", cell.container))[0]
        host = item["HostConfig"]
        if (
            not item["State"]["Running"]
            or host["NetworkMode"] != "none"
            or host["NanoCpus"] != 2_000_000_000
            or host["Memory"] != 2 * 1024 * 1024 * 1024
            or host["MemorySwap"] != 2 * 1024 * 1024 * 1024
            or host["PidsLimit"] != 128
            or cpu_set(host["CpusetCpus"]) != cpu_set(runtime.admission.model_cpusets[lane])
        ):
            raise RuntimeError("N05_MODEL_CELL_RESOURCE_LIMIT_MISMATCH")


def validate_effective_cgroups(snapshot: dict, *, cpuset: str, memory_bytes: int, pids: int) -> None:
    quota, period = snapshot["cpu_max"].split()
    if (
        not quota.isascii()
        or not quota.isdecimal()
        or not period.isascii()
        or not period.isdecimal()
        or int(period) <= 0
        or int(quota) != 2 * int(period)
        or cpu_set(snapshot["cpuset_cpus_effective"]) != cpu_set(cpuset)
        or snapshot["memory_limit_bytes"] != memory_bytes
        or snapshot["pids_limit"] != pids
    ):
        raise RuntimeError("EFFECTIVE_CGROUP_LIMITS_MISMATCH")


def stop_owned_model_cells(runtime: ThreeLaneRuntime) -> None:
    names = {cell.container for cell in runtime.cells}
    failures = []
    for cell in runtime.cells:
        try:
            cell.stop()
        except BaseException as exc:
            failures.append(type(exc).__name__)
    runtime.started = False
    remaining = set(docker("ps", "--all", "--format", "{{.Names}}").decode().splitlines())
    if failures or names & remaining:
        raise RuntimeError("OWNED_MODEL_CELL_CLEANUP_FAILED")


async def run_phase(
    *,
    phase_name: str,
    stress_lane: int | None,
    lock_path: Path,
    model_path: Path,
    output: Path,
    records: list[dict],
) -> dict:
    phase_root = output / ("phase-" + phase_name)
    runtime = ThreeLaneRuntime(lock_path, model_path, phase_root / "runtime")
    burner: str | None = None
    phase_result: dict = {"phase": phase_name, "stress_lane": stress_lane}
    try:
        runtime_inspection = runtime.start()
        check_model_limits(runtime, runtime_inspection)
        if stress_lane is not None:
            burner = start_burner(
                runtime.lock["defense_image"], runtime.admission.model_cpusets[stress_lane]
            )
        context = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
        sessions = [str(uuid4()) for _ in range(3)]
        for lane, session in enumerate(sessions):
            runtime.model.bind_session(session, lane, context)
        counter_start_ns = time.monotonic_ns()
        model_before = [cgroup_snapshot(cell.container) for cell in runtime.cells]
        burner_before = cgroup_snapshot(burner, python_image=True) if burner else None
        for lane, snapshot in enumerate(model_before):
            validate_effective_cgroups(
                snapshot,
                cpuset=runtime.admission.model_cpusets[lane],
                memory_bytes=2 * 1024 * 1024 * 1024,
                pids=128,
            )
        if burner_before is not None:
            validate_effective_cgroups(
                burner_before,
                cpuset=runtime.admission.model_cpusets[stress_lane],
                memory_bytes=256 * 1024 * 1024,
                pids=32,
            )
        inference_start_ns = time.monotonic_ns()
        phase_deadline = asyncio.get_running_loop().time() + PHASE_TIMEOUT_SECONDS
        calls: list[list[dict]] = [[], [], []]
        for index, record in enumerate(records):
            requests = [
                TargetRequest(
                    **context.model_dump(),
                    session_id=sessions[lane],
                    attempt_id=str(uuid4()),
                    turn_index=index,
                    text=record["text"],
                    max_output_tokens=OUTPUT_TOKEN_CAP,
                )
                for lane in range(3)
            ]
            remaining = phase_deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("PHASE_TIMEOUT")
            responses = await asyncio.wait_for(
                asyncio.gather(*(runtime.model.infer(request) for request in requests)),
                timeout=remaining,
            )
            for lane, response in enumerate(responses):
                calls[lane].append(
                    {
                        "input_tokens": response.input_tokens,
                        "output_tokens": response.output_tokens,
                        "duration_us": response.duration_us,
                        "output_sha256": sha256(response.text.encode("utf-8")),
                    }
                )
        inference_end_ns = time.monotonic_ns()
        model_after = [cgroup_snapshot(cell.container) for cell in runtime.cells]
        burner_after = cgroup_snapshot(burner, python_image=True) if burner else None
        counter_end_ns = time.monotonic_ns()
        for lane, snapshot in enumerate(model_after):
            validate_effective_cgroups(
                snapshot,
                cpuset=runtime.admission.model_cpusets[lane],
                memory_bytes=2 * 1024 * 1024 * 1024,
                pids=128,
            )
        if burner_after is not None:
            validate_effective_cgroups(
                burner_after,
                cpuset=runtime.admission.model_cpusets[stress_lane],
                memory_bytes=256 * 1024 * 1024,
                pids=32,
            )
        inference_elapsed_us = max(1, (inference_end_ns - inference_start_ns) // 1000)
        cgroup_elapsed_us = max(1, (counter_end_ns - counter_start_ns) // 1000)
        lanes = []
        for lane in range(3):
            output_tokens = sum(item["output_tokens"] for item in calls[lane])
            durations = sorted(item["duration_us"] for item in calls[lane])
            middle = len(durations) // 2
            median_duration_us = (
                durations[middle]
                if len(durations) % 2
                else (durations[middle - 1] + durations[middle]) // 2
            )
            lanes.append(
                {
                    "lane": lane,
                    "call_count": len(calls[lane]),
                    "input_tokens": sum(item["input_tokens"] for item in calls[lane]),
                    "output_tokens": output_tokens,
                    "inference_window_elapsed_us": inference_elapsed_us,
                    "output_tokens_per_second": round(output_tokens * 1_000_000 / inference_elapsed_us, 6),
                    "median_model_call_duration_us": median_duration_us,
                    "model_cgroup_delta": counter_delta(model_before[lane], model_after[lane]),
                    "calls": calls[lane],
                }
            )
        phase_result.update(
            {
                "result": "MEASURED",
                "runtime_scope": runtime_inspection["scope"],
                "host_cpu_exclusivity_verified": runtime_inspection["host_cpu_exclusivity_verified"],
                "fairness_measured_by_runtime": runtime_inspection["fairness_measured"],
                "model_cpusets": list(runtime.admission.model_cpusets),
                "lanes": lanes,
                "inference_window_elapsed_us": inference_elapsed_us,
                "cgroup_window_elapsed_us": cgroup_elapsed_us,
                "burner": (
                    {
                        "container_name_sha256": sha256(burner.encode("ascii")),
                        "cpuset_cpus": runtime.admission.model_cpusets[stress_lane],
                        "cpu_quota_cores": 2,
                        "memory_limit_bytes": 256 * 1024 * 1024,
                        "pids_limit": 32,
                        "network_mode": "none",
                        "nonroot_readonly_capdrop_no_new_privileges": True,
                        "cgroup_delta": counter_delta(burner_before, burner_after),
                        "cpu_cores_used": None,
                    }
                    if burner and burner_before and burner_after
                    else None
                ),
            }
        )
        if phase_result["burner"] is not None:
            cpu_delta = phase_result["burner"]["cgroup_delta"]["cpu_stat"].get("usage_usec", 0)
            phase_result["burner"]["cpu_cores_used"] = round(cpu_delta / cgroup_elapsed_us, 6)
            phase_result["burner"]["load_detected"] = (
                phase_result["burner"]["cpu_cores_used"] >= MINIMUM_STRESSOR_CPU_CORES
            )
        return phase_result
    finally:
        try:
            if burner is not None:
                remove_owned_container(burner)
        finally:
            stop_owned_model_cells(runtime)


def summarize(phases: list[dict]) -> dict:
    baselines = [phase for phase in phases if phase["stress_lane"] is None]
    if len(baselines) != 2:
        raise RuntimeError("MATCHED_BASELINE_PHASES_REQUIRED")
    baseline = {}
    for lane in range(3):
        baseline[lane] = sum(
            phase["lanes"][lane]["output_tokens_per_second"] for phase in baselines
        ) / len(baselines)
    stress_phases = [phase for phase in phases if phase["stress_lane"] is not None]
    if [phase["stress_lane"] for phase in stress_phases] != [0, 1, 2]:
        raise RuntimeError("ONE_CPU_LOAD_PHASE_PER_LANE_REQUIRED")
    lane_comparisons = []
    for phase in stress_phases:
        lane = phase["stress_lane"]
        values = phase["lanes"]
        tps = values[lane]["output_tokens_per_second"]
        base = baseline[lane]
        lane_comparisons.append(
            {
                "stress_lane": lane,
                "baseline_output_tokens_per_second_mean": round(base, 6),
                "loaded_output_tokens_per_second": tps,
                "loaded_to_baseline_ratio": round(tps / base, 6) if base else None,
                "relative_change_percent": round((tps / base - 1) * 100, 3) if base else None,
                "burner_cpu_cores_used": phase["burner"]["cpu_cores_used"],
                "load_detected": phase["burner"]["load_detected"],
                "observed_other_lane_output_tokens_per_second": {
                    str(other): values[other]["output_tokens_per_second"]
                    for other in range(3) if other != lane
                },
            }
        )
    all_load_detected = all(item["load_detected"] for item in lane_comparisons)
    return {
        "scope": SCOPE,
        "result": "CPU_LOAD_APPLIED" if all_load_detected else "INCONCLUSIVE_LOAD_NOT_DETECTED",
        "baseline_phases": len(baselines),
        "cpu_load_phases": len(stress_phases),
        "lane_comparisons": lane_comparisons,
        "minimum_stressor_cpu_cores_for_detected_load": MINIMUM_STRESSOR_CPU_CORES,
        "defense_verdicts_observed": False,
        "ram_pid_io_contention_applied": False,
        "host_or_hypervisor_cpu_exclusivity_verified": False,
        "full_p011_acceptance": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("lock", "model", "corpus", "corpus-receipt", "corpus-keys", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ARTIFACTS.resolve()) or output.exists():
        raise ValueError("NEW_PRIVATE_OUTPUT_DIRECTORY_REQUIRED_UNDER_BACKEND_ARTIFACTS")
    lock_path, model_path = args.lock.resolve(), args.model.resolve()
    corpus_root, corpus_receipt, corpus_keys = (
        args.corpus.resolve(), args.corpus_receipt.resolve(), args.corpus_keys.resolve()
    )
    if not all(path.is_file() for path in (lock_path, model_path, corpus_receipt, corpus_keys)):
        raise FileNotFoundError("ADMITTED_LOCAL_MODEL_OR_CORPUS_INPUT_MISSING")
    if not corpus_root.is_dir():
        raise FileNotFoundError("PREPARED_PUBLIC_CORPUS_DIRECTORY_MISSING")
    output.mkdir(parents=True, exist_ok=False)
    result: dict = {
        "schema_version": "arena-n07b-resource-fairness-observation.v1",
        "scope": SCOPE,
        "result": "INCONCLUSIVE",
        "runtime_downloads": False,
        "real_inference_performed": False,
        "real_public_jbb_used": False,
        "defense_verdicts_observed": False,
        "ram_pid_io_contention_applied": False,
        "full_p011_acceptance": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
        "lock_sha256": digest_file(lock_path),
        "model_sha256": digest_file(model_path),
        "corpus_receipt_sha256": digest_file(corpus_receipt),
    }
    phases: list[dict] = []
    try:
        ensure_local_docker()
        existing = running_containers()
        if existing:
            result["failure_code"] = "PREEXISTING_RUNNING_CONTAINERS_LEFT_UNTOUCHED"
            result["preexisting_running_container_count"] = len(existing)
            result["preexisting_running_container_name_sha256"] = sorted(
                sha256(name.encode("utf-8")) for name in existing
            )
            raise RuntimeError("PREEXISTING_RUNNING_CONTAINERS_LEFT_UNTOUCHED")
        admission = load_wire(LaneAdmission, Path(lock_path).read_bytes())
        corpus = PreparedPublicCorpus(
            corpus_root,
            corpus_receipt,
            corpus_keys,
            expected_receipt_sha256=admission.corpus_receipt_sha256,
        )
        records = pick_records(corpus)
        result["selected_public_records"] = [
            {key: value for key, value in item.items() if key != "text"}
            for item in records
        ]
        result["selected_records_per_split"] = RECORDS_PER_SPLIT
        result["selected_record_source"] = "JBB-Behaviors/REAL_PUBLIC"
        result["initial_running_container_count"] = 0
        preflight_burner(admission.defense_image)
        phases_to_run = [
            ("baseline-pre", None),
            ("cpu-load-lane-0", 0),
            ("cpu-load-lane-1", 1),
            ("cpu-load-lane-2", 2),
            ("baseline-post", None),
        ]
        for phase_name, stress_lane in phases_to_run:
            phase = asyncio.run(
                run_phase(
                    phase_name=phase_name,
                    stress_lane=stress_lane,
                    lock_path=lock_path,
                    model_path=model_path,
                    output=output,
                    records=records,
                )
            )
            phases.append(phase)
        summary = summarize(phases)
        result.update(
            {
                "phases": phases,
                "summary": summary,
                "result": summary["result"],
                "real_inference_performed": True,
                "real_public_jbb_used": True,
                "model_kind": "REAL_LOCAL_QWEN_0.5B_Q4_K_M",
                "phase_count": len(phases),
                "model_lane_count": 3,
                "calls_per_lane_per_phase": len(records),
                "total_model_calls": len(phases) * len(records) * 3,
                "output_token_cap_per_call": OUTPUT_TOKEN_CAP,
                "phase_timeout_seconds": PHASE_TIMEOUT_SECONDS,
                "runtime_downloads": False,
                "full_p011_acceptance": False,
                "full_n07_acceptance": False,
                "full_arena_acceptance": False,
                "guarantee_tier_achieved": None,
            }
        )
        return_code = 0 if result["result"] == "CPU_LOAD_APPLIED" else 2
    except BaseException as exc:
        result["result"] = "INCONCLUSIVE"
        failure = "PROBE_EXCEPTION_" + type(exc).__name__
        safe_message = str(exc)
        if isinstance(exc, RuntimeError) and re.fullmatch(r"[A-Z0-9_]+", safe_message):
            failure += ":" + safe_message
        result.setdefault("failure_code", failure)
        result["partial_phases"] = phases
        return_code = 1
    (output / "observation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = result.get("summary", {})
    print(
        json.dumps(
            {
                "result": result["result"],
                "scope": SCOPE,
                "phase_count": result.get("phase_count", len(phases)),
                "total_model_calls": result.get("total_model_calls"),
                "lane_comparisons": summary.get("lane_comparisons"),
                "defense_verdicts_observed": False,
                "ram_pid_io_contention_applied": False,
                "full_p011_acceptance": False,
                "full_n07_acceptance": False,
                "full_arena_acceptance": False,
                "guarantee_tier_achieved": None,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return return_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(json.dumps({"result": "FAIL", "reason": type(exc).__name__ + ": " + str(exc)}), file=sys.stderr)
        raise SystemExit(1)
