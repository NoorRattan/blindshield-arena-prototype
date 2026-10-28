"""Measure bounded RAM and lane-local PID pressure through N04/N05 turns.

Each of three blocks runs the same six admitted public JBB inputs once at
baseline, once with a resident RAM holder in the local Docker VM, and once
with idle processes occupying the selected model lane's existing pids cgroup.
Order is counterbalanced. I/O pressure is not attempted because the measured
VM did not expose an enforced io.max policy or a verified backing-device map.

The result is scoped resource-pressure evidence. It is not a fairness, SLA,
host-exclusivity, P-011/P-013, N07, or Arena-acceptance result.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import re
import sys
import statistics
import time
from types import SimpleNamespace
from uuid import uuid4


BACKEND = Path(__file__).resolve().parents[1]
ARTIFACTS = BACKEND / "artifacts"
SCOPE = "N07B_PAIRED_PUBLIC_JBB_RAM_AND_LANE_PID_PRESSURE_OBSERVATION"
SCHEMA = "arena-n07b-resource-ram-pid-pressure.v1"
TURNS_PER_PHASE = 6
BLOCKS = 3
PHASE_TIMEOUT_SECONDS = 600
RAM_TARGET_BYTES = 1536 * 1024 * 1024
RAM_LIMIT_BYTES = 2 * 1024 * 1024 * 1024
RAM_HEADROOM_CUSHION_BYTES = 1024 * 1024 * 1024
RAM_MINIMUM_RISE_BYTES = 1280 * 1024 * 1024
RAM_PIDS_LIMIT = 8
PID_PRESSURE_TASKS = 64
PID_REQUIRED_REMAINING = 24
PID_REAP_TIMEOUT_SECONDS = 5

sys.path.insert(0, str(BACKEND))

from arena.contracts.crypto import sha256  # noqa: E402
from arena.integration.lanes import ThreeLaneRuntime, capacity, cpu_set  # noqa: E402
from arena.integration.runtime import docker, ensure_local_docker  # noqa: E402
from tools import run_n07b_resource_fairness_verdict_matrix as base  # noqa: E402
from tools.run_n07b_resource_fairness_probe import (  # noqa: E402
    check_model_limits,
    counter_delta,
    cgroup_snapshot,
    remove_owned_container as remove_owned_docker_container,
    running_containers,
    validate_effective_cgroups,
)
from tools.verify_n04 import sources as backend_sources  # noqa: E402


RAM_HOLDER_SCRIPT = r'''import json, os, signal, sys, time

target = int(sys.argv[1])
safety_floor = int(sys.argv[2])
stopping = False
def request_stop(_signum, _frame):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, request_stop)
with open('/tmp/ready', 'w', encoding='ascii') as handle:
    handle.write('ready')
while not os.path.exists('/tmp/go'):
    time.sleep(0.05)
resident = bytearray(target)
page_size = os.sysconf('SC_PAGE_SIZE')
for offset in range(0, target, page_size):
    resident[offset] = 1
minimum_available = None
floor_crossed = False
released = False
while not stopping:
    values = {}
    for line in open('/proc/meminfo', encoding='ascii'):
        key, separator, value = line.partition(':')
        if separator and key == 'MemAvailable':
            values[key] = int(value.split()[0]) * 1024
            break
    available = values.get('MemAvailable')
    if available is None:
        floor_crossed = True
        resident = None
        released = True
        break
    minimum_available = available if minimum_available is None else min(minimum_available, available)
    if available < safety_floor:
        floor_crossed = True
        resident = None
        released = True
        break
    time.sleep(0.25)
print(json.dumps({
    'target_bytes': target,
    'minimum_mem_available_bytes': minimum_available,
    'safety_floor_bytes': safety_floor,
    'safety_floor_crossed': floor_crossed,
    'pressure_released_for_headroom': released,
}), flush=True)
'''

ACTIVE_RUNNER: "ResourceRunner | None" = None
ORIGINAL_CAPTURE = base.PhaseCapture
ORIGINAL_START_BURNER = base.start_burner
ORIGINAL_REMOVE_OWNED_CONTAINER = base.remove_owned_container


def phase_plan() -> list[dict]:
    orders = (
        ("BASELINE", "RAM_PRESSURE", "PID_PRESSURE"),
        ("PID_PRESSURE", "BASELINE", "RAM_PRESSURE"),
        ("RAM_PRESSURE", "PID_PRESSURE", "BASELINE"),
    )
    result = []
    for block, order in enumerate(orders, start=1):
        for condition in order:
            stress_lane = block - 1 if condition != "BASELINE" else None
            result.append(
                {
                    "phase": f"block-{block}-{condition.lower()}",
                    "block": block,
                    "condition": condition,
                    "stress_lane": stress_lane,
                }
            )
    return result


def all_container_names() -> set[str]:
    return {
        name
        for name in docker("ps", "--all", "--format", "{{.Names}}").decode().splitlines()
        if name
    }


def _read_cgroup_events(snapshot: dict) -> dict[str, int]:
    values = snapshot.get("memory_events")
    if not isinstance(values, dict) or not {"oom", "oom_kill"}.issubset(values):
        raise RuntimeError("MEMORY_EVENTS_UNAVAILABLE")
    return values


def _validate_memory_snapshot(snapshot: dict, cpuset: str) -> None:
    quota, period = snapshot["cpu_max"].split()
    if (
        not quota.isascii()
        or not quota.isdecimal()
        or not period.isascii()
        or not period.isdecimal()
        or int(period) <= 0
        or int(quota) * 4 != int(period)
        or cpu_set(snapshot["cpuset_cpus_effective"]) != cpu_set(cpuset)
        or snapshot["memory_limit_bytes"] != RAM_LIMIT_BYTES
        or snapshot["pids_limit"] != RAM_PIDS_LIMIT
    ):
        raise RuntimeError("RAM_STRESSOR_EFFECTIVE_CGROUP_LIMITS_MISMATCH")
    if snapshot["memory_peak_bytes"] is None:
        raise RuntimeError("MEMORY_PEAK_UNAVAILABLE")
    _read_cgroup_events(snapshot)


class ResourcePhaseCapture(ORIGINAL_CAPTURE):
    def __init__(self, scheduled: dict, output: Path):
        super().__init__(scheduled, output)
        self.mem_available_before: int | None = None
        self.mem_available_after: int | None = None
        self.resource_before: dict | None = None
        self.resource_after: dict | None = None
        self.model_container_names_before: list[str] | None = None
        self.model_container_names_after: list[str] | None = None

    def read_cgroups(self) -> dict:
        if self.runtime is None:
            raise RuntimeError("N05_RUNTIME_NOT_CAPTURED")
        models = [cgroup_snapshot(cell.container) for cell in self.runtime.cells]
        for lane, snapshot in enumerate(models):
            validate_effective_cgroups(
                snapshot,
                cpuset=self.runtime.admission.model_cpusets[lane],
                memory_bytes=RAM_LIMIT_BYTES,
                pids=128,
            )
        condition = self.scheduled["condition"]
        resource = None
        if condition == "RAM_PRESSURE":
            if not self.burner or self.burner not in ACTIVE_RUNNER.memory_containers:
                raise RuntimeError("RAM_STRESSOR_NOT_ACTIVE")
            resource = cgroup_snapshot(self.burner, python_image=True)
            _validate_memory_snapshot(
                resource,
                self.runtime.admission.model_cpusets[self.scheduled["stress_lane"]],
            )
        elif condition == "PID_PRESSURE":
            resource = models[self.scheduled["stress_lane"]]
        mem_available = capacity(self.runtime.admission.defense_image)["mem_available_bytes"]
        return {
            "models": models,
            "model_container_names": [cell.container for cell in self.runtime.cells],
            "burner": resource,
            "mem_available_bytes": mem_available,
        }

    async def begin_window(self) -> None:
        async with self.window_lock:
            if self.window_started:
                return
            if self.runtime is None:
                raise RuntimeError("N05_RUNTIME_NOT_CAPTURED")
            if self.scheduled["condition"] != "BASELINE":
                if ACTIVE_RUNNER is None:
                    raise RuntimeError("RESOURCE_RUNNER_NOT_ACTIVE")
                self.burner = ACTIVE_RUNNER.start_pressure(
                    self.scheduled,
                    self.runtime,
                    self.runtime.lock["defense_image"],
                    self.runtime.admission.model_cpusets[self.scheduled["stress_lane"]],
                )
                self.burner_name = self.burner
            before = await asyncio.to_thread(self.read_cgroups)
            self.model_before = before["models"]
            self.model_container_names_before = before["model_container_names"]
            self.burner_before = before["burner"]
            self.resource_before = before["burner"]
            self.mem_available_before = before["mem_available_bytes"]
            self.window_start_ns = time.monotonic_ns()
            self.window_started = True

    async def finish_window(self) -> None:
        async with self.window_lock:
            if self.window_finished or len(self.turns) != TURNS_PER_PHASE:
                return
            after = await asyncio.to_thread(self.read_cgroups)
            self.model_after = after["models"]
            self.model_container_names_after = after["model_container_names"]
            self.burner_after = after["burner"]
            self.resource_after = after["burner"]
            self.mem_available_after = after["mem_available_bytes"]
            self.window_end_ns = time.monotonic_ns()
            if self.model_before is None or self.model_after is None:
                raise RuntimeError("RESOURCE_WINDOW_CGROUPS_MISSING")
            for lane in range(3):
                self.counter_deltas[str(lane)] = counter_delta(
                    self.model_before[lane], self.model_after[lane]
                )
            if self.resource_before is not None and self.resource_after is not None:
                self.counter_deltas["burner"] = counter_delta(
                    self.resource_before, self.resource_after
                )
            self.window_finished = True

    def json_phase(self) -> dict:
        if (
            not self.window_finished
            or self.window_start_ns is None
            or self.window_end_ns is None
        ):
            raise RuntimeError("RESOURCE_WINDOW_INCOMPLETE")
        elapsed_us = max(1, (self.window_end_ns - self.window_start_ns) // 1000)
        runtime = self.runtime
        if runtime is None or self.cli_summary is None:
            raise RuntimeError("RESOURCE_PHASE_RUNTIME_OR_SUMMARY_MISSING")
        model_traces = base.measured_model_traces(
            self.turns, runtime.model.trace if runtime.model else []
        )
        resource_info = ACTIVE_RUNNER.pressure_results.get(self.scheduled["phase"])
        if self.scheduled["condition"] != "BASELINE":
            if resource_info is None:
                raise RuntimeError("RESOURCE_PRESSURE_RESULT_MISSING")
            resource_info = {
                **resource_info,
                "window_cgroup_delta": self.counter_deltas.get("burner"),
                "window_resource_current_bytes_after": (
                    self.resource_after["memory_current_bytes"]
                    if self.scheduled["condition"] == "RAM_PRESSURE"
                    else self.resource_after["pids_current"]
                ),
                "mem_available_before_bytes": self.mem_available_before,
                "mem_available_after_bytes": self.mem_available_after,
                "mem_available_floor_bytes": runtime.admission.minimum_available_memory_bytes,
                "model_cgroup_limits_unchanged": all(
                    self.counter_deltas[str(lane)].get("memory_limit_bytes") == RAM_LIMIT_BYTES
                    and self.counter_deltas[str(lane)].get("pids_limit") == 128
                    for lane in range(3)
                ),
            }
            if self.scheduled["condition"] == "PID_PRESSURE":
                resource_info["model_cell_container_matches_window_end"] = (
                    self.model_container_names_after is not None
                    and sha256(
                        self.model_container_names_after[
                            self.scheduled["stress_lane"]
                        ].encode("ascii")
                    )
                    == resource_info.get("model_cell_container_name_sha256")
                )
        return {
            **self.scheduled,
            "result": "MEASURED",
            "runtime_scope": "N05_THREE_PROCESS_BASELINE",
            "host_cpu_exclusivity_verified": False,
            "fairness_measured_by_runtime": False,
            "model_cpusets": list(runtime.admission.model_cpusets),
            "resource_window_elapsed_us": elapsed_us,
            "model_cgroup_delta": {
                str(lane): self.counter_deltas[str(lane)] for lane in range(3)
            },
            "resource_pressure": resource_info,
            "model_overlap": base.model_overlap_summary(model_traces),
            "model_overlap_scope": "N04_CONTROLLER_TURNS_ONLY; N05_STARTUP_CONFORMANCE_TRACES_EXCLUDED",
            "turns": sorted(
                self.turns,
                key=lambda item: (item["lane"], item["record_id_sha256"]),
            ),
            "private_run_path": self.output.relative_to(BACKEND).as_posix(),
            "n04_cli": {
                "run_label": self.cli_summary["run_label"],
                "defense_mode": self.cli_summary["defense_mode"],
                "real_model": self.cli_summary["real_model"],
                "turn_count": self.cli_summary["turns"],
                "model_dispatches": self.cli_summary["model_dispatches"],
                "verifier_exit_code": self.cli_summary["verifier_exit_code"],
                "verifier_status": self.cli_summary["verifier_result"]["status"],
                "three_lane_acceptance": self.cli_summary["three_lane_acceptance"],
                "n05_baseline_mechanisms_delivered": self.cli_summary[
                    "n05_baseline_mechanisms_delivered"
                ],
            },
        }

    def partial_json(self) -> dict:
        value = super().partial_json()
        value.update(
            {
                "condition": self.scheduled["condition"],
                "phase": self.scheduled["phase"],
                "block": self.scheduled["block"],
                "stress_lane": self.scheduled["stress_lane"],
                "private_run_path": self.output.relative_to(BACKEND).as_posix(),
            }
        )
        if ACTIVE_RUNNER is not None:
            value["resource_pressure"] = ACTIVE_RUNNER.pressure_results.get(
                self.scheduled["phase"]
            )
        return value


class ResourceRunner(base.MatrixRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.memory_containers: set[str] = set()
        self.pid_pools: dict[str, dict] = {}
        self.pressure_results: dict[str, dict] = {}
        self.phase: ResourcePhaseCapture | None = None
        self.original_globals: dict[str, object] = {}

    def install(self) -> None:
        global ACTIVE_RUNNER
        if ACTIVE_RUNNER is not None:
            raise RuntimeError("ANOTHER_RESOURCE_RUNNER_IS_ACTIVE")
        ACTIVE_RUNNER = self
        self.original_globals = {
            "PhaseCapture": base.PhaseCapture,
            "start_burner": base.start_burner,
            "remove_owned_container": base.remove_owned_container,
        }

        def deferred_start(_image: str, _cpuset: str) -> str:
            phase = self.phase
            if phase is None or phase.scheduled["condition"] == "BASELINE":
                raise RuntimeError("RESOURCE_STRESSOR_PHASE_MISSING")
            return "deferred:" + phase.scheduled["phase"]

        def owned_cleanup(name: str) -> None:
            if name.startswith("deferred:"):
                return
            self.stop_pressure(name)

        base.PhaseCapture = ResourcePhaseCapture
        base.start_burner = deferred_start
        base.remove_owned_container = owned_cleanup
        super().install()

    def restore(self) -> None:
        global ACTIVE_RUNNER
        super().restore()
        if self.original_globals:
            base.PhaseCapture = self.original_globals["PhaseCapture"]
            base.start_burner = self.original_globals["start_burner"]
            base.remove_owned_container = self.original_globals[
                "remove_owned_container"
            ]
            self.original_globals.clear()
        if ACTIVE_RUNNER is self:
            ACTIVE_RUNNER = None

    def start_pressure(
        self, scheduled: dict, runtime: ThreeLaneRuntime, image: str, cpuset: str
    ) -> str:
        if scheduled["condition"] == "RAM_PRESSURE":
            return self.start_ram_pressure(scheduled, runtime, image, cpuset)
        if scheduled["condition"] == "PID_PRESSURE":
            return self.start_pid_pressure(scheduled, runtime)
        raise RuntimeError("UNKNOWN_RESOURCE_PRESSURE_CONDITION")

    def start_ram_pressure(
        self, scheduled: dict, runtime: ThreeLaneRuntime, image: str, cpuset: str
    ) -> str:
        floor = runtime.admission.minimum_available_memory_bytes + RAM_HEADROOM_CUSHION_BYTES
        available_before = capacity(image)["mem_available_bytes"]
        if available_before < floor + RAM_TARGET_BYTES:
            raise RuntimeError("RAM_PRESSURE_PREFLIGHT_HEADROOM_TOO_LOW")
        name = "arena-n07b-resource-ram-" + uuid4().hex
        self.memory_containers.add(name)
        try:
            docker(
                "run", "--detach", "--pull", "never", "--name", name,
                "--label", "arena.n07b.resource-ram=true", "--network", "none",
                "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--memory", "2g",
                "--memory-swap", "2g", "--cpus", "0.25", "--cpuset-cpus", cpuset,
                "--pids-limit", str(RAM_PIDS_LIMIT), "--log-driver", "json-file",
                "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m", "--entrypoint", "python",
                image, "-I", "-c", RAM_HOLDER_SCRIPT, str(RAM_TARGET_BYTES), str(floor),
            )
            config = json.loads(docker("inspect", name))[0]
            host = config["HostConfig"]
            if not (
                config["State"]["Running"]
                and config["Config"]["User"] == "65534:65534"
                and config["Config"]["Labels"].get("arena.n07b.resource-ram") == "true"
                and host["ReadonlyRootfs"]
                and not host["Privileged"]
                and host["CapDrop"] == ["ALL"]
                and "no-new-privileges" in host["SecurityOpt"]
                and host["Memory"] == RAM_LIMIT_BYTES
                and host["MemorySwap"] == RAM_LIMIT_BYTES
                and host["NanoCpus"] == 250_000_000
                and host["PidsLimit"] == RAM_PIDS_LIMIT
                and host["NetworkMode"] == "none"
                and cpu_set(host["CpusetCpus"]) == cpu_set(cpuset)
            ):
                raise RuntimeError("RAM_STRESSOR_CONTAINER_POLICY_MISMATCH")
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                ready = json.loads(docker(
                    "exec", name, "python", "-I", "-c",
                    "import json; from pathlib import Path; print(json.dumps({'ready':Path('/tmp/ready').is_file()}))",
                ).decode("ascii", errors="strict"))
                if ready.get("ready") is True:
                    before_load = cgroup_snapshot(name, python_image=True)
                    _validate_memory_snapshot(before_load, cpuset)
                    docker(
                        "exec", name, "python", "-I", "-c",
                        "from pathlib import Path; Path('/tmp/go').touch()",
                    )
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("RAM_STRESSOR_READY_TIMEOUT")
            deadline = time.monotonic() + 45
            loaded = None
            while time.monotonic() < deadline:
                loaded = cgroup_snapshot(name, python_image=True)
                _validate_memory_snapshot(loaded, cpuset)
                if (
                    loaded["memory_current_bytes"] - before_load["memory_current_bytes"]
                    >= RAM_MINIMUM_RISE_BYTES
                ):
                    break
                if not json.loads(docker("inspect", name))[0]["State"]["Running"]:
                    raise RuntimeError("RAM_STRESSOR_EXITED_BEFORE_LOAD")
                time.sleep(0.25)
            if loaded is None or loaded["memory_current_bytes"] - before_load["memory_current_bytes"] < RAM_MINIMUM_RISE_BYTES:
                raise RuntimeError("RAM_PRESSURE_NOT_DETECTED")
            available_after = capacity(image)["mem_available_bytes"]
            events_before = _read_cgroup_events(before_load)
            events_after = _read_cgroup_events(loaded)
            if (
                available_after < floor
                or events_after["oom"] != events_before["oom"]
                or events_after["oom_kill"] != events_before["oom_kill"]
            ):
                raise RuntimeError("RAM_PRESSURE_HEADROOM_OR_OOM_GUARD_FAILED")
            self.pressure_results[scheduled["phase"]] = {
                "kind": "VM_SHARED_RESIDENT_RAM_CGROUP",
                "stressor_container_name_sha256": sha256(name.encode("ascii")),
                "target_bytes": RAM_TARGET_BYTES,
                "memory_limit_bytes": RAM_LIMIT_BYTES,
                "memory_swap_limit_bytes": RAM_LIMIT_BYTES,
                "pids_limit": RAM_PIDS_LIMIT,
                "cpuset_cpus": cpuset,
                "cpu_quota_cores": 0.25,
                "network_mode": "none",
                "nonroot_readonly_capdrop_no_new_privileges": True,
                "available_before_bytes": available_before,
                "available_after_allocation_bytes": available_after,
                "minimum_required_available_bytes": floor,
                "allocation_cgroup_current_before_bytes": before_load["memory_current_bytes"],
                "allocation_cgroup_current_after_bytes": loaded["memory_current_bytes"],
                "allocation_cgroup_rise_bytes": loaded["memory_current_bytes"] - before_load["memory_current_bytes"],
                "allocation_memory_peak_bytes": loaded["memory_peak_bytes"],
                "allocation_memory_events_delta": counter_delta(before_load, loaded)["memory_events_delta"],
                "safety_floor_crossed": False,
                "cleanup_completed": False,
            }
            return name
        except BaseException:
            try:
                self.stop_pressure(name)
            except BaseException:
                pass
            raise

    def start_pid_pressure(self, scheduled: dict, runtime: ThreeLaneRuntime) -> str:
        lane = scheduled["stress_lane"]
        container = runtime.cells[lane].container
        before = cgroup_snapshot(container)
        if before["pids_limit"] != 128:
            raise RuntimeError("PID_MODEL_CGROUP_LIMIT_MISMATCH")
        if before["pids_limit"] - before["pids_current"] < PID_PRESSURE_TASKS + PID_REQUIRED_REMAINING + 2:
            raise RuntimeError("PID_PRESSURE_SAFE_HEADROOM_UNAVAILABLE")
        token = uuid4().hex
        name = "arena-n07b-pid-lane-" + str(lane) + "-" + token
        pid_file = "/tmp/" + name + ".pids"
        ready_file = "/tmp/" + name + ".ready"
        supervisor_file = "/tmp/" + name + ".supervisor"
        script = (
            f"pid_file='{pid_file}'; ready_file='{ready_file}'; supervisor_file='{supervisor_file}'; "
            ": > \"$pid_file\"; printf '%s\\n' \"$$\" > \"$supervisor_file\"; "
            f"i=0; while [ \"$i\" -lt {PID_PRESSURE_TASKS} ]; do "
            "sleep 3600 </dev/null >/dev/null 2>&1 & printf '%s\\n' \"$!\" >> \"$pid_file\"; "
            "i=$((i+1)); done; : > \"$ready_file\"; wait"
        )
        pool = {
            "container": container,
            "lane": lane,
            "children": [],
            "supervisor": None,
            "pid_file": pid_file,
            "ready_file": ready_file,
            "supervisor_file": supervisor_file,
            "pids_current_before": before["pids_current"],
            "pids_limit": before["pids_limit"],
            "cleanup_completed": False,
            "ready": False,
        }
        self.pid_pools[name] = pool
        try:
            docker("exec", "--detach", container, "/bin/sh", "-c", script)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                result = docker(
                    "exec", container, "/bin/sh", "-c",
                    f"if [ -f '{supervisor_file}' ]; then printf 'SUPERVISOR:'; cat '{supervisor_file}'; fi; "
                    f"if [ -f '{ready_file}' ]; then printf 'READY\\n'; fi; "
                    f"if [ -f '{pid_file}' ]; then printf 'CHILDREN\\n'; cat '{pid_file}'; fi",
                ).decode("ascii", errors="strict")
                lines = [line.strip() for line in result.splitlines() if line.strip()]
                supervisor_line = next(
                    (line for line in lines if line.startswith("SUPERVISOR:")), None
                )
                if supervisor_line is not None:
                    supervisor = supervisor_line.removeprefix("SUPERVISOR:")
                    if not supervisor.isascii() or not supervisor.isdecimal():
                        raise RuntimeError("PID_PRESSURE_SUPERVISOR_ID_INVALID")
                    pool["supervisor"] = supervisor
                if "CHILDREN" in lines:
                    child_lines = lines[lines.index("CHILDREN") + 1:]
                    if any(not item.isascii() or not item.isdecimal() for item in child_lines):
                        raise RuntimeError("PID_PRESSURE_CHILD_SET_INVALID")
                    pool["children"] = child_lines
                ready = "READY" in lines
                if ready:
                    children = pool["children"]
                    supervisor = pool["supervisor"]
                    if len(children) != PID_PRESSURE_TASKS or supervisor is None:
                        raise RuntimeError("PID_PRESSURE_CHILD_SET_INVALID")
                    after = cgroup_snapshot(container)
                    if after["pids_current"] - before["pids_current"] < PID_PRESSURE_TASKS:
                        raise RuntimeError("PID_PRESSURE_NOT_DETECTED_IN_MODEL_CGROUP")
                    if after["pids_limit"] - after["pids_current"] < PID_REQUIRED_REMAINING:
                        raise RuntimeError("PID_PRESSURE_REQUIRED_HEADROOM_NOT_RETAINED")
                    pool["pids_current_after_start"] = after["pids_current"]
                    pool["pids_current_delta"] = after["pids_current"] - before["pids_current"]
                    pool["pids_limit"] = after["pids_limit"]
                    pool["ready"] = True
                    self.pressure_results[scheduled["phase"]] = {
                        "kind": "SELECTED_MODEL_LANE_PIDS_CGROUP_OCCUPANCY",
                        "lane": lane,
                        "model_cell_container_name_sha256": sha256(container.encode("ascii")),
                        "idle_child_process_count_requested": PID_PRESSURE_TASKS,
                        "pid_cgroup_limit": after["pids_limit"],
                        "minimum_remaining_slots": PID_REQUIRED_REMAINING,
                        "pids_current_before": before["pids_current"],
                        "pids_current_after_start": after["pids_current"],
                        "pids_current_delta": after["pids_current"] - before["pids_current"],
                        "same_model_cell_cgroup": True,
                        "children_idle": True,
                        "network_mode": "none",
                        "cleanup_completed": False,
                    }
                    return name
                time.sleep(0.1)
            raise RuntimeError("PID_PRESSURE_READY_TIMEOUT")
        except BaseException:
            try:
                self.stop_pressure(name)
            except BaseException:
                # The enclosing N04 runtime stop removes this lane container;
                # the observation remains INCONCLUSIVE if cleanup was incomplete.
                pass
            raise

    def stop_pressure(self, handle: str) -> None:
        if handle in self.memory_containers:
            name = handle
            state = None
            try:
                docker("stop", "--time", "5", name)
                logs = docker("logs", name).decode("utf-8", errors="replace")
                records = []
                for line in logs.splitlines():
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(value, dict) and "target_bytes" in value:
                        records.append(value)
                if len(records) != 1:
                    raise RuntimeError("RAM_STRESSOR_FINAL_LOG_INVALID")
                state = json.loads(docker("inspect", name))[0]["State"]
                if state.get("OOMKilled") or records[0].get("safety_floor_crossed") is not False:
                    raise RuntimeError("RAM_STRESSOR_OOM_OR_SAFETY_FLOOR_TRIP")
                docker("rm", "--force", name)
                self.memory_containers.remove(name)
                for item in self.pressure_results.values():
                    if item.get("stressor_container_name_sha256") == sha256(name.encode("ascii")):
                        item["minimum_mem_available_bytes"] = records[0].get("minimum_mem_available_bytes")
                        item["safety_floor_crossed"] = records[0].get("safety_floor_crossed")
                        item["pressure_released_for_headroom"] = records[0].get("pressure_released_for_headroom")
                        item["stressor_exit_code"] = state.get("ExitCode")
                        item["oom_killed"] = state.get("OOMKilled")
                        item["cleanup_completed"] = True
                return
            finally:
                names = all_container_names()
                if name in names:
                    remove_owned_docker_container(name)
                    self.memory_containers.discard(name)
            
        pool = self.pid_pools.get(handle)
        if pool is not None:
            container = pool["container"]
            if container not in all_container_names():
                phase = self.phase
                end_snapshot = (
                    phase.resource_after
                    if phase is not None
                    and phase.scheduled["condition"] == "PID_PRESSURE"
                    and phase.resource_after is not None
                    else None
                )
                end_name = (
                    phase.model_container_names_after[pool["lane"]]
                    if phase is not None
                    and phase.model_container_names_after is not None
                    else None
                )
                if (
                    phase is None
                    or not phase.window_finished
                    or end_name != container
                    or end_snapshot is None
                    or end_snapshot.get("pids_current", 0)
                    < pool["pids_current_before"] + PID_PRESSURE_TASKS
                    or end_snapshot.get("pids_limit", 0)
                    - end_snapshot.get("pids_current", 999)
                    < PID_REQUIRED_REMAINING
                    or pool.get("ready") is not True
                ):
                    pool["cleanup_completed"] = False
                    raise RuntimeError("PID_PRESSURE_CONTAINER_REMOVED_BEFORE_VERIFIED_WINDOW_END")
                pool["pids_current_at_window_end"] = end_snapshot["pids_current"]
                pool["container_removed_after_window_end"] = True
                pool["all_pool_pids_absent_after_cleanup"] = True
                pool["cleanup_method"] = "N05_CELL_REMOVED_AFTER_WINDOW_CAPTURE"
                pool["pids_current_before_cleanup"] = None
                pool["pids_current_after_cleanup"] = None
                pool["cleanup_completed"] = True
                for item in self.pressure_results.values():
                    if item.get("lane") == pool["lane"] and item.get("kind") == "SELECTED_MODEL_LANE_PIDS_CGROUP_OCCUPANCY" and item.get("cleanup_completed") is False:
                        item.update(
                            {
                                "pids_current_at_window_end": end_snapshot["pids_current"],
                                "container_removed_after_window_end": True,
                                "all_pool_pids_absent_after_cleanup": True,
                                "cleanup_method": "N05_CELL_REMOVED_AFTER_WINDOW_CAPTURE",
                                "pids_current_before_cleanup": None,
                                "pids_current_after_cleanup": None,
                                "cleanup_completed": True,
                            }
                        )
                del self.pid_pools[handle]
                return
            before_cleanup = cgroup_snapshot(container)
            pool_pids = list(pool["children"])
            supervisor = pool.get("supervisor")
            if supervisor is not None:
                pool_pids.append(supervisor)
            if any(not pid.isascii() or not pid.isdecimal() for pid in pool_pids):
                pool["cleanup_completed"] = False
                raise RuntimeError("PID_PRESSURE_TRACKED_PID_SET_INVALID")
            child_pids = list(pool["children"])
            child_signal = "kill -TERM " + " ".join(child_pids) + " 2>/dev/null || true; " if child_pids else ""
            supervisor_signal = (
                f"kill -TERM {supervisor} 2>/dev/null || true; "
                if supervisor is not None
                else ""
            )
            signal_script = (
                child_signal
                if pool.get("ready") is True
                else supervisor_signal + child_signal
            )
            docker("exec", container, "/bin/sh", "-c", signal_script)

            def live_pool_pids() -> list[str]:
                if not pool_pids:
                    return []
                check_script = (
                    "for pid in " + " ".join(pool_pids) + "; do "
                    "if kill -0 \"$pid\" 2>/dev/null; then printf '%s\\n' \"$pid\"; fi; "
                    "done"
                )
                return [
                    line.strip()
                    for line in docker(
                        "exec", container, "/bin/sh", "-c", check_script
                    ).decode("ascii", errors="strict").splitlines()
                    if line.strip()
                ]

            deadline = time.monotonic() + PID_REAP_TIMEOUT_SECONDS
            supervisor_stop_at = time.monotonic() + 1
            after_cleanup = cgroup_snapshot(container)
            remaining = live_pool_pids()
            while remaining and time.monotonic() < deadline:
                if (
                    pool.get("ready") is True
                    and supervisor is not None
                    and supervisor in remaining
                    and time.monotonic() >= supervisor_stop_at
                ):
                    docker(
                        "exec", container, "/bin/sh", "-c",
                        f"kill -TERM {supervisor} 2>/dev/null || true",
                    )
                    supervisor_stop_at = deadline
                time.sleep(0.1)
                after_cleanup = cgroup_snapshot(container)
                remaining = live_pool_pids()
            if (
                remaining
                or pool.get("ready") is not True
                or after_cleanup["pids_current"] > pool["pids_current_before"] + 2
            ):
                pool["cleanup_completed"] = False
                raise RuntimeError("PID_PRESSURE_CHILDREN_NOT_REAPED")
            pool["pids_current_before_cleanup"] = before_cleanup["pids_current"]
            pool["pids_current_after_cleanup"] = after_cleanup["pids_current"]
            pool["all_pool_pids_absent_after_cleanup"] = True
            pool["container_removed_after_window_end"] = False
            pool["cleanup_method"] = "EXACT_RECORDED_PID_SET_REAPED"
            pool["cleanup_completed"] = True
            for item in self.pressure_results.values():
                if item.get("lane") == pool["lane"] and item.get("kind") == "SELECTED_MODEL_LANE_PIDS_CGROUP_OCCUPANCY" and item.get("cleanup_completed") is False:
                    item["pids_current_before_cleanup"] = before_cleanup["pids_current"]
                    item["pids_current_after_cleanup"] = after_cleanup["pids_current"]
                    item["all_pool_pids_absent_after_cleanup"] = True
                    item["container_removed_after_window_end"] = False
                    item["cleanup_method"] = "EXACT_RECORDED_PID_SET_REAPED"
                    item["cleanup_completed"] = True
            del self.pid_pools[handle]
            return
        raise RuntimeError("UNKNOWN_OWNED_RESOURCE_STRESSOR")


def analyze_phases(phases: list[dict]) -> dict:
    expected = phase_plan()
    if len(phases) != len(expected):
        raise ValueError("RAM_PID_PHASE_COUNT_MISMATCH")
    by_block_condition: dict[tuple[int, str], dict] = {}
    verdicts: dict[str, int] = {}
    common_case_set: set[tuple[int, str, str, int]] | None = None
    for phase, scheduled in zip(phases, expected, strict=True):
        if (
            any(phase.get(key) != scheduled[key] for key in ("phase", "block", "condition", "stress_lane"))
            or phase.get("result") != "MEASURED"
            or len(phase.get("turns", [])) != TURNS_PER_PHASE
            or phase.get("n04_cli", {}).get("run_label") != "REAL_PUBLIC"
            or phase.get("n04_cli", {}).get("defense_mode") != "INPUT"
            or phase.get("n04_cli", {}).get("real_model") is not True
            or phase.get("n04_cli", {}).get("three_lane_acceptance") is not False
            or phase.get("n04_cli", {}).get("n05_baseline_mechanisms_delivered") is not True
            or phase.get("n04_cli", {}).get("turn_count") != TURNS_PER_PHASE
            or phase.get("n04_cli", {}).get("verifier_exit_code") != 0
            or phase.get("n04_cli", {}).get("verifier_status") != "PASS_PUBLIC_EVIDENCE"
        ):
            raise ValueError("RAM_PID_PHASE_INVALID_OR_N04_VERIFICATION_FAILED")
        model_deltas = phase.get("model_cgroup_delta")
        if not isinstance(model_deltas, dict):
            raise ValueError("MODEL_CGROUP_WINDOW_DELTA_MISSING")
        for lane in range(3):
            events = model_deltas.get(str(lane), {}).get("memory_events_delta")
            if (
                not isinstance(events, dict)
                or type(events.get("oom")) is not int
                or type(events.get("oom_kill")) is not int
                or events["oom"] != 0
                or events["oom_kill"] != 0
            ):
                raise ValueError("MODEL_CGROUP_OOM_EVENT_OBSERVED_OR_UNAVAILABLE")
        if phase["condition"] == "BASELINE":
            if phase.get("resource_pressure") is not None:
                raise ValueError("BASELINE_CONTAINS_RESOURCE_STRESSOR")
        else:
            pressure = phase.get("resource_pressure")
            if not isinstance(pressure, dict) or pressure.get("cleanup_completed") is not True:
                raise ValueError("RESOURCE_PRESSURE_OR_CLEANUP_NOT_VERIFIED")
            if phase["condition"] == "RAM_PRESSURE" and (
                pressure.get("kind") != "VM_SHARED_RESIDENT_RAM_CGROUP"
                or pressure.get("safety_floor_crossed") is not False
                or pressure.get("pressure_released_for_headroom") is not False
                or pressure.get("stressor_exit_code") != 0
                or pressure.get("oom_killed") is not False
                or type(pressure.get("minimum_mem_available_bytes")) is not int
                or pressure["minimum_mem_available_bytes"] < pressure["minimum_required_available_bytes"]
                or pressure.get("allocation_cgroup_rise_bytes", 0) < RAM_MINIMUM_RISE_BYTES
                or pressure.get("mem_available_after_bytes", 0) < pressure.get("minimum_required_available_bytes", 1)
                or pressure.get("allocation_cgroup_current_after_bytes", 0)
                - pressure.get("allocation_cgroup_current_before_bytes", 0)
                < RAM_MINIMUM_RISE_BYTES
                or pressure.get("window_resource_current_bytes_after", 0)
                - pressure.get("allocation_cgroup_current_before_bytes", 0)
                < RAM_MINIMUM_RISE_BYTES
                or not isinstance(pressure.get("allocation_memory_events_delta"), dict)
                or pressure["allocation_memory_events_delta"].get("oom") != 0
                or pressure["allocation_memory_events_delta"].get("oom_kill") != 0
                or not isinstance(pressure.get("window_cgroup_delta"), dict)
                or not isinstance(
                    pressure.get("window_cgroup_delta", {}).get("memory_events_delta"), dict
                )
                or pressure["window_cgroup_delta"].get("memory_events_delta", {}).get("oom") != 0
                or pressure["window_cgroup_delta"].get("memory_events_delta", {}).get("oom_kill") != 0
            ):
                raise ValueError("RAM_PRESSURE_ASSERTION_FAILED")
            if phase["condition"] == "PID_PRESSURE" and (
                pressure.get("kind") != "SELECTED_MODEL_LANE_PIDS_CGROUP_OCCUPANCY"
                or pressure.get("same_model_cell_cgroup") is not True
                or pressure.get("children_idle") is not True
                or pressure.get("model_cell_container_matches_window_end") is not True
                or pressure.get("pids_current_delta", 0) < PID_PRESSURE_TASKS
                or not isinstance(pressure.get("window_cgroup_delta"), dict)
                or pressure["window_cgroup_delta"].get("pids_current_after", 0)
                < pressure.get("pids_current_before", 0) + PID_PRESSURE_TASKS
                or pressure.get("pid_cgroup_limit", 0)
                - pressure.get("window_cgroup_delta", {}).get("pids_current_after", 999)
                < PID_REQUIRED_REMAINING
                or pressure.get("all_pool_pids_absent_after_cleanup") is not True
                or pressure.get("cleanup_method") not in {
                    "EXACT_RECORDED_PID_SET_REAPED",
                    "N05_CELL_REMOVED_AFTER_WINDOW_CAPTURE",
                }
                or (
                    pressure.get("cleanup_method") == "EXACT_RECORDED_PID_SET_REAPED"
                    and pressure.get("pids_current_after_cleanup", 999)
                    > pressure.get("pids_current_before", 0) + 2
                )
                or (
                    pressure.get("cleanup_method") == "N05_CELL_REMOVED_AFTER_WINDOW_CAPTURE"
                    and (
                        pressure.get("container_removed_after_window_end") is not True
                        or pressure.get("pids_current_after_cleanup") is not None
                    )
                )
            ):
                raise ValueError("PID_PRESSURE_ASSERTION_FAILED")
        keys = set()
        for turn in phase["turns"]:
            verdict = turn.get("verdict")
            if verdict not in {"ALLOW", "BLOCK", "SANITIZE"}:
                raise ValueError("DEFENSE_VERDICT_INVALID")
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
            if turn.get("defense_event_outcome") != verdict:
                raise ValueError("DEFENSE_EVENT_OUTCOME_MISMATCH")
            expected_disposition = {
                "ALLOW": "ALLOWED",
                "BLOCK": "BLOCKED_BY_DEFENSE",
                "SANITIZE": "SANITIZED",
            }[verdict]
            if turn.get("pipeline_disposition") != expected_disposition:
                raise ValueError("DEFENSE_DISPOSITION_MISMATCH")
            if turn.get("model_execution") not in {"EXECUTED", "NOT_EVALUATED"}:
                raise ValueError("MODEL_EXECUTION_STATE_INVALID")
            if (verdict == "BLOCK") != (turn["model_execution"] == "NOT_EVALUATED"):
                raise ValueError("INPUT_BLOCK_MODEL_DISPATCH_BOUNDARY_INVALID")
            if type(turn.get("controller_latency_us")) is not int or turn["controller_latency_us"] <= 0:
                raise ValueError("CONTROLLER_LATENCY_INVALID")
            if (turn["model_execution"] == "EXECUTED") != (type(turn.get("model_latency_us")) is int):
                raise ValueError("MODEL_LATENCY_EXECUTION_STATE_MISMATCH")
            if type(turn.get("model_latency_us")) is int and turn["model_latency_us"] <= 0:
                raise ValueError("MODEL_LATENCY_INVALID")
            key = (turn.get("lane"), turn.get("record_id_sha256"), turn.get("prompt_sha256"), turn.get("turn_index"))
            if key in keys:
                raise ValueError("DUPLICATE_PHASE_TURN_KEY")
            keys.add(key)
        if len(keys) != TURNS_PER_PHASE or {key[0] for key in keys} != {0, 1, 2}:
            raise ValueError("PHASE_CASE_SET_INVALID")
        if phase["n04_cli"].get("model_dispatches") != sum(
            turn["model_execution"] == "EXECUTED" for turn in phase["turns"]
        ):
            raise ValueError("N04_MODEL_DISPATCH_COUNT_MISMATCH")
        if common_case_set is None:
            common_case_set = keys
        elif keys != common_case_set:
            raise ValueError("FIXED_PUBLIC_JBB_CASE_SET_CHANGED")
        by_block_condition[(phase["block"], phase["condition"])] = phase
    paired = []
    outcome_drift = 0
    model_response_drift = 0
    for block in range(1, BLOCKS + 1):
        baseline = by_block_condition[(block, "BASELINE")]
        baseline_turns = {
            (item["lane"], item["record_id_sha256"], item["prompt_sha256"], item["turn_index"]): item
            for item in baseline["turns"]
        }
        for condition in ("RAM_PRESSURE", "PID_PRESSURE"):
            stressed = by_block_condition[(block, condition)]
            stressed_turns = {
                (item["lane"], item["record_id_sha256"], item["prompt_sha256"], item["turn_index"]): item
                for item in stressed["turns"]
            }
            if set(stressed_turns) != set(baseline_turns):
                raise ValueError("BASELINE_STRESS_CASE_SET_MISMATCH")
            for key in sorted(baseline_turns):
                left, right = baseline_turns[key], stressed_turns[key]
                outcome_same = (
                    left["verdict"], left["pipeline_disposition"], left["model_execution"]
                ) == (
                    right["verdict"], right["pipeline_disposition"], right["model_execution"]
                )
                outcome_drift += int(not outcome_same)
                response_same = None
                if left["model_execution"] == right["model_execution"] == "EXECUTED":
                    response_same = left.get("model_output_sha256") == right.get("model_output_sha256")
                    model_response_drift += int(not response_same)
                paired.append(
                    {
                        "block": block,
                        "condition": condition,
                        "lane": key[0],
                        "record_id_sha256": key[1],
                        "prompt_sha256": key[2],
                        "turn_index": key[3],
                        "outcome_stable": outcome_same,
                        "model_response_hash_match": response_same,
                        "model_token_counts_match": (
                            left.get("model_input_tokens"), left.get("model_output_tokens")
                        ) == (
                            right.get("model_input_tokens"), right.get("model_output_tokens")
                        ) if response_same is not None else None,
                        "controller_latency_baseline_us": left["controller_latency_us"],
                        "controller_latency_stress_us": right["controller_latency_us"],
                        "controller_latency_change_percent": round(
                            (right["controller_latency_us"] - left["controller_latency_us"])
                            * 100 / left["controller_latency_us"],
                            6,
                        ),
                        "model_latency_baseline_us": left["model_latency_us"],
                        "model_latency_stress_us": right["model_latency_us"],
                        "model_latency_change_percent": (
                            round(
                                (right["model_latency_us"] - left["model_latency_us"])
                                * 100 / left["model_latency_us"],
                                6,
                            )
                            if type(left.get("model_latency_us")) is int
                            and type(right.get("model_latency_us")) is int
                            and left["model_latency_us"] > 0
                            else None
                        ),
                    }
                )
    controller_changes = [item["controller_latency_change_percent"] for item in paired]
    model_changes = [
        item["model_latency_change_percent"]
        for item in paired
        if item["model_latency_change_percent"] is not None
    ]
    if outcome_drift:
        result_status = "OUTCOME_DRIFT_OBSERVED"
    elif model_response_drift:
        result_status = "MODEL_RESPONSE_DRIFT_OBSERVED"
    else:
        result_status = "RAM_PID_PRESSURE_PAIRED_OBSERVED"

    def latency_summary(rows: list[dict], key: str) -> dict:
        changes = [row[key] for row in rows if row[key] is not None]
        return {
            "median_percent": round(statistics.median(changes), 6) if changes else None,
            "min_percent": min(changes) if changes else None,
            "max_percent": max(changes) if changes else None,
            "pair_count": len(changes),
        }

    by_condition = {}
    for condition in ("RAM_PRESSURE", "PID_PRESSURE"):
        rows = [row for row in paired if row["condition"] == condition]
        by_condition[condition] = {
            "controller": latency_summary(rows, "controller_latency_change_percent"),
            "model": latency_summary(rows, "model_latency_change_percent"),
        }
    return {
        "result": result_status,
        "phase_count": len(phases),
        "block_count": BLOCKS,
        "turn_count": sum(len(phase["turns"]) for phase in phases),
        "model_dispatch_count": sum(
            turn["model_execution"] == "EXECUTED" for phase in phases for turn in phase["turns"]
        ),
        "baseline_to_resource_pair_count": len(paired),
        "verdict_distribution": verdicts,
        "observed_verdict_count": len(verdicts),
        "varied_defense_outcomes_observed": len(verdicts) > 1,
        "defense_outcome_coverage": (
            "VARIED_OUTCOMES_OBSERVED"
            if len(verdicts) > 1
            else f"SINGLE_OUTCOME_{next(iter(verdicts))}"
        ),
        "defense_outcome_drift_count": outcome_drift,
        "model_response_hash_drift_count": model_response_drift,
        "model_token_count_drift_count": sum(
            row["model_token_counts_match"] is False for row in paired
        ),
        "latency_change_summary": {
            "controller_percent_median": round(statistics.median(controller_changes), 6) if controller_changes else None,
            "controller_percent_min": min(controller_changes) if controller_changes else None,
            "controller_percent_max": max(controller_changes) if controller_changes else None,
            "controller_pair_count": len(controller_changes),
            "model_percent_median": round(statistics.median(model_changes), 6) if model_changes else None,
            "model_percent_min": min(model_changes) if model_changes else None,
            "model_percent_max": max(model_changes) if model_changes else None,
            "model_pair_count": len(model_changes),
        },
        "latency_change_by_condition": by_condition,
        "paired_rows": paired,
        "ram_pressure_observed": all(
            phase["resource_pressure"].get("allocation_cgroup_rise_bytes", 0) >= RAM_MINIMUM_RISE_BYTES
            for phase in phases if phase["condition"] == "RAM_PRESSURE"
        ),
        "pid_pressure_observed_in_selected_model_cgroup": all(
            phase["resource_pressure"].get("pids_current_delta", 0) >= PID_PRESSURE_TASKS
            for phase in phases if phase["condition"] == "PID_PRESSURE"
        ),
        "io_pressure_result": "NOT_RUN_UNSUPPORTED_IO_MAX_OR_BACKING_DEVICE_MAP",
        "host_cpu_exclusivity_verified": False,
        "fairness_established": False,
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }


async def run_phase(runner: ResourceRunner, scheduled: dict, output: Path) -> dict:
    runner.phase = ResourcePhaseCapture(scheduled, output)
    return_code = await asyncio.wait_for(
        base.run_n04_cli(
            SimpleNamespace(
                lock=runner.lock,
                model=runner.model,
                corpus=runner.corpus,
                corpus_receipt=runner.corpus_receipt,
                corpus_keys=runner.corpus_keys,
                output=output,
                mode="INPUT",
                traffic="real",
                lanes=3,
                n06_policy=None,
                n06_policy_public_key=None,
                n06_policy_key_id=None,
                n06_local_mtls=False,
                n06_sealed_profile=False,
                n06_workload="six",
            )
        ),
        timeout=PHASE_TIMEOUT_SECONDS,
    )
    if return_code != 0:
        raise RuntimeError("N04_CLI_RUN_FAILED")
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    if (
        summary.get("run_label") != "REAL_PUBLIC"
        or summary.get("defense_mode") != "INPUT"
        or summary.get("real_model") is not True
        or summary.get("turns") != TURNS_PER_PHASE
        or summary.get("lane_count") != 3
        or summary.get("three_lane_acceptance") is not False
        or summary.get("n05_baseline_mechanisms_delivered") is not True
        or summary.get("model_dispatches", 0) <= 0
        or summary.get("verifier_exit_code") != 0
        or summary.get("verifier_result", {}).get("status") != "PASS_PUBLIC_EVIDENCE"
    ):
        raise RuntimeError("N04_CLI_PROFILE_MISMATCH")
    if runner.phase.cli_summary is not None:
        raise RuntimeError("N04_CLI_SUMMARY_ALREADY_SET")
    runner.phase.cli_summary = summary
    if len(runner.phase.turns) != TURNS_PER_PHASE or not runner.phase.window_finished:
        raise RuntimeError("N04_TURN_OBSERVATIONS_INCOMPLETE")
    result = runner.phase.json_phase()
    result["n04_summary_sha256"] = base.digest_file(output / "summary.json")
    result["public_bundle_sha256"] = base.digest_file(output / "public-evidence.zip")
    if summary["model_dispatches"] != sum(
        turn["model_execution"] == "EXECUTED" for turn in result["turns"]
    ):
        raise RuntimeError("N04_DISPATCH_COUNT_MISMATCH")
    traces = base.measured_model_traces(result["turns"], summary.get("model_trace", []))
    result["model_overlap"] = base.model_overlap_summary(traces)
    if running_containers():
        raise RuntimeError("OWNED_PHASE_LEFT_RUNNING_CONTAINERS")
    return result


def preflight_pid_tools(image: str) -> bool:
    try:
        output = docker(
            "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
            "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt",
            "no-new-privileges", "--memory", "64m", "--memory-swap", "64m",
            "--cpus", "0.25", "--pids-limit", "4", "--log-driver", "none",
            "--entrypoint", "/bin/sh", image, "-c",
            "command -v sleep >/dev/null && command -v cat >/dev/null && command -v rm >/dev/null && printf PID_TOOLS_READY",
        ).decode("ascii", errors="strict")
        return output.strip() == "PID_TOOLS_READY"
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("lock", "model", "corpus", "corpus-receipt", "corpus-keys", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    lock, model, corpus = args.lock.resolve(), args.model.resolve(), args.corpus.resolve()
    receipt, keys, output = args.corpus_receipt.resolve(), args.corpus_keys.resolve(), args.output.resolve()
    if not all(path.is_file() for path in (lock, model, receipt, keys)) or not corpus.is_dir():
        raise FileNotFoundError("ADMITTED_LOCAL_MODEL_OR_PUBLIC_CORPUS_INPUT_MISSING")
    if not output.is_relative_to(ARTIFACTS.resolve()) or output.exists():
        raise ValueError("NEW_PRIVATE_OUTPUT_DIRECTORY_REQUIRED_UNDER_BACKEND_ARTIFACTS")
    output.mkdir(parents=True, exist_ok=False)
    from arena.contracts.jsonwire import load_wire
    from arena.integration.lanes import LaneAdmission

    admission = load_wire(LaneAdmission, lock.read_bytes())
    before_sources = backend_sources()
    result: dict = {
        "schema_version": SCHEMA,
        "scope": SCOPE,
        "result": "INCONCLUSIVE",
        "real_inference_performed": False,
        "real_public_jbb_used": False,
        "traffic_label": "REAL_PUBLIC",
        "defense_mode": "INPUT",
        "lock_sha256": base.digest_file(lock),
        "model_sha256": base.digest_file(model),
        "corpus_receipt_sha256": base.digest_file(receipt),
        "source_sha256": before_sources,
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
        "io_pressure_result": "NOT_RUN_UNSUPPORTED_IO_MAX_OR_BACKING_DEVICE_MAP",
    }
    runner = ResourceRunner(
        lock=lock,
        model=model,
        corpus=corpus,
        corpus_receipt=receipt,
        corpus_keys=keys,
    )
    phases: list[dict] = []
    try:
        ensure_local_docker()
        names_before = all_container_names()
        active = running_containers()
        if active:
            raise RuntimeError("PREEXISTING_RUNNING_CONTAINERS_LEFT_UNTOUCHED")
        result["pre_run_container_check"] = {
            "result": "PASS",
            "running_container_count": 0,
            "all_container_name_sha256": sorted(sha256(name.encode()) for name in names_before),
        }
        base.preflight_burner(admission.defense_image)
        if not preflight_pid_tools(admission.llama_image):
            raise RuntimeError("PINNED_MODEL_IMAGE_PID_TOOLS_UNAVAILABLE")
        runner.install()
        for scheduled in phase_plan():
            phase_output = output / scheduled["phase"]
            try:
                phases.append(asyncio.run(run_phase(runner, scheduled, phase_output)))
            except BaseException:
                if runner.phase is not None:
                    phases.append(runner.phase.partial_json())
                raise
        analysis = analyze_phases(phases)
        result.update(
            {
                "result": analysis["result"],
                "real_inference_performed": True,
                "real_public_jbb_used": True,
                "phase_plan": phase_plan(),
                "phases": phases,
                "analysis": analysis,
                "runtime_downloads": False,
                "resource_scope": {
                    "ram": "resident 1.5 GiB allocation in a separate no-network cgroup sharing the local Docker VM",
                    "pid": "64 idle child processes in one selected N05 model lane's existing pids cgroup, with 24 slots reserved",
                    "io": "NOT_RUN; io.max was blank and backing-device enforcement was not verified",
                },
            }
        )
        return_code = 0
    except BaseException as exc:
        result["result"] = "INCONCLUSIVE"
        result["failure_code"] = "PROBE_EXCEPTION_" + type(exc).__name__
        message = str(exc)
        if re.fullmatch(r"[A-Z0-9_]+", message):
            result["failure_code"] += ":" + message
        result["partial_phases"] = phases
        result["pressure_results"] = runner.pressure_results
        return_code = 1
    finally:
        runner.restore()
    try:
        after_sources = backend_sources()
        result["source_sha256_after"] = after_sources
        result["source_unchanged_during_run"] = before_sources == after_sources
        if before_sources != after_sources:
            result["result"] = "INCONCLUSIVE"
            result["failure_code"] = "SOURCE_CHANGED_DURING_RUN"
            return_code = 1
        names_after = all_container_names()
        active_after = running_containers()
        result["post_run_container_check"] = {
            "result": "PASS" if not active_after and names_after == names_before else "CONTAINER_INVENTORY_CHANGED",
            "running_container_count": len(active_after),
            "all_container_inventory_unchanged": names_after == names_before,
            "running_container_name_sha256": sorted(sha256(name.encode()) for name in active_after),
            "added_container_name_sha256": sorted(sha256(name.encode()) for name in names_after - names_before),
            "removed_container_name_sha256": sorted(sha256(name.encode()) for name in names_before - names_after),
        }
        if active_after or names_after != names_before:
            result["result"] = "INCONCLUSIVE"
            result["failure_code"] = "CONTAINER_INVENTORY_CHANGED_AFTER_OWNED_CLEANUP"
            return_code = 1
    except BaseException:
        result["result"] = "INCONCLUSIVE"
        result["failure_code"] = "POST_RUN_CLEANUP_OR_SOURCE_CHECK_FAILED"
        return_code = 1
    (output / "observation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = result.get("analysis", {})
    print(
        json.dumps(
            {
                "result": result["result"],
                "scope": SCOPE,
                "phase_count": len(result.get("phases", result.get("partial_phases", []))),
                "turn_count": summary.get("turn_count"),
                "model_dispatch_count": summary.get("model_dispatch_count"),
                "baseline_to_resource_pair_count": summary.get("baseline_to_resource_pair_count"),
                "verdict_distribution": summary.get("verdict_distribution"),
                "defense_outcome_drift_count": summary.get("defense_outcome_drift_count"),
                "defense_outcome_coverage": summary.get("defense_outcome_coverage"),
                "varied_defense_outcomes_observed": summary.get("varied_defense_outcomes_observed"),
                "ram_pressure_observed": summary.get("ram_pressure_observed"),
                "pid_pressure_observed": summary.get("pid_pressure_observed_in_selected_model_cgroup"),
                "io_pressure_result": "NOT_RUN_UNSUPPORTED_IO_MAX_OR_BACKING_DEVICE_MAP",
                "p011_complete": False,
                "p013_complete": False,
                "full_n07_acceptance": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
