"""N05 trusted three-process pool. No public route or new signed wire format.

Mappings come only from the broker's durable session lane, never a participant.
UNKNOWN quarantines its lane; neither retry nor reset silently redispatches work.
"""

import asyncio
import json
from pathlib import Path
import time

from pydantic import BeforeValidator, Field, TypeAdapter
from typing import Annotated, Literal

from arena.contracts.common import Context, Uuid, as_tuple
from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire
from arena.ports import DependencyUnavailable, TargetNotDispatched
from .runtime import DockerRuntime, docker, ensure_local_docker, runtime_source_hashes
from .types import AdmissionLock


class LaneAdmission(AdmissionLock):
    schema_version: Literal["arena-n05-admission.v1"]
    cell_admission_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    model_cpusets: Annotated[tuple[str, str, str], BeforeValidator(as_tuple)]
    defense_cpuset: str
    minimum_available_memory_bytes: Literal[7516192768]  # 3 * 2 GiB plus 1 GiB headroom
    claim_scope: Literal["N05_LOCAL_THREE_PROCESS_BASELINE_NOT_FULL_ARENA_ACCEPTANCE"]


def cpu_set(value):
    """Parse kernel cpulist syntax, rejecting duplicate/ambiguous or huge lists."""
    result = set()
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError("CPUSET_REQUIRED")
    for part in value.split(","):
        bounds = part.split("-")
        if len(bounds) not in {1, 2} or any(not x.isascii() or not x.isdecimal() for x in bounds):
            raise ValueError("CPUSET_INVALID")
        first, last = int(bounds[0]), int(bounds[-1])
        if first > last or last > 65535:
            raise ValueError("CPUSET_INVALID")
        members = set(range(first, last + 1))
        if result & members:
            raise ValueError("CPUSET_DUPLICATE")
        result |= members
    return result


def cpu_string(members):
    return ",".join(str(value) for value in sorted(members))


# Runs only inside the pinned, no-network, nonprivileged Python image.
CAPACITY_SCRIPT = """
import json, os
from pathlib import Path
allowed=sorted(os.sched_getaffinity(0))
siblings={str(cpu):Path('/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list'%cpu).read_text().strip() for cpu in allowed}
mem={k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())}
print(json.dumps({'allowed_cpus':allowed,'siblings':siblings,'mem_available_bytes':mem['MemAvailable']}))
"""


def capacity(image):
    ensure_local_docker()
    return json.loads(docker(
        "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.5", "--pids-limit", "16",
        "--log-driver", "none", "--entrypoint", "python", image, "-I", "-c", CAPACITY_SCRIPT,
    ))


def select_cpus(observation):
    allowed = set(observation["allowed_cpus"])
    groups = sorted({tuple(sorted(cpu_set(value))) for value in observation["siblings"].values()})
    # Allocate whole VM-visible sibling groups. Host/hypervisor scheduling remains unverified.
    groups = [set(group) for group in groups if set(group) <= allowed]
    if len(groups) < 7:
        raise DependencyUnavailable("SEVEN_DISTINCT_VM_CORE_GROUPS_REQUIRED")
    lanes = [cpu_string(groups[2 * i] | groups[2 * i + 1]) for i in range(3)]
    return tuple(lanes), cpu_string(allowed - set().union(*(cpu_set(x) for x in lanes)))


def check_capacity(admission, observation):
    sets = [cpu_set(value) for value in (*admission.model_cpusets, admission.defense_cpuset)]
    allowed = set(observation["allowed_cpus"])
    for index, members in enumerate(sets):
        if not members <= allowed or any(members & old for old in sets[:index]):
            raise DependencyUnavailable("CPUSET_NOT_AVAILABLE_OR_OVERLAPPING")
        for cpu in members:
            if not cpu_set(observation["siblings"][str(cpu)]) <= members:
                raise DependencyUnavailable("VM_SMT_SIBLINGS_SPLIT_BETWEEN_CELLS")
    for members in sets[:3]:
        groups = {frozenset(cpu_set(observation["siblings"][str(cpu)])) for cpu in members}
        if len(groups) != 2:
            raise DependencyUnavailable("TWO_VM_CORE_GROUPS_PER_MODEL_REQUIRED")
    if observation["mem_available_bytes"] < admission.minimum_available_memory_bytes:
        raise DependencyUnavailable("THREE_LANE_MEMORY_HEADROOM_UNAVAILABLE")


class PinnedCell(DockerRuntime):
    def __init__(self, *args, cpuset, defense_cpuset, **kwargs):
        self.cpuset, self.defense_cpuset = cpuset, defense_cpuset
        super().__init__(*args, **kwargs)
        self.container = self.container.replace("n04-model", "n05-model")

    def model_resource_args(self):
        return ["--cpuset-cpus", self.cpuset]

    def defense_resource_args(self):
        return ["--cpuset-cpus", self.defense_cpuset]

    def inspect(self):
        result = super().inspect()
        item = json.loads(docker("inspect", self.container))[0]
        effective = docker("exec", self.container, "cat", "/sys/fs/cgroup/cpuset.cpus.effective").decode().strip()
        mounts = item["Mounts"]
        if (cpu_set(effective) != cpu_set(self.cpuset)
            or cpu_set(item["HostConfig"]["CpusetCpus"]) != cpu_set(self.cpuset)
            or len(mounts) != 1
            or mounts[0]["Type"] != "bind"
            or mounts[0]["Destination"] != "/model.gguf"
            or mounts[0]["RW"]
            or item["HostConfig"]["PidMode"] or item["HostConfig"]["IpcMode"] != "private"):
            raise DependencyUnavailable("N05_CELL_BOUNDARY_MISMATCH")
        result.update(scope="N05_ONE_OF_THREE_PROCESS_CELLS", cpuset_effective=effective,
                      vm_sibling_groups_partitioned=True, host_cpu_exclusivity_verified=False)
        return result


class ThreeLaneModel:
    """One active turn per broker-pinned lane, no hidden queue or inference retry."""

    def __init__(self, cells, recreate):
        if len(cells) != 3:
            raise ValueError("EXACTLY_THREE_CELLS_REQUIRED")
        self.cells, self.recreate = cells, recreate
        self.bindings = {}
        self.owners = {}
        self.active = set()
        self.quarantined = set()
        self.closed = set()
        self.trace = []  # Operator-only metadata, no payload text.

    def bind_session(self, session_id, lane, context):
        TypeAdapter(Uuid).validate_python(session_id)
        # Canonical validation uses an existing shared type without changing its bytes.
        Context.model_validate(context.model_dump())
        if type(lane) is not int or lane not in range(3) or session_id in self.closed:
            raise DependencyUnavailable("LANE_BINDING_INVALID")
        value = (lane, context.domain_id, context.experiment_id, context.epoch)
        if self.bindings.get(session_id, value) != value or self.owners.get(lane, session_id) != session_id:
            raise DependencyUnavailable("LANE_BINDING_CONFLICT")
        if lane in self.quarantined:
            raise DependencyUnavailable("MODEL_LANE_QUARANTINED")
        self.bindings[session_id], self.owners[lane] = value, session_id

    async def infer(self, request):
        binding = self.bindings.get(request.session_id)
        if binding is None or binding[1:] != (request.domain_id, request.experiment_id, request.epoch):
            raise TargetNotDispatched("MODEL_BROKER_BINDING_REQUIRED")
        lane = binding[0]
        if lane in self.quarantined or request.session_id in self.closed:
            raise TargetNotDispatched("MODEL_LANE_QUARANTINED")
        if lane in self.active:
            raise TargetNotDispatched("ONE_UNRESOLVED_TURN_PER_LANE")
        self.active.add(lane)
        trace = {"lane": lane, "session_id": request.session_id, "turn_id": request.attempt_id,
                 "container": self.cells[lane].container, "begin_ns": time.monotonic_ns()}
        self.trace.append(trace)
        try:
            response = await self.cells[lane].model.infer(request)
            trace["execution"] = "EXECUTED"
            return response
        except TargetNotDispatched:
            trace["execution"] = "NOT_EVALUATED"
            raise
        except BaseException:
            trace["execution"] = "UNKNOWN"
            self.quarantined.add(lane)
            raise
        finally:
            trace["end_ns"] = time.monotonic_ns()
            self.active.remove(lane)

    async def reset(self, session_id):
        binding = self.bindings.get(session_id)
        if binding is None:
            return
        lane = binding[0]
        if lane in self.active or lane in self.quarantined:
            raise DependencyUnavailable("LANE_NOT_SAFE_TO_RESET")
        self.closed.add(session_id)
        try:
            await self.cells[lane].model.reset(session_id)
            # New process/address space before reuse, including sessions blocked before inference.
            self.cells[lane] = await asyncio.to_thread(self.recreate, lane)
        except BaseException:
            self.quarantined.add(lane)
            raise
        del self.bindings[session_id]
        del self.owners[lane]

    def get_assigned_lane(self, session_id):
        binding = self.bindings.get(session_id)
        return None if binding is None else f"lane-{binding[0]}"


class ThreeLaneRuntime:
    lane_count = 3

    def __init__(self, lock_path, model_path, private_root):
        self.lock_bytes = Path(lock_path).read_bytes()
        self.admission = load_wire(LaneAdmission, self.lock_bytes)
        self.cell_lock_path = Path(lock_path).parent / "cell-admission.json"
        if sha256(self.cell_lock_path.read_bytes()) != self.admission.cell_admission_sha256:
            raise DependencyUnavailable("N05_CELL_ADMISSION_MISMATCH")
        base = load_wire(AdmissionLock, self.cell_lock_path.read_bytes()).model_dump()
        self.lock = self.admission.model_dump()
        if any(self.lock[name] != value for name, value in base.items() if name not in {"schema_version", "claim_scope"}):
            raise DependencyUnavailable("N05_BASE_PROFILE_FIELDS_MISMATCH")
        self.model_path = model_path
        self.root = Path(private_root)
        self.root.mkdir(parents=True, exist_ok=False)
        self.cells = []
        self.generation = [0, 0, 0]
        self.started = False
        self.defense_trace = []
        self.model = None

    def _cell(self, lane):
        return PinnedCell(self.cell_lock_path, self.model_path,
                          self.root / f"lane-{lane}-generation-{self.generation[lane]}",
                          cpuset=self.admission.model_cpusets[lane], defense_cpuset=self.admission.defense_cpuset)

    def start(self):
        if runtime_source_hashes() != self.lock["runtime_source_sha256"]:
            raise DependencyUnavailable("FROZEN_RUNTIME_SOURCE_CHANGED_REPREPARE_ADMISSION")
        self.capacity = capacity(self.lock["defense_image"])
        check_capacity(self.admission, self.capacity)
        try:
            for lane in range(3):
                cell = self._cell(lane)
                self.cells.append(cell)
                cell.start()
            self.model = ThreeLaneModel(self.cells, self._recreate)
            self.started = True
            return self.inspect()
        except BaseException:
            self.stop()
            raise

    def _recreate(self, lane):
        old = self.cells[lane]
        old.stop()
        # A failed removal cannot be mistaken for a fresh/reset lane.
        if old.container in docker("ps", "--all", "--format", "{{.Names}}").decode().splitlines():
            raise DependencyUnavailable("OLD_CELL_NOT_REMOVED")
        self.generation[lane] += 1
        cell = self._cell(lane)
        self.cells[lane] = cell
        cell.start()
        return cell

    def inspect(self):
        if len(self.cells) != 3 or len({cell.container for cell in self.cells}) != 3:
            raise DependencyUnavailable("THREE_DISTINCT_CELLS_REQUIRED")
        return {"scope": "N05_THREE_PROCESS_BASELINE", "cells": [cell.inspect() for cell in self.cells],
                "capacity_before_start": self.capacity, "guarantee_tier_achieved": None,
                "host_cpu_exclusivity_verified": False, "fairness_measured": False}

    async def evaluate(self, request):
        if not self.started:
            raise DependencyUnavailable("RUNTIME_NOT_STARTED")
        trace = {"begin_ns": time.monotonic_ns(), "call_token": request.call_token}
        self.defense_trace.append(trace)
        try:
            return await self.cells[0].evaluate(request)
        finally:
            trace["end_ns"] = time.monotonic_ns()

    def stop(self):
        for cell in self.cells:
            cell.stop()
        self.started = False
