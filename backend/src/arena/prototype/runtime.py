"""Exactly three staged-admitted cells using the selected assembled image."""
from pathlib import Path
import asyncio
import json

from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire
from arena.integration.lanes import PinnedCell, ThreeLaneModel, ThreeLaneRuntime
from arena.integration.runtime import docker
from arena.model_runtime import BACKEND, ModelCellRuntime, file_digest
from arena.ports import DependencyUnavailable
from .admission import PrototypeProfile, fresh_capacity, verify_gate


class ProfileCell(ModelCellRuntime, PinnedCell):
    def __init__(self, profile_path, model_path, root, cpuset, defense_cpuset):
        self.cpuset, self.defense_cpuset = cpuset, defense_cpuset
        ModelCellRuntime.__init__(self, profile_path, model_path, root)
        self.container = self.container.replace("model-component", "prototype-model")


class PrototypeRuntime(ThreeLaneRuntime):
    supported_interaction_modes = frozenset({"INTERACTIVE", "SEALED_BATCH"})

    def __init__(self, profile_path, grant_path, public_key, model_path, private_root, *, purpose="SERVICE"):
        if purpose not in {"STATIC", "SERVICE"}:
            raise ValueError("EXPLICIT_RUNTIME_STAGE_REQUIRED")
        self.profile_path = Path(profile_path).resolve()
        self.grant_path, self.public_key, self.purpose = Path(grant_path), public_key, purpose
        self.lock_bytes = self.profile_path.read_bytes()
        self.profile = load_wire(PrototypeProfile, self.lock_bytes)
        grant = verify_gate(self.grant_path, self.profile_path, public_key, purpose)
        expected = "PASS_STATIC_CALIBRATION_ONLY" if purpose == "STATIC" else "READY_FOR_BOUNDED_ARENA_EXECUTION"
        if grant.receipt.observations.get("result") != expected:
            raise DependencyUnavailable("RUNTIME_GATE_RESULT_REJECTED")
        self.admission = self.profile
        self.lock = self.profile.component.admission.model_dump()
        self.lock.update(llama_image=self.profile.component.assembled_image_id,
            model_cpusets=self.profile.model_cpusets, defense_cpuset=self.profile.defense_cpuset,
            schema_version="arena-prototype-execution.v1",
            prototype_profile_sha256=sha256(self.lock_bytes), staged_gate_sha256=file_digest(grant_path),
            admission_stage=purpose, claim_scope="LOCAL_OFFLINE_PROTOTYPE_NOT_FULL_T_P_ACCEPTANCE")
        self.lock_bytes = (json.dumps(self.lock, sort_keys=True, indent=2) + "\n").encode()
        self.model_path = Path(model_path).resolve()
        self.root = Path(private_root).resolve()
        if not self.root.is_relative_to((BACKEND / "artifacts").resolve()):
            raise ValueError("PROTOTYPE_PRIVATE_OUTPUT_REQUIRED")
        self.root.mkdir(parents=True, exist_ok=False)
        self.cell_lock_path = self.root / "cell-profile.json"
        self.cell_lock_path.write_bytes((self.profile.component.model_dump_json(indent=2) + "\n").encode())
        (self.root / "publisher-observation.json").write_bytes((self.profile_path.parent / "publisher-observation.json").read_bytes())
        self.cells, self.owned_cells = [], []
        self.generation, self.started, self.defense_trace, self.model = [0, 0, 0], False, [], None

    def _cell(self, lane):
        cell = ProfileCell(self.cell_lock_path, self.model_path,
            self.root / f"lane-{lane}-generation-{self.generation[lane]}",
            self.profile.model_cpusets[lane], self.profile.defense_cpuset)
        self.owned_cells.append(cell)
        return cell

    def start(self):
        # Verify again after initialization, immediately before any load.
        verify_gate(self.grant_path, self.profile_path, self.public_key, self.purpose)
        observed = fresh_capacity(self.profile)
        self.capacity_observation = observed
        self.capacity = observed["vm"]
        try:
            for lane in range(3):
                cell = self._cell(lane)
                self.cells.append(cell)
                cell.start()
            self.model = ThreeLaneModel(self.cells, self._recreate)
            self.model_contexts_destroyed = False
            self.started = True
            return self.inspect()
        except BaseException:
            self.stop()
            raise

    def inspect(self):
        result = super().inspect()
        result.update(scope="STAGED_LOCAL_PROTOTYPE_THREE_LANES", profile_sha256=file_digest(self.profile_path),
            model_image_id=self.profile.component.assembled_image_id, admission_stage=self.purpose,
            cold_resume_authorized=False, full_t_p_acceptance=False)
        return result

    async def close_models(self, sessions):
        """Destroy terminal model contexts without creating an unanchored successor."""
        if not self.started or self.model is None or self.model.active:
            raise DependencyUnavailable("TERMINAL_MODEL_QUIESCENCE_REQUIRED")
        self.model.closed.update(sessions)
        self.model.quarantined.update(range(3))
        failures = []
        for cell in self.owned_cells:
            try:
                await asyncio.to_thread(cell.stop)
            except Exception as exc:
                failures.append(type(exc).__name__)
        remaining = docker("ps", "--all", "--format", "{{.Names}}").decode().splitlines()
        if failures or any(cell.container in remaining for cell in self.owned_cells):
            raise DependencyUnavailable("TERMINAL_MODEL_CONTEXT_DESTRUCTION_UNCONFIRMED")
        self.model.bindings.clear()
        self.model.owners.clear()
        self.model_contexts_destroyed = True
        self.terminal_model_cleanup = {
            "terminal_model_contexts_destroyed": True,
            "owned_container_count": len(self.owned_cells),
            "model_containers_recreated": False,
        }
        # The separate, ephemeral defense adapter remains available for authorized
        # POST_HOC work. All model lanes remain permanently quarantined.
        return self.terminal_model_cleanup

    def stop(self):
        failures = []
        for cell in self.owned_cells:
            try:
                cell.stop()
            except Exception as exc:
                failures.append(type(exc).__name__)
        self.started = False
        if not self.owned_cells:
            return
        remaining = docker("ps", "--all", "--format", "{{.Names}}").decode().splitlines()
        if failures or any(cell.container in remaining for cell in self.owned_cells):
            raise DependencyUnavailable("PROTOTYPE_OWNED_CONTAINER_CLEANUP_UNCONFIRMED")


def memory_observation(cell):
    raw = docker("exec", cell.container, "/bin/sh", "-c",
        "cat /sys/fs/cgroup/memory.peak; cat /sys/fs/cgroup/memory.events").decode().splitlines()
    events = dict(line.split() for line in raw[1:])
    inspected = json.loads(docker("inspect", cell.container))[0]
    return {"memory_peak_bytes": int(raw[0]), "oom": int(events["oom"]),
        "oom_kill": int(events["oom_kill"]), "container_id": inspected["Id"], "image_id": inspected["Image"]}
