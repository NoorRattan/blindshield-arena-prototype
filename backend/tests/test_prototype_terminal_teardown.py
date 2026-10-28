"""Terminal close destroys owned model contexts instead of recreating lanes."""
import asyncio
import base64
import json
from types import SimpleNamespace

import pytest

from arena.ports import DependencyUnavailable
from arena.prototype import runtime as module
from arena.prototype.service import PrototypeService
from arena.contracts.crypto import sha256
from arena.prototype import service as service_module
from arena.broker.store import Store


def runtime_fixture():
    runtime = object.__new__(module.PrototypeRuntime)
    stopped = []
    runtime.started = True
    runtime.model = SimpleNamespace(
        active=set(), closed=set(), quarantined=set(), bindings={"session": 0}, owners={0: "session"},
    )
    runtime.owned_cells = [SimpleNamespace(container="owned-" + str(lane), stop=lambda lane=lane: stopped.append(lane))
                           for lane in range(3)]
    return runtime, stopped


def test_terminal_close_destroys_all_owned_contexts_and_fences_future_model_use(monkeypatch):
    runtime, stopped = runtime_fixture()
    monkeypatch.setattr(module, "docker", lambda *args: b"unrelated-user-container\n")
    result = asyncio.run(runtime.close_models(("session",)))
    assert stopped == [0, 1, 2]
    assert runtime.model.quarantined == {0, 1, 2}
    assert runtime.model.closed == {"session"}
    assert not runtime.model.bindings and not runtime.model.owners
    assert runtime.model_contexts_destroyed is True
    assert result["model_containers_recreated"] is False


def test_terminal_close_refuses_unsettled_inference_and_unconfirmed_destruction(monkeypatch):
    runtime, stopped = runtime_fixture()
    runtime.model.active.add(1)
    with pytest.raises(DependencyUnavailable, match="QUIESCENCE_REQUIRED"):
        asyncio.run(runtime.close_models(("session",)))
    assert not stopped
    runtime.model.active.clear()
    monkeypatch.setattr(module, "docker", lambda *args: b"owned-1\n")
    with pytest.raises(DependencyUnavailable, match="DESTRUCTION_UNCONFIRMED"):
        asyncio.run(runtime.close_models(("session",)))
    assert runtime.model.quarantined == {0, 1, 2}


@pytest.mark.parametrize("effective,accepted", [("0-3", True), ("0-4", False), ("0,0,1,2,3", False)])
def test_recovery_cell_fence_compares_cpu_membership_not_kernel_spelling(effective, accepted):
    service = object.__new__(PrototypeService)
    service.ctx = object()
    lock = {"llama_image": "sha256:" + "a" * 64,
            "model_cpusets": ["0,1,2,3", "4,5,6,7", "8,9,10,11"]}
    lock_bytes = json.dumps(lock).encode()
    service.profile = SimpleNamespace(execution_lock_sha256=sha256(lock_bytes))
    events = [SimpleNamespace(event_type=kind, sequence=index, artifact_ciphertext_refs=(ref,))
              for index, (kind, ref) in enumerate([
                  ("MANIFEST_SEALED", "manifest"), ("PREFLIGHT_PASSED", "readiness")])]
    artifacts = {
        "manifest": {"sealed": {}, "execution_lock": lock,
                     "execution_lock_bytes_base64": base64.b64encode(lock_bytes).decode()},
        "readiness": {"runtime": {"cells": [
            {"container_id": str(i + 1) * 64, "image_id": lock["llama_image"],
             "cpuset_effective": value} for i, value in enumerate([effective, "4-7", "8-11"])]},
            "corpus_receipt_sha256": "b" * 64, "scope": "N04_SINGLE_LANE_LOCAL_INTEGRATION"},
    }
    service.recorder = SimpleNamespace(get_events=lambda context: events)
    service.anchor = SimpleNamespace(verify_events=lambda context, value: None)
    service.vault = SimpleNamespace(get=lambda ref, **kwargs: artifacts[ref])
    if accepted:
        cells = service._load_manifest_bound_old_cells()
        assert [cell["cpuset"] for cell in cells] == lock["model_cpusets"]
    else:
        with pytest.raises(DependencyUnavailable, match="STARTUP_MODEL_FENCE_MANIFEST_INVALID"):
            service._load_manifest_bound_old_cells()


@pytest.mark.parametrize("variant", ["valid", "tmpfs_missing", "extra_bind", "cpuset_extra", "label_override"])
def test_recovery_fence_uses_docker_host_tmpfs_metadata_and_refuses_extra_mounts(tmp_path, monkeypatch, variant):
    service = object.__new__(PrototypeService)
    service.recovery_only = True
    service.controller = SimpleNamespace(runtime=SimpleNamespace(model=SimpleNamespace(sessions={"session": 0})))
    service.ctx = SimpleNamespace(domain_id="domain", experiment_id="experiment", epoch=1)
    service.store = Store(tmp_path / "store.sqlite3", b"k" * 32)
    service.store.initialize()
    image = "sha256:" + "a" * 64
    service._recovery_old_cells = tuple(dict(container_id=str(i + 1) * 64, image_id=image,
        image_ref=image, cpuset=",".join(str(n) for n in range(i*4,i*4+4))) for i in range(3))
    present = {cell["container_id"] for cell in service._recovery_old_cells}
    removed = []
    image_labels = {"arena.model_profile": "pinned-profile", "arena.model_sha256": "b" * 64,
                    "arena.model_recipe_sha256": "c" * 64}
    command = ["--model", "/model.gguf", "--host", "127.0.0.1", "--port", "8080",
        "--n-gpu-layers", "0", "--threads", "2", "--ctx-size", "2048", "--parallel", "1",
        "--cache-ram", "0", "--ctx-checkpoints", "0", "--no-kv-unified", "--no-cache-idle-slots",
        "--no-context-shift", "--no-webui", "--offline", "--log-disable", "--slots", "--slot-save-path", "/tmp"]
    def docker(*args):
        if args[:2] == ("image", "inspect"):
            return json.dumps([dict(Id=image, Config=dict(Labels=image_labels))]).encode()
        if args[0] == "rm":
            removed.append(args[-1]); present.remove(args[-1]); return b""
        cell = next(cell for cell in service._recovery_old_cells if cell["container_id"] == args[1])
        host = dict(ReadonlyRootfs=True, Privileged=False, NetworkMode="none", PortBindings={},
            Memory=2147483648, MemorySwap=2147483648, NanoCpus=2000000000, PidsLimit=128,
            CpusetCpus=cell["cpuset"].split(",")[0]+"-"+cell["cpuset"].split(",")[-1],
            CapDrop=["ALL"], CapAdd=None, SecurityOpt=["no-new-privileges"],
            Tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=64m"})
        mounts = [dict(Type="bind", Destination="/model.gguf", RW=False)]
        if variant == "tmpfs_missing": host["Tmpfs"] = {}
        if variant == "extra_bind": mounts.append(dict(Type="bind", Destination="/host", RW=True))
        if variant == "cpuset_extra": host["CpusetCpus"] = "0-4"
        labels = dict(image_labels, **{"arena.n04": "true"})
        if variant == "label_override": labels["arena.model_sha256"] = "d" * 64
        return json.dumps([dict(Id=cell["container_id"], Image=image, Name="/arena-prototype-model-owned",
            Config=dict(Image=image, Cmd=command, Labels=labels, User="65534:65534"),
            HostConfig=host, Mounts=mounts)]).encode()
    monkeypatch.setattr(service_module, "docker", docker)
    monkeypatch.setattr(service_module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout=("\n".join(present)+"\n").encode()))
    if variant == "valid":
        service._fence_previous_model_containers("session")
        assert len(removed) == 3 and not present
        with service.store.connect() as conn:
            assert conn.execute("SELECT fence_status FROM prototype_recovery_fences").fetchone()[0] == "PRIOR_MODEL_PROCESSES_ABSENT"
    else:
        with pytest.raises(DependencyUnavailable, match="CONTAINER_BINDING_INVALID"):
            service._fence_previous_model_containers("session")
        assert not removed
