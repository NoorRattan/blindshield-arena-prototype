"""Adversarial staged-authority tests; mocks here make no hardware claim."""
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire
from arena.model_runtime import BACKEND, ModelProfile
from arena.ports import DependencyUnavailable
from arena.prototype import admission as gate
from arena.prototype.runtime import PrototypeRuntime


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "authority.key"
    private.write_bytes(key.private_bytes_raw())
    original = load_wire(ModelProfile, (BACKEND / "infra/model-component/profile.json").read_bytes())
    source = {"src/test.py": "a" * 64}
    component = original.model_copy(update={"admission": original.admission.model_copy(update={"runtime_source_sha256": source})})
    profile = gate.PrototypeProfile(component=component, model_cpusets=("0,1", "2,3", "4,5"), defense_cpuset="6,7",
        source_sha256=source, source_commit="0" * 40, input_sha256={}, authority_public_key_sha256=sha256(key.public_key().public_bytes_raw()))
    path = tmp_path / "profile.json"
    path.write_bytes((profile.model_dump_json() + "\n").encode())
    monkeypatch.setattr(gate, "source_hashes", lambda: source)
    monkeypatch.setattr(gate, "runtime_source_hashes", lambda: source)
    monkeypatch.setattr(gate, "check_inputs", lambda p: None)
    monkeypatch.setattr(gate, "check_source_binding", lambda p: None)
    return profile, path, key, private


def save(path, signed):
    path.write_bytes((signed.model_dump_json() + "\n").encode())


def test_owner_labeled_pem_key_is_loaded_without_exposing_or_rewriting_it(tmp_path):
    from cryptography.hazmat.primitives import serialization
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "owner-private.pem"
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    raw = b"OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE\n" + pem
    path.write_bytes(raw)
    assert gate.key_from_file(path).public_key().public_bytes_raw() == key.public_key().public_bytes_raw()
    assert path.read_bytes() == raw


@pytest.mark.parametrize("mutation", ["stage", "profile", "signature", "expired", "future", "source", "trust"])
def test_gate_refuses_substitution_expiry_and_wrong_authority(candidate, tmp_path, monkeypatch, mutation):
    profile, path, key, private = candidate
    signed = gate.issue("STATIC", path, private, {"result": "PASS_STATIC_CALIBRATION_ONLY"})
    grant = tmp_path / "static.json"
    public = key.public_key().public_bytes_raw()
    expected, now = "STATIC", signed.receipt.issued_at_unix
    if mutation == "stage": expected = "SERVICE"
    elif mutation == "profile": path.write_bytes(path.read_bytes() + b" ")
    elif mutation == "signature": signed = signed.model_copy(update={"signature": "0" * 128})
    elif mutation == "expired": now = signed.receipt.expires_at_unix
    elif mutation == "future": now -= 1
    elif mutation == "source": monkeypatch.setattr(gate, "source_hashes", lambda: {"changed.py": "b" * 64})
    elif mutation == "trust": public = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    save(grant, signed)
    with pytest.raises(DependencyUnavailable): gate.verify_gate(grant, path, public, expected, now=now)


def measured(profile):
    return {"result": "PASS_THREE_LANE_CALIBRATION", "model_image_id": profile.component.assembled_image_id,
        "real_model_dispatches": 6, "containers_cleaned_up": True, "three_lane_overlap_ns": 100,
        "capacity_before_start": {"vm": {"mem_available_bytes": 12 * 1024**3}},
        "cells": [{"lane": i, "cpuset": cpu, "container_id": "id-" + str(i), "image_id": profile.component.assembled_image_id,
            "memory_peak_bytes": 1024**3, "oom": 0, "oom_kill": 0, "successful_calls": 2} for i, cpu in enumerate(profile.model_cpusets)]}


@pytest.mark.parametrize("mutation", ["image", "overlap", "bool-overlap", "peak-zero", "peak-cap", "bool-peak", "oom", "lane-id", "cpuset", "cleanup", "headroom", "missing-call"])
def test_final_gate_rejects_invalid_measurements(candidate, mutation):
    profile = candidate[0]
    value = measured(profile)
    if mutation == "image": value["model_image_id"] = "sha256:" + "0" * 64
    elif mutation == "overlap": value["three_lane_overlap_ns"] = 0
    elif mutation == "bool-overlap": value["three_lane_overlap_ns"] = True
    elif mutation == "peak-zero": value["cells"][0]["memory_peak_bytes"] = 0
    elif mutation == "peak-cap": value["cells"][0]["memory_peak_bytes"] = profile.model_lane_memory_limit_bytes
    elif mutation == "bool-peak": value["cells"][0]["memory_peak_bytes"] = True
    elif mutation == "oom": value["cells"][1]["oom_kill"] = 1
    elif mutation == "lane-id": value["cells"][1]["container_id"] = value["cells"][0]["container_id"]
    elif mutation == "cpuset": value["cells"][2]["cpuset"] = value["cells"][0]["cpuset"]
    elif mutation == "cleanup": value["containers_cleaned_up"] = False
    elif mutation == "headroom": value["capacity_before_start"]["vm"]["mem_available_bytes"] = 3 * 1024**3
    else: value["real_model_dispatches"] = 5
    with pytest.raises(DependencyUnavailable): gate.validate_calibration(value, profile)


def test_final_admission_requires_parent_and_current_capacity(candidate, tmp_path, monkeypatch):
    profile, path, key, private = candidate
    static, calibration = tmp_path / "static.json", tmp_path / "calibration.json"
    save(static, gate.issue("STATIC", path, private, {"result": "PASS_STATIC_CALIBRATION_ONLY"}))
    save(calibration, gate.issue("CALIBRATION", path, private, measured(profile), parent="0" * 64))
    with pytest.raises(DependencyUnavailable, match="PARENT_MISMATCH"):
        gate.service_check(path, calibration, static, key.public_key().public_bytes_raw())
    save(calibration, gate.issue("CALIBRATION", path, private, measured(profile), parent=gate.file_digest(static)))
    def low(*args): raise DependencyUnavailable("HOST_PROTOTYPE_CAPACITY_BELOW_FLOOR")
    monkeypatch.setattr(gate, "fresh_capacity", low)
    with pytest.raises(DependencyUnavailable, match="CAPACITY_BELOW"):
        gate.service_check(path, calibration, static, key.public_key().public_bytes_raw())


def test_static_grant_cannot_construct_a_service_runtime(candidate, tmp_path):
    profile, path, key, private = candidate
    grant = tmp_path / "static.json"
    save(grant, gate.issue("STATIC", path, private, {"result": "PASS_STATIC_CALIBRATION_ONLY"}))
    with pytest.raises(DependencyUnavailable):
        PrototypeRuntime(path, grant, key.public_key().public_bytes_raw(), tmp_path / "model", tmp_path / "runtime")


def test_input_manifest_is_mandatory_and_paths_cannot_escape(candidate, monkeypatch):
    profile = candidate[0]
    monkeypatch.undo()
    with pytest.raises(DependencyUnavailable, match="INPUTS_MISSING"):
        gate.check_inputs(profile)
    inputs = {path: gate.file_digest(BACKEND / path) for path in gate.REQUIRED_INPUTS}
    inputs["../README.md"] = gate.file_digest(BACKEND.parent / "README.md")
    with pytest.raises(DependencyUnavailable, match="INPUT_CHANGED"):
        gate.check_inputs(profile.model_copy(update={"input_sha256": inputs}))


def test_capacity_refuses_before_any_probe_or_model(candidate, monkeypatch):
    profile = candidate[0]
    monkeypatch.setattr(gate, "host_available_memory", lambda: profile.host_available_memory_floor_bytes - 1)
    def forbidden(*a): raise AssertionError("Capacity refusal must precede Docker/model work")
    monkeypatch.setattr(gate, "capacity", forbidden)
    with pytest.raises(DependencyUnavailable, match="HOST_PROTOTYPE_CAPACITY_BELOW_FLOOR"):
        gate.fresh_capacity(profile)


def test_failed_cell_start_stops_every_owned_cell(monkeypatch):
    runtime = object.__new__(PrototypeRuntime)
    runtime.profile_path = runtime.grant_path = Path("unused")
    runtime.public_key, runtime.purpose, runtime.profile = b"", "SERVICE", object()
    runtime.cells, runtime.owned_cells, runtime.stopped = [], [], []
    from arena.prototype import runtime as module
    monkeypatch.setattr(module, "verify_gate", lambda *a: None)
    monkeypatch.setattr(module, "fresh_capacity", lambda p: {"vm": {}})
    class Cell:
        def __init__(self, lane): self.lane = lane
        def start(self):
            if self.lane == 1: raise DependencyUnavailable("LOAD_FAILED")
    runtime._cell = lambda i: Cell(i)
    runtime.stop = lambda: runtime.stopped.extend(c.lane for c in runtime.cells)
    with pytest.raises(DependencyUnavailable, match="LOAD_FAILED"): runtime.start()
    assert runtime.stopped == [0, 1]
