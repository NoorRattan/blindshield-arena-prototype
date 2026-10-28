"""Separate static/calibration/service authority; no full T/P acceptance claim.

Operator-supplied public trust is external to receipts. A static grant permits
only the bounded calibration runner. Service grants require measured evidence
for the exact candidate and current source, and capacity is rechecked at load.
"""
from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Annotated, Literal
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BeforeValidator, Field

from arena.contracts.common import Digest, Signature, Uuid, WireModel, as_tuple
from arena.contracts.crypto import canonical_bytes, sha256, verify
from arena.contracts.jsonwire import load_wire
from arena.integration.lanes import capacity, check_capacity
from arena.integration.runtime import docker, runtime_source_hashes
from arena.model_runtime import BACKEND, ModelProfile, file_digest, host_available_memory, validate_assets, validate_image
from arena.ports import DependencyUnavailable


REQUIRED_INPUTS = frozenset({"infra/model-component/profile.json", "infra/model-component/publisher-observation.json",
    "infra/model-component/build-provenance.json", "requirements.lock", "config/n04-sources.json",
    "infra/owner-delegated-n08/demo-ca-certificate.pem", "infra/owner-delegated-n08/recorder-public.pem",
    "infra/owner-delegated-n08/witness-public.pem", "infra/owner-delegated-n08/authority-manifest.json",
    "infra/prototype/recovery-authorities.json"})


class PrototypeProfile(WireModel):
    schema_version: Literal["arena-prototype-profile.v1"] = "arena-prototype-profile.v1"
    scope: Literal["LOCAL_OFFLINE_PROTOTYPE_NOT_FULL_T_P_ACCEPTANCE"] = "LOCAL_OFFLINE_PROTOTYPE_NOT_FULL_T_P_ACCEPTANCE"
    component: ModelProfile
    model_cpusets: Annotated[tuple[str, str, str], BeforeValidator(as_tuple)]
    defense_cpuset: str
    minimum_available_memory_bytes: Literal[7516192768] = 7516192768
    model_lane_memory_limit_bytes: Literal[2147483648] = 2147483648
    host_available_memory_floor_bytes: Literal[8589934592] = 8589934592
    disk_free_floor_bytes: Literal[1073741824] = 1073741824
    source_sha256: dict[str, Digest]
    source_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    input_sha256: dict[str, Digest]
    authority_public_key_sha256: Digest
    cold_resume_authorized: Literal[False] = False
    bind_address: Literal["127.0.0.1"] = "127.0.0.1"
    query_budget: Literal[24] = 24
    calibration_turns_per_lane: Literal[2] = 2


class GateReceipt(WireModel):
    schema_version: Literal["arena-prototype-gate.v1"] = "arena-prototype-gate.v1"
    stage: Literal["STATIC", "CALIBRATION", "SERVICE"]
    profile_sha256: Digest
    nonce: Uuid
    issued_at_unix: Annotated[int, Field(strict=True, ge=0)]
    expires_at_unix: Annotated[int, Field(strict=True, ge=0)]
    parent_receipt_sha256: Digest | None
    observations: dict


class SignedGate(WireModel):
    receipt: GateReceipt
    signature: Signature


def source_hashes():
    result = runtime_source_hashes()
    for path in sorted((BACKEND / "tools").glob("prototype_*.py")):
        result[path.relative_to(BACKEND).as_posix()] = file_digest(path)
    for relative in ("requirements.lock", "infra/cells/Dockerfile.model"):
        result[relative] = file_digest(BACKEND / relative)
    return result


def check_source_binding(profile):
    if subprocess.run(["git", "merge-base", "--is-ancestor", profile.source_commit, "HEAD"], cwd=BACKEND, capture_output=True).returncode:
        raise DependencyUnavailable("ADMISSION_SOURCE_COMMIT_NOT_AN_ANCESTOR")
    for relative, expected in profile.source_sha256.items():
        result = subprocess.run(["git", "show", profile.source_commit + ":backend/" + relative], cwd=BACKEND, capture_output=True)
        if result.returncode or sha256(result.stdout) != expected:
            raise DependencyUnavailable("ADMISSION_REQUIRES_COMMITTED_SOURCE_FREEZE")


def key_from_file(path):
    raw = Path(path).read_bytes()
    if b"-----BEGIN PRIVATE KEY-----" in raw:
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("ED25519_ADMISSION_AUTHORITY_REQUIRED")
        return key
    return Ed25519PrivateKey.from_private_bytes(raw)


def key_public(path):
    raw = Path(path).read_bytes()
    return bytes.fromhex(raw.decode("ascii").strip()) if len(raw) != 32 else raw


def authority_public(role):
    path = BACKEND / "infra/owner-delegated-n08" / (role + "-public.pem")
    return serialization.load_pem_public_key(path.read_bytes()).public_bytes_raw()


def gate_message(receipt):
    return b"arena.prototype/gate\x00" + canonical_bytes(receipt.model_dump())


def issue(stage, profile_path, key_path, observations, *, parent=None):
    profile = load_wire(PrototypeProfile, Path(profile_path).read_bytes())
    key = key_from_file(key_path)
    if sha256(key.public_key().public_bytes_raw()) != profile.authority_public_key_sha256:
        raise ValueError("ADMISSION_SIGNER_MISMATCH")
    now = int(time.time())
    receipt = GateReceipt(stage=stage, profile_sha256=file_digest(profile_path), nonce=str(uuid4()),
        issued_at_unix=now, expires_at_unix=now + 86400, parent_receipt_sha256=parent, observations=observations)
    return SignedGate(receipt=receipt, signature=key.sign(gate_message(receipt)).hex())


def verify_gate(path, profile_path, public_key, stage, *, now=None):
    profile = load_wire(PrototypeProfile, Path(profile_path).read_bytes())
    signed = load_wire(SignedGate, Path(path).read_bytes())
    r = signed.receipt
    current = int(time.time()) if now is None else now
    if (sha256(public_key) != profile.authority_public_key_sha256
        or not verify(gate_message(r), signed.signature, public_key)
        or r.stage != stage or r.profile_sha256 != file_digest(profile_path)
        or not r.issued_at_unix <= current < r.expires_at_unix
        or r.expires_at_unix - r.issued_at_unix > 86400):
        raise DependencyUnavailable("STAGED_ADMISSION_SIGNATURE_SCOPE_OR_FRESHNESS_REJECTED")
    if profile.source_sha256 != source_hashes() or profile.component.admission.runtime_source_sha256 != runtime_source_hashes():
        raise DependencyUnavailable("STAGED_ADMISSION_SOURCE_CHANGED")
    check_source_binding(profile)
    check_inputs(profile)
    return signed


def check_inputs(profile):
    if not REQUIRED_INPUTS <= profile.input_sha256.keys():
        raise DependencyUnavailable("STAGED_ADMISSION_REQUIRED_INPUTS_MISSING")
    for relative, digest in profile.input_sha256.items():
        path = (BACKEND / relative).resolve()
        if not path.is_relative_to(BACKEND) or not path.is_file() or file_digest(path) != digest:
            raise DependencyUnavailable("STAGED_ADMISSION_INPUT_CHANGED")


def fresh_capacity(profile, *, probe=True):
    available = host_available_memory()
    if available < profile.host_available_memory_floor_bytes:
        raise DependencyUnavailable("HOST_PROTOTYPE_CAPACITY_BELOW_FLOOR")
    disk = shutil.disk_usage(BACKEND / "artifacts").free
    if disk < profile.disk_free_floor_bytes:
        raise DependencyUnavailable("PROTOTYPE_DISK_HEADROOM_UNAVAILABLE")
    result = {"host_available_bytes": available, "workspace_disk_free_bytes": disk}
    if probe:
        vm = capacity(profile.component.admission.defense_image)
        check_capacity(profile, vm)
        result["vm"] = vm
    return result


def static_check(profile_path, model, public_key):
    profile = load_wire(PrototypeProfile, Path(profile_path).read_bytes())
    if sha256(public_key) != profile.authority_public_key_sha256:
        raise DependencyUnavailable("EXTERNAL_ADMISSION_TRUST_MISMATCH")
    if profile.source_sha256 != source_hashes() or profile.component.admission.runtime_source_sha256 != runtime_source_hashes():
        raise DependencyUnavailable("STAGED_ADMISSION_SOURCE_CHANGED")
    check_source_binding(profile)
    check_inputs(profile)
    build = json.loads((BACKEND / "infra/model-component/build-provenance.json").read_bytes())
    if build.get("image_ids") != [profile.component.assembled_image_id] * 2:
        raise DependencyUnavailable("SELECTED_REPEATED_BUILD_PROVENANCE_MISMATCH")
    observation = Path(profile_path).parent / "publisher-observation.json"
    if file_digest(observation) != profile.component.publisher_observation_sha256:
        raise DependencyUnavailable("MODEL_PUBLISHER_OBSERVATION_CHANGED")
    validate_assets(profile.component, Path(model))
    image = validate_image(profile.component)
    defense = json.loads(docker("image", "inspect", profile.component.admission.defense_image))[0]
    if (defense.get("Os") != "linux" or defense.get("Architecture") != "amd64"
        or (defense["Config"].get("Labels") or {}).get("arena.defense_source_sha256") != profile.component.admission.defense_source_sha256):
        raise DependencyUnavailable("PINNED_DEFENSE_IMAGE_REJECTED")
    # This runs a fixed, no-network capacity fixture in the pinned defense image,
    # never an arbitrary image or a model. It is part of static preflight.
    resources = fresh_capacity(profile)
    versions = {name: importlib.metadata.version(name) for name in ("pydantic", "cryptography")}
    pins = {"pydantic": "2.14.1", "cryptography": "50.0.2"}
    if versions != pins:
        raise DependencyUnavailable("PROTOTYPE_PYTHON_DEPENDENCY_PINS_CHANGED")
    return {"result": "PASS_STATIC_CALIBRATION_ONLY", "model_image_id": image["Id"],
        "defense_image_id": defense["Id"], "capacity": resources, "dependency_versions": versions,
        "service_authorized": False, "full_t_p_acceptance": False}


def validate_calibration(observation, profile):
    """Validate measured facts rather than accepting a PASS string or test count."""
    if (observation.get("result") != "PASS_THREE_LANE_CALIBRATION"
        or observation.get("model_image_id") != profile.component.assembled_image_id
        or observation.get("real_model_dispatches") != 6
        or observation.get("containers_cleaned_up") is not True
        or type(observation.get("three_lane_overlap_ns")) is not int
        or observation["three_lane_overlap_ns"] <= 0):
        raise DependencyUnavailable("CALIBRATION_INCOMPLETE_OR_WRONG_SCOPE")
    cells = observation.get("cells", [])
    if (len(cells) != 3 or len({c.get("container_id") for c in cells}) != 3
        or [c.get("lane") for c in cells] != [0, 1, 2]):
        raise DependencyUnavailable("CALIBRATION_THREE_DISTINCT_LANES_REQUIRED")
    for cell, cpuset in zip(cells, profile.model_cpusets, strict=True):
        if (cell.get("cpuset") != cpuset or cell.get("image_id") != profile.component.assembled_image_id
            or type(cell.get("memory_peak_bytes")) is not int
            or not 0 < cell["memory_peak_bytes"] < profile.model_lane_memory_limit_bytes
            or cell.get("oom_kill") != 0 or cell.get("oom") != 0
            or cell.get("successful_calls") != 2):
            raise DependencyUnavailable("CALIBRATION_RESOURCE_OR_EXECUTION_MISMATCH")
    peak = sum(c["memory_peak_bytes"] for c in cells)
    if peak + 1073741824 > observation["capacity_before_start"]["vm"]["mem_available_bytes"]:
        raise DependencyUnavailable("CALIBRATION_AGGREGATE_HEADROOM_FAILED")


def service_check(profile_path, calibration_path, static_path, public_key):
    profile = load_wire(PrototypeProfile, Path(profile_path).read_bytes())
    static = verify_gate(static_path, profile_path, public_key, "STATIC")
    calibration = verify_gate(calibration_path, profile_path, public_key, "CALIBRATION")
    if calibration.receipt.parent_receipt_sha256 != file_digest(static_path):
        raise DependencyUnavailable("CALIBRATION_STATIC_PARENT_MISMATCH")
    validate_calibration(calibration.receipt.observations, profile)
    return {"result": "READY_FOR_BOUNDED_ARENA_EXECUTION", "capacity": fresh_capacity(profile),
        "static_sha256": file_digest(static_path), "calibration_sha256": file_digest(calibration_path),
        "cold_resume_authorized": False, "full_t_p_acceptance": False}
