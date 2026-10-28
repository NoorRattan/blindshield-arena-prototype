"""Pinned, locally assembled Qwen model cell; component admission, not N08.

The existing llama.cpp protocol and hardened Docker lifecycle are reused.
This separately versioned profile admits the actual locally built image ID;
historical N04 admission types and signing bytes are unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import Field

from arena.contracts.common import Digest, WireModel
from arena.contracts.jsonwire import load_wire
from arena.integration.runtime import DockerRuntime, docker, ensure_local_docker
from arena.integration.types import AdmissionLock
from arena.ports import DependencyUnavailable


BACKEND = Path(__file__).resolve().parents[2]
ImageId = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class ModelProfile(WireModel):
    schema_version: Literal["arena-model-component-profile.v1"]
    profile_id: Literal["qwen25-05b-cpu-component-v1"]
    authorization: Literal["BOUNDED_STEP2_MODEL_COMPONENT_VALIDATION_ONLY"]
    artifact_label: Literal["OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE"]
    n08_workload_authorized: Literal[False]
    admission: AdmissionLock
    model_bytes: Annotated[int, Field(strict=True, gt=0)]
    model_readme_sha256: Digest
    assembled_image_id: ImageId
    dockerfile_sha256: Digest
    publisher_observation_sha256: Digest
    host_available_memory_floor_bytes: Literal[8589934592]


def file_digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def host_available_memory() -> int:
    if os.name == "nt":
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong) for name in
                ("total", "available", "page_total", "page_available", "virtual_total", "virtual_available", "extended")
            ]
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise DependencyUnavailable("HOST_CAPACITY_UNAVAILABLE")
        return int(status.available)
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise DependencyUnavailable("HOST_CAPACITY_UNAVAILABLE")


def validate_assets(profile: ModelProfile, model: Path) -> None:
    """Reject missing/changed inputs before contacting Docker or dispatching."""
    pins = json.loads((BACKEND / "config/n04-sources.json").read_bytes())
    admission = profile.admission
    for name in (
        "model_repository", "model_revision", "model_filename", "model_sha256",
        "model_license", "model_license_sha256", "llama_image",
        "llama_source_revision", "defense_python_base",
    ):
        if getattr(admission, name) != pins[name]:
            raise DependencyUnavailable("MODEL_PROFILE_SOURCE_PIN_MISMATCH")
    if profile.model_bytes != pins["model_bytes"] or profile.model_readme_sha256 != pins["model_readme_sha256"]:
        raise DependencyUnavailable("MODEL_PROFILE_ASSET_PIN_MISMATCH")
    if not model.is_file():
        raise DependencyUnavailable("MODEL_FILE_MISSING")
    if model.stat().st_size != profile.model_bytes or file_digest(model) != admission.model_sha256:
        raise DependencyUnavailable("MODEL_BYTES_CHANGED")
    for name, expected in (("LICENSE", admission.model_license_sha256), ("README.md", profile.model_readme_sha256)):
        path = model.parent / name
        if not path.is_file() or file_digest(path) != expected:
            raise DependencyUnavailable("MODEL_LICENSE_OR_CARD_CHANGED")
    if file_digest(BACKEND / "infra/cells/Dockerfile.model") != profile.dockerfile_sha256:
        raise DependencyUnavailable("MODEL_BUILD_RECIPE_CHANGED")


def validate_image(profile: ModelProfile) -> dict:
    ensure_local_docker()
    base = json.loads(docker("image", "inspect", profile.admission.llama_image))[0]
    image = json.loads(docker("image", "inspect", profile.assembled_image_id))[0]
    labels = image["Config"].get("Labels") or {}
    if (
        image["Id"] != profile.assembled_image_id
        or image.get("Os") != "linux" or image.get("Architecture") != "amd64"
        or labels.get("org.opencontainers.image.revision") != profile.admission.llama_source_revision
        or labels.get("arena.model_sha256") != profile.admission.model_sha256
        or labels.get("arena.model_recipe_sha256") != profile.dockerfile_sha256
        or labels.get("arena.model_profile") != profile.profile_id
        or image["Config"].get("User") != "65534:65534"
        or image["Config"].get("Entrypoint") != base["Config"].get("Entrypoint")
        or image.get("RootFS", {}).get("Layers") != base.get("RootFS", {}).get("Layers")
    ):
        raise DependencyUnavailable("MODEL_ASSEMBLED_IMAGE_BINDING_MISMATCH")
    return image


class ModelCellRuntime(DockerRuntime):
    """Use the assembled image, with the existing private llama.cpp adapter.

    No participant route accepts this profile. The caller must be a trusted
    local component operator. Readiness here establishes only model-cell fit.
    """

    def __init__(self, profile_path: Path, model_path: Path, private_root: Path):
        self.profile_path = profile_path.resolve()
        self.lock_bytes = profile_path.read_bytes()
        self.profile = load_wire(ModelProfile, self.lock_bytes)
        self.lock = self.profile.admission.model_dump()
        self.lock["llama_image"] = self.profile.assembled_image_id
        self.model_path = Path(model_path).resolve()
        self.root = Path(private_root).resolve()
        if not self.root.is_relative_to((BACKEND / "artifacts").resolve()):
            raise ValueError("MODEL_RUNTIME_OUTPUT_MUST_STAY_IN_IGNORED_ARTIFACTS")
        self.root.mkdir(parents=True, exist_ok=False)
        self.container = "arena-model-component-" + uuid4().hex
        self.model = None
        self.started = False
        self._owns_local_resources = False

    def start(self):
        validate_assets(self.profile, self.model_path)
        observation = self.profile_path.parent / "publisher-observation.json"
        if not observation.is_file() or file_digest(observation) != self.profile.publisher_observation_sha256:
            raise DependencyUnavailable("MODEL_PUBLISHER_OBSERVATION_CHANGED")
        if host_available_memory() < self.profile.host_available_memory_floor_bytes:
            raise DependencyUnavailable("HOST_MODEL_COMPONENT_CAPACITY_BELOW_FLOOR")
        validate_image(self.profile)
        return super().start()
