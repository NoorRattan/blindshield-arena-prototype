"""Prepare a pinned publisher-Qwen model component; never global N08 admission."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire
from arena.integration.runtime import docker, ensure_local_docker, runtime_source_hashes
from arena.integration.types import AdmissionLock
from arena.model_runtime import BACKEND, ModelProfile, file_digest, validate_assets, validate_image


def prepare(model_dir: Path, output: Path, base_admission: Path) -> ModelProfile:
    output = output.resolve()
    if not output.is_relative_to((BACKEND / "artifacts").resolve()) or output.exists():
        raise ValueError("NEW_MODEL_PROFILE_DIRECTORY_UNDER_ARTIFACTS_REQUIRED")
    pins = json.loads((BACKEND / "config/n04-sources.json").read_bytes())
    model = model_dir / pins["model_filename"]
    for name, expected in ((pins["model_filename"], pins["model_sha256"]), ("LICENSE", pins["model_license_sha256"]), ("README.md", pins["model_readme_sha256"])):
        if file_digest(model_dir / name) != expected:
            raise ValueError("LOCAL_PUBLISHER_ASSET_MISMATCH")
    if model.stat().st_size != pins["model_bytes"]:
        raise ValueError("LOCAL_MODEL_SIZE_MISMATCH")
    opener = build_opener(ProxyHandler({}))
    base = f'https://huggingface.co/{pins["model_repository"]}/resolve/{pins["model_revision"]}/'
    tree_url = f'https://huggingface.co/api/models/{pins["model_repository"]}/tree/{pins["model_revision"]}'
    with opener.open(tree_url, timeout=45) as response:
        entries = json.loads(response.read(1_000_000))
    entry = next(item for item in entries if item.get("path") == pins["model_filename"])
    if entry["size"] != pins["model_bytes"] or entry.get("lfs", {}).get("oid") != pins["model_sha256"]:
        raise ValueError("PINNED_PUBLISHER_MODEL_METADATA_MISMATCH")
    observed = {}
    for name in ("LICENSE", "README.md"):
        with opener.open(base + name, timeout=45) as response:
            raw = response.read(200_001)
        expected = pins["model_license_sha256" if name == "LICENSE" else "model_readme_sha256"]
        if len(raw) > 200_000 or sha256(raw) != expected:
            raise ValueError("PINNED_PUBLISHER_LICENSE_OR_CARD_MISMATCH")
        observed[name] = {"sha256": sha256(raw), "bytes": len(raw)}
    observation = {
        "schema_version": "arena-publisher-model-observation.v1",
        "artifact_label": "OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE",
        "repository": pins["model_repository"], "revision": pins["model_revision"],
        "tree_url": tree_url, "model": entry, "small_files": observed,
        "local_model_sha256": file_digest(model),
        "scope": "Publisher asset identity and exact local bytes; independent training/quantization lineage is not established",
    }
    # Explicit preparation may use public HTTPS. Runtime below never downloads.
    ensure_local_docker()
    base_image = json.loads(docker("image", "inspect", pins["llama_image"]))[0]
    # Bind timestamps to the immutable publisher image. Default BuildKit
    # attestation timestamps otherwise change the image index on every build;
    # the explicit build receipt below preserves our local assembly provenance.
    created = base_image["Config"]["Labels"]["org.opencontainers.image.created"]
    source_epoch = str(int(datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp()))
    output.mkdir(parents=True)
    observation_raw = (json.dumps(observation, indent=2) + "\n").encode()
    (output / "publisher-observation.json").write_bytes(observation_raw)
    recipe = BACKEND / "infra/cells/Dockerfile.model"
    recipe_hash = file_digest(recipe)
    args = ["build", "--network", "none", "--pull=false", "--provenance=false", "--platform", "linux/amd64",
            "--build-arg", "SOURCE_DATE_EPOCH=" + source_epoch,
            "--build-arg", "LLAMA_BASE=" + pins["llama_image"],
            "--build-arg", "LLAMA_REVISION=" + pins["llama_source_revision"],
            "--build-arg", "MODEL_SHA256=" + pins["model_sha256"],
            "--build-arg", "RECIPE_SHA256=" + recipe_hash,
            "--iidfile", str(output / "model-image.id"), "--file", str(recipe), str(recipe.parent)]
    docker(*args, timeout=180)
    image_id = (output / "model-image.id").read_text().strip()
    admission = load_wire(AdmissionLock, base_admission.read_bytes())
    admission = AdmissionLock.model_validate(admission.model_dump() | {"runtime_source_sha256": runtime_source_hashes()})
    profile = ModelProfile(
        schema_version="arena-model-component-profile.v1", profile_id="qwen25-05b-cpu-component-v1",
        authorization="BOUNDED_STEP2_MODEL_COMPONENT_VALIDATION_ONLY",
        artifact_label="OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE",
        n08_workload_authorized=False, admission=admission, model_bytes=pins["model_bytes"],
        model_readme_sha256=pins["model_readme_sha256"], assembled_image_id=image_id,
        dockerfile_sha256=recipe_hash, publisher_observation_sha256=sha256(observation_raw),
        host_available_memory_floor_bytes=8589934592,
    )
    validate_assets(profile, model)
    image = validate_image(profile)
    (output / "profile.json").write_text(profile.model_dump_json(indent=2) + "\n", encoding="utf-8")
    build = {"schema_version": "arena-model-build.v1", "command": ["docker", *args],
             "network": "none", "automatic_pulls": False, "image_id": image_id,
             "base_image": pins["llama_image"], "dockerfile_sha256": recipe_hash,
             "rootfs_layers": image["RootFS"]["Layers"], "runtime_downloads": False,
             "source_date_epoch": source_epoch, "default_timestamped_attestation": False,
             "scope": "Reproducible assembly from a pinned publisher binary image; not an independent source compilation"}
    (output / "build.json").write_text(json.dumps(build, indent=2) + "\n", encoding="utf-8")
    return profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--base-admission", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    profile = prepare(args.model_dir.resolve(), args.output, args.base_admission)
    print(json.dumps({"result": "MODEL_COMPONENT_PREPARED_NOT_N08_READY", "image_id": profile.assembled_image_id,
                      "profile_sha256": file_digest(args.output / "profile.json")}))


if __name__ == "__main__":
    main()
