"""Freeze a new selected-runtime candidate. Grants no model or service permission."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from arena.contracts.jsonwire import load_wire
from arena.integration.lanes import capacity, select_cpus
from arena.integration.runtime import runtime_source_hashes
from arena.model_runtime import BACKEND, ModelProfile, file_digest, validate_image
from arena.prototype.admission import PrototypeProfile, REQUIRED_INPUTS, authority_public, check_source_binding, key_public, source_hashes
from arena.contracts.crypto import sha256


def prepare(component_path, public_path, output):
    output = Path(output).resolve()
    if not output.is_relative_to(BACKEND / "artifacts") or output.exists():
        raise ValueError("NEW_PRIVATE_PREPARATION_DIRECTORY_REQUIRED")
    original = load_wire(ModelProfile, Path(component_path).read_bytes())
    if file_digest(component_path) != file_digest(BACKEND / "infra/model-component/profile.json"):
        raise ValueError("EXACT_SELECTED_COMPONENT_REQUIRED")
    validate_image(original)
    # Refresh host implementation admission in a NEW derived profile only.
    admission = original.admission.model_copy(update={"runtime_source_sha256": runtime_source_hashes()})
    component = ModelProfile.model_validate(original.model_dump() | {"admission": admission.model_dump()})
    cpus, defense = select_cpus(capacity(admission.defense_image))
    if key_public(public_path) != authority_public("recorder"):
        raise ValueError("PINNED_OWNER_ADMISSION_AUTHORITY_REQUIRED")
    bindings = sorted(REQUIRED_INPUTS)
    profile = PrototypeProfile(component=component, model_cpusets=cpus, defense_cpuset=defense,
        source_sha256=source_hashes(), input_sha256={p: file_digest(BACKEND / p) for p in bindings},
        source_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=BACKEND, text=True).strip(),
        authority_public_key_sha256=sha256(key_public(public_path)))
    check_source_binding(profile)
    output.mkdir(parents=True)
    (output / "profile.json").write_bytes((profile.model_dump_json(indent=2) + "\n").encode())
    shutil.copyfile(Path(component_path).parent / "publisher-observation.json", output / "publisher-observation.json")
    print(json.dumps({"result": "CANDIDATE_ONLY_NO_WORKLOAD_AUTHORITY", "profile_sha256": file_digest(output / "profile.json")}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--component", required=True, type=Path)
    p.add_argument("--authority-public-key", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    prepare(a.component, a.authority_public_key, a.output)
