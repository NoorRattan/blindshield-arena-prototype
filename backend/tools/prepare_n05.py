"""Freeze three-lane CPU topology using existing admitted local artifacts; no downloads."""

import argparse
import json
from pathlib import Path

from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire
from arena.integration.types import AdmissionLock
from arena.integration.runtime import runtime_source_hashes
from arena.integration.lanes import LaneAdmission, capacity, select_cpus, check_capacity


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts") or output.exists():
        raise ValueError("NEW_IGNORED_PREPARATION_DIRECTORY_REQUIRED")
    base = load_wire(AdmissionLock, args.cell_lock.read_bytes())
    pins = json.loads((ROOT / "config/n04-sources.json").read_bytes())
    for name in ("model_repository", "model_revision", "model_filename", "model_sha256", "model_license_sha256",
                 "llama_image", "llama_source_revision", "defense_python_base"):
        if getattr(base, name) != pins[name]:
            raise ValueError("CELL_ADMISSION_NOT_PINNED")
    # Re-freeze new source in new files. Original admission/receipts remain immutable.
    base = base.model_copy(update={"runtime_source_sha256": runtime_source_hashes()})
    base = AdmissionLock.model_validate(base.model_dump())
    base_raw = (base.model_dump_json(indent=2) + "\n").encode()
    observed = capacity(base.defense_image)
    cpus, defense_cpus = select_cpus(observed)
    admission = LaneAdmission.model_validate({
        **base.model_dump(), "schema_version": "arena-n05-admission.v1",
        "claim_scope": "N05_LOCAL_THREE_PROCESS_BASELINE_NOT_FULL_ARENA_ACCEPTANCE",
        "cell_admission_sha256": sha256(base_raw), "model_cpusets": cpus, "defense_cpuset": defense_cpus,
        "minimum_available_memory_bytes": 7516192768,
    })
    check_capacity(admission, observed)
    output.mkdir(parents=True)
    (output / "cell-admission.json").write_bytes(base_raw)
    (output / "admission.json").write_text(admission.model_dump_json(indent=2) + "\n", encoding="ascii")
    (output / "capacity.json").write_text(json.dumps(observed, indent=2) + "\n", encoding="ascii")
    print(json.dumps({"result": "PREPARED_NOT_ARENA_READY", "model_cpusets": cpus,
                      "defense_cpuset": defense_cpus, "observed_mem_available_bytes": observed["mem_available_bytes"],
                      "runtime_downloads": False}))


if __name__ == "__main__":
    main()
