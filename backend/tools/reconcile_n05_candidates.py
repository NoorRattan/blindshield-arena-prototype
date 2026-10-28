"""Verify MEM041 N05 pins carried in the incomplete environment lock.

This is a source/local-artifact reconciliation only. Candidate values remain
N05-scoped and never authorize an N08 profile or model workload.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys


BACKEND = Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
ACTIVE = REPOSITORY / "memory files" / "hackathon"
EVIDENCE = ACTIVE / "evidence"
MEM041 = "n08-fresh-n05-baseline-2026-10-25-mem041.json"
MEM041_INDEX = "n08-fresh-n05-baseline-2026-10-25-mem041-outputs.json"
MEM043 = "n08-exact-build-admission-gate-review-2026-10-25-mem043.json"
SOURCE_PATHS = (
    "backend/environment.lock.json",
    "backend/config/n04-sources.json",
    "backend/src/arena/integration/runtime.py",
    "backend/infra/source-allowlist.json",
    "backend/infra/preflight/policy.json",
    "backend/tools/reconcile_n05_candidates.py",
    f"memory files/hackathon/evidence/{MEM041}",
    f"memory files/hackathon/evidence/{MEM041_INDEX}",
    f"memory files/hackathon/evidence/{MEM043}",
)


def digest_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON_OBJECT_REQUIRED")
    return value


def source_hashes(repository_root: Path) -> dict[str, str]:
    result = {}
    for relative in SOURCE_PATHS:
        path = repository_root / relative
        if not path.is_file():
            raise ValueError("REQUIRED_SOURCE_MISSING")
        result[relative] = digest_file(path)
    return result


def cpu_ids(value: str) -> tuple[int, ...]:
    values = []
    for piece in value.split(","):
        part = piece.strip().split("-")
        if len(part) == 1:
            values.append(int(part[0]))
        elif len(part) == 2:
            start, end = map(int, part)
            if end < start:
                raise ValueError("INVALID_CPU_RANGE")
            values.extend(range(start, end + 1))
        else:
            raise ValueError("INVALID_CPU_SET")
    return tuple(sorted(set(values)))


def memory_limit_bytes(runtime_source: str) -> int:
    match = re.search(r'["\']--memory["\']\s*,\s*["\']([1-9][0-9]*)([gGmMkK])["\']', runtime_source)
    if not match:
        raise ValueError("N05_MEMORY_LIMIT_NOT_SOURCE_DERIVED")
    scale = {"g": 1024**3, "m": 1024**2, "k": 1024}[match.group(2).lower()]
    return int(match.group(1)) * scale


def _candidate_artifacts(backend_root: Path, source_config: dict, published: dict) -> dict:
    artifact_root = (backend_root / "artifacts").resolve()
    admission_path = backend_root / "artifacts/n05-prepared-mem041/admission.json"
    cell_path = backend_root / "artifacts/n05-prepared-mem041/cell-admission.json"
    model_name = source_config.get("model_filename")
    if not isinstance(model_name, str) or Path(model_name).name != model_name:
        raise ValueError("MODEL_FILENAME_INVALID")
    model_path = backend_root / "artifacts/n04-release-preparation" / model_name
    license_path = model_path.parent / "LICENSE"
    if not all(
        path.is_file() and path.resolve().is_relative_to(artifact_root)
        for path in (admission_path, cell_path, model_path, license_path)
    ):
        raise ValueError("LOCAL_N05_CANDIDATE_MISSING")

    local_admission = load_json(admission_path)
    cell_admission = load_json(cell_path)
    hashes = {
        "admission": digest_file(admission_path),
        "cell_admission": digest_file(cell_path),
        "model": digest_file(model_path),
        "license": digest_file(license_path),
    }
    facts_match = all(
        (
            hashes["admission"] == published["sha256"],
            hashes["cell_admission"] == published["cell_admission_sha256"],
            hashes["model"] == published["model_sha256"] == source_config["model_sha256"],
            hashes["license"] == published["model_license_sha256"] == source_config["model_license_sha256"],
            model_path.stat().st_size == source_config["model_bytes"],
            local_admission.get("model_sha256") == hashes["model"],
            local_admission.get("model_license_sha256") == hashes["license"],
            cell_admission.get("model_sha256") == hashes["model"],
            cell_admission.get("model_license_sha256") == hashes["license"],
            local_admission.get("model_revision") == source_config["model_revision"],
            local_admission.get("model_filename") == source_config["model_filename"],
            local_admission.get("tokenizer_binding") == "EMBEDDED_IN_EXACT_GGUF",
        )
    )
    if not facts_match:
        raise ValueError("LOCAL_N05_ARTIFACTS_DO_NOT_MATCH_MEM041")
    return {
        "hashes": hashes,
        "model_bytes": model_path.stat().st_size,
        "admission": local_admission,
        "cell_admission": cell_admission,
    }


def verify(repository_root: Path = REPOSITORY) -> dict:
    backend_root = repository_root / "backend"
    active = repository_root / "memory files" / "hackathon"
    evidence = active / "evidence"
    before = source_hashes(repository_root)

    lock = load_json(backend_root / "environment.lock.json")
    source_config = load_json(backend_root / "config/n04-sources.json")
    source_allowlist = load_json(backend_root / "infra/source-allowlist.json")
    fixture_policy = load_json(backend_root / "infra/preflight/policy.json")
    mem041_path = evidence / MEM041
    mem041 = load_json(mem041_path)
    mem041_index_path = evidence / MEM041_INDEX
    mem043_path = evidence / MEM043
    mem043 = load_json(mem043_path)
    if not source_config["llama_image"].endswith("@" + mem041["admission"]["model_image_digest"]):
        raise ValueError("MODEL_IMAGE_REFERENCE_DIGEST_MISMATCH")
    candidate = lock.get("n05_candidate")
    prior_candidate = mem043.get("mem041_n05_candidate_facts")
    if not isinstance(candidate, dict) or not isinstance(prior_candidate, dict):
        raise ValueError("N05_CANDIDATE_OBJECT_MISSING")

    artifacts_before = _candidate_artifacts(backend_root, source_config, mem041["admission"])
    runtime_text = (backend_root / "src/arena/integration/runtime.py").read_text(encoding="utf-8")
    model_limit = memory_limit_bytes(runtime_text)
    expected = {
        "schema_version": "arena-n05-environment-candidate.v1",
        "status": "CANDIDATE_NOT_N08_ADMISSION",
        "scope": "N05_LOCAL_THREE_PROCESS_BASELINE_NOT_FULL_ARENA_ACCEPTANCE",
        "source_revision": "MEM-041",
        "base_commit": mem041["base_commit"],
        "base_tree": mem041["base_tree"],
        "receipt_path": "../memory files/hackathon/evidence/" + MEM041,
        "receipt_sha256": digest_file(mem041_path),
        "outputs_index_path": "../memory files/hackathon/evidence/" + MEM041_INDEX,
        "outputs_index_sha256": digest_file(mem041_index_path),
        "admission_sha256": mem041["admission"]["sha256"],
        "cell_admission_sha256": mem041["admission"]["cell_admission_sha256"],
        "model": {
            "repository": source_config["model_repository"],
            "revision": source_config["model_revision"],
            "filename": source_config["model_filename"],
            "bytes": source_config["model_bytes"],
            "sha256": source_config["model_sha256"],
            "license": source_config["model_license"],
            "license_sha256": source_config["model_license_sha256"],
            "readme_sha256": source_config["model_readme_sha256"],
            "tokenizer_binding": "EMBEDDED_IN_EXACT_GGUF",
        },
        "images": {
            "model": {
                "reference": source_config["llama_image"],
                "digest": mem041["admission"]["model_image_digest"],
                "source_revision": source_config["llama_source_revision"],
                "platform": source_config["platform"],
            },
            "defense": {
                "digest": mem041["admission"]["defense_image_digest"],
                "python_base": source_config["defense_python_base"],
                "platform": source_config["platform"],
            },
        },
        "runtime_limits": {
            "context_tokens": artifacts_before["cell_admission"]["context_tokens"],
            "input_token_cap": artifacts_before["cell_admission"]["input_token_cap"],
            "max_output_tokens": artifacts_before["cell_admission"]["max_output_tokens"],
            "deadline_seconds": artifacts_before["cell_admission"]["deadline_seconds"],
        },
        "resources": {
            "model_cpu_sets": artifacts_before["admission"]["model_cpusets"],
            "defense_cpu_set": artifacts_before["admission"]["defense_cpuset"],
            "model_lane_memory_limit_bytes": model_limit,
            "model_lane_memory_limit_source": "backend/src/arena/integration/runtime.py",
            "minimum_available_memory_bytes": mem041["admission"]["minimum_available_memory_bytes"],
            "linux_vm_available_bytes_before_cells": mem041["admission"]["linux_vm_available_bytes_before_cells"],
            "windows_host_available_bytes_during_n05_observation": mem041["runtime_observation"]["windows_host_available_bytes"],
            "capacity_floor_bytes_during_n05_observation": mem041["runtime_observation"]["capacity_floor_bytes"],
            "windows_host_below_floor_by_bytes": mem041["runtime_observation"]["windows_host_below_floor_by_bytes"],
        },
        "bounded_n05_measurements": {
            "observed_processing_overlap_ns": mem041["n05_run"]["observed_processing_overlap_ns"],
            "containers_changed_before_reuse": mem041["n05_run"]["containers_changed_before_reuse"],
            "host_cpu_exclusivity_verified": mem041["n05_run"]["host_cpu_exclusivity_verified"],
            "full_probe_acceptance": mem041["n05_run"]["full_probe_acceptance"],
            "full_arena_acceptance": mem041["n05_run"]["full_arena_acceptance"],
            "guarantee_tier_achieved": mem041["n05_run"]["guarantee_tier_achieved"],
        },
        "n08_workload_authorized": False,
    }
    if candidate != expected:
        raise ValueError("N05_CANDIDATE_LOCK_MISMATCH")
    review_matches = all(
        (
            prior_candidate.get("local_n05_admission_matches_mem041") is True,
            prior_candidate.get("model_artifact_matches_mem041") is True,
            prior_candidate.get("license_file_matches_mem041") is True,
            prior_candidate.get("candidate_model_revision") == candidate["model"]["revision"],
            prior_candidate.get("candidate_model_license") == candidate["model"]["license"],
            prior_candidate.get("candidate_llama_source_revision") == candidate["images"]["model"]["source_revision"],
            prior_candidate.get("candidate_model_image_id") == candidate["images"]["model"]["digest"],
            prior_candidate.get("candidate_defense_image_id") == candidate["images"]["defense"]["digest"],
            prior_candidate.get("candidate_tokenizer_binding") == candidate["model"]["tokenizer_binding"],
            prior_candidate.get("candidate_input_token_cap") == candidate["runtime_limits"]["input_token_cap"],
            prior_candidate.get("candidate_context_tokens") == candidate["runtime_limits"]["context_tokens"],
            prior_candidate.get("candidate_max_output_tokens") == candidate["runtime_limits"]["max_output_tokens"],
            prior_candidate.get("candidate_deadline_seconds") == candidate["runtime_limits"]["deadline_seconds"],
            prior_candidate.get("candidate_model_cpusets") == candidate["resources"]["model_cpu_sets"],
            prior_candidate.get("candidate_defense_cpuset") == candidate["resources"]["defense_cpu_set"],
            prior_candidate.get("candidate_minimum_available_memory_bytes") == candidate["resources"]["minimum_available_memory_bytes"],
            prior_candidate.get("candidate_model_lane_memory_limit_bytes") == candidate["resources"]["model_lane_memory_limit_bytes"],
            prior_candidate.get("candidate_scope") == candidate["scope"],
        )
    )
    if not review_matches:
        raise ValueError("MEM043_CANDIDATE_REVIEW_MISMATCH")
    if not all(
        (
            lock.get("status") == "INCOMPLETE_NOT_READY",
            lock.get("lock_complete") is False,
            lock["linux_runtime"].get("image_ids") == [],
            lock["linux_runtime"].get("effective_profile_id") is None,
            lock["model"].get("artifact_sha256") is None,
            lock["model"].get("tokenizer_sha256") is None,
            lock["model"].get("backend_revision") is None,
            lock["model"].get("license_lock") is None,
            lock["model"].get("model_specific_input_token_cap") is None,
            lock["model"].get("three_lane_peak_memory_measured") is False,
            lock["resource_policy"].get("policy_frozen") is False,
            all(value is None for value in lock["authorities"].values()),
            source_allowlist.get("approved_execution_images") == [],
            fixture_policy.get("approved_probe_images") == [],
        )
    ):
        raise ValueError("N08_ADMISSION_FIELDS_WERE_PROMOTED")

    artifacts_after = _candidate_artifacts(backend_root, source_config, mem041["admission"])
    after = source_hashes(repository_root)
    if before != after:
        raise ValueError("SOURCE_CHANGED_DURING_RECONCILIATION")
    if artifacts_before["hashes"] != artifacts_after["hashes"]:
        raise ValueError("LOCAL_CANDIDATES_CHANGED_DURING_RECONCILIATION")

    return {
        "schema_version": "arena-n08-n05-candidate-reconciliation.v1",
        "revision": "MEM-044",
        "status": "PASS_N05_CANDIDATES_ONLY_N08_REMAINS_NOT_READY",
        "scope": "SOURCE_AND_LOCAL_ARTIFACT_N05_CANDIDATE_RECONCILIATION",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_revision": "MEM-041",
        "source_base_commit": mem041["base_commit"],
        "source_file_count": len(after),
        "source_sha256": after,
        "source_unchanged_during_review": True,
        "candidate_artifact_sha256": artifacts_after["hashes"],
        "candidate_model_bytes": artifacts_after["model_bytes"],
        "candidate_artifacts_unchanged_during_review": True,
        "candidate_inventory_sha256": digest_file(backend_root / "environment.lock.json"),
        "candidate_status": candidate["status"],
        "n08_profile_set": False,
        "n08_authorities_provisioned": False,
        "approved_execution_image_count": 0,
        "approved_synthetic_preflight_image_count": 0,
        "n08_resource_policy_frozen": False,
        "n08_peak_memory_measured": False,
        "workload_authorized": False,
        "model_workload_started": False,
        "docker_queries_performed": False,
        "docker_mutations_performed": False,
        "network_access_performed": False,
        "frontend_changed": False,
        "historical_evidence_rewritten": False,
        "n07_acceptance": False,
        "n08_acceptance": False,
        "all_t_p_acceptance": False,
        "arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }


def output_path(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(EVIDENCE.resolve()) or resolved.suffix != ".json":
        raise ValueError("OUTPUT_MUST_BE_JSON_UNDER_PROJECT_EVIDENCE")
    if resolved.exists():
        raise FileExistsError("OUTPUT_ALREADY_EXISTS")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New sanitized JSON under project evidence")
    args = parser.parse_args()
    try:
        target = output_path(args.output)
        report = verify()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
        print(json.dumps({
            "result": report["status"],
            "source_file_count": report["source_file_count"],
            "candidate_model_bytes": report["candidate_model_bytes"],
            "workload_authorized": False,
            "model_workload_started": False,
            "output": target.relative_to(REPOSITORY).as_posix(),
        }))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        message = str(exc).replace(str(REPOSITORY), "REPOSITORY_ROOT").replace(str(BACKEND), "BACKEND_ROOT")
        print("N05 candidate reconciliation failed: " + message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
