"""Review N08 build/admission inputs without Docker, network or model execution.

This reports source-bound N05 candidate facts and unresolved N08 gates. It never
approves an image, completes the environment lock, or authorizes a workload.
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
MEM041_RECEIPT = Path("memory files/hackathon/evidence/n08-fresh-n05-baseline-2026-10-25-mem041.json")
MEM042_RECEIPT = Path("memory files/hackathon/evidence/n08-passive-runtime-environment-lock-inventory-2026-10-25-mem042.json")
SOURCE_PATHS = (
    "backend/environment.lock.json",
    "backend/infra/source-allowlist.json",
    "backend/infra/preflight/policy.json",
    "backend/config/n04-sources.json",
    "backend/tools/prepare_n05.py",
    "backend/tools/verify_n05.py",
    "backend/src/arena/integration/types.py",
    "backend/src/arena/integration/lanes.py",
    "backend/src/arena/integration/runtime.py",
    "backend/infra/cells/Dockerfile.defense",
    "backend/infra/cells/defense.py",
    "backend/tools/review_n08_gates.py",
    "memory files/hackathon/evidence/n08-fresh-n05-baseline-2026-10-25-mem041.json",
    "memory files/hackathon/evidence/n08-passive-runtime-environment-lock-inventory-2026-10-25-mem042.json",
)
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


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


def image_id(reference) -> str | None:
    if not isinstance(reference, str):
        return None
    if "@" in reference:
        reference = reference.rsplit("@", 1)[1]
    return reference if SHA256.fullmatch(reference) else None


def _mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _approved_image_id(value) -> str | None:
    if isinstance(value, dict):
        return image_id(value.get("image_id"))
    return image_id(value)


def _n05_model_memory_limit(runtime_source: str) -> int | None:
    """Extract the first Docker --memory value, which is the N05 model cell."""
    match = re.search(r'["\']--memory["\']\s*,\s*["\']([1-9][0-9]*)([gGmMkK])["\']', runtime_source)
    if not match:
        return None
    quantity = int(match.group(1))
    unit = match.group(2).lower()
    scale = {"g": 1024 ** 3, "m": 1024 ** 2, "k": 1024}[unit]
    return quantity * scale


def _source_hashes(repository_root: Path) -> tuple[dict[str, str], list[str]]:
    hashes: dict[str, str] = {}
    missing: list[str] = []
    for relative in SOURCE_PATHS:
        path = repository_root / relative
        if not path.is_file():
            missing.append(relative)
        else:
            hashes[relative] = digest_file(path)
    return hashes, missing


def _read_candidate_artifacts(backend_root: Path, source_config: dict, published_admission: dict) -> dict:
    artifact_root = (backend_root / "artifacts").resolve()
    admission_path = backend_root / "artifacts/n05-prepared-mem041/admission.json"
    model_name = source_config.get("model_filename")
    if not isinstance(model_name, str) or Path(model_name).name != model_name or "/" in model_name or "\\" in model_name:
        model_name = None
    model_path = backend_root / "artifacts/n04-release-preparation" / model_name if model_name else None
    license_path = model_path.parent / "LICENSE" if model_path else None

    local_admission = None
    local_admission_sha = None
    if admission_path.is_file() and admission_path.resolve().is_relative_to(artifact_root):
        try:
            local_admission_sha = digest_file(admission_path)
            local_admission = load_json(admission_path)
        except (OSError, ValueError, TypeError):
            # A malformed ignored admission is a missing candidate, not permission
            # to use fields copied from it.
            local_admission = None

    model_sha = None
    model_bytes = None
    if model_path and model_path.is_file() and model_path.resolve().is_relative_to(artifact_root):
        model_sha = digest_file(model_path)
        model_bytes = model_path.stat().st_size
    license_sha = None
    if license_path and license_path.is_file() and license_path.resolve().is_relative_to(artifact_root):
        license_sha = digest_file(license_path)

    expected_model = published_admission.get("model_sha256")
    expected_license = published_admission.get("model_license_sha256")
    expected_admission = published_admission.get("sha256")
    expected_model_image = published_admission.get("model_image_digest")
    expected_defense_image = published_admission.get("defense_image_digest")

    local_facts_match = isinstance(local_admission, dict) and all((
        local_admission_sha == expected_admission,
        local_admission.get("model_sha256") == expected_model,
        local_admission.get("model_license_sha256") == expected_license,
        image_id(local_admission.get("llama_image")) == expected_model_image,
        image_id(local_admission.get("defense_image")) == expected_defense_image,
    ))
    verified_admission = local_admission if local_facts_match else {}
    runtime_source_path = backend_root / "src/arena/integration/runtime.py"
    try:
        runtime_source = runtime_source_path.read_text(encoding="utf-8")
    except OSError:
        runtime_source = ""
    return {
        "published_mem041_admission_sha256": expected_admission,
        "published_mem041_model_sha256": expected_model,
        "published_mem041_license_sha256": expected_license,
        "local_n05_admission_present": local_admission is not None,
        "local_n05_admission_sha256": local_admission_sha,
        "local_n05_admission_matches_mem041": local_facts_match,
        "model_artifact_present": model_sha is not None,
        "model_artifact_bytes": model_bytes,
        "model_artifact_sha256": model_sha,
        "model_artifact_matches_mem041": model_sha == expected_model if model_sha else False,
        "license_file_present": license_sha is not None,
        "license_file_sha256": license_sha,
        "license_file_matches_mem041": license_sha == expected_license if license_sha else False,
        "candidate_model_revision": verified_admission.get("model_revision"),
        "candidate_model_license": verified_admission.get("model_license"),
        "candidate_llama_source_revision": verified_admission.get("llama_source_revision"),
        "candidate_model_image_id": expected_model_image if local_facts_match else None,
        "candidate_defense_image_id": expected_defense_image if local_facts_match else None,
        "candidate_tokenizer_binding": verified_admission.get("tokenizer_binding"),
        "candidate_input_token_cap": verified_admission.get("input_token_cap"),
        "candidate_context_tokens": verified_admission.get("context_tokens"),
        "candidate_max_output_tokens": verified_admission.get("max_output_tokens"),
        "candidate_deadline_seconds": verified_admission.get("deadline_seconds"),
        "candidate_scope": verified_admission.get("claim_scope"),
        "candidate_model_cpusets": verified_admission.get("model_cpusets"),
        "candidate_defense_cpuset": verified_admission.get("defense_cpuset"),
        "candidate_minimum_available_memory_bytes": verified_admission.get("minimum_available_memory_bytes"),
        "candidate_model_lane_memory_limit_bytes": _n05_model_memory_limit(runtime_source),
        "candidate_model_lane_memory_limit_source": "backend/src/arena/integration/runtime.py" if runtime_source else None,
        "candidate_scope_note": "Only fields from a local admission whose bytes match MEM041 are emitted as N05 candidates; none is N08 approval.",
    }


def review(backend_root: Path = BACKEND, repository_root: Path = REPOSITORY,
           reviewed_source_commit: str | None = None) -> dict:
    """Return a sanitized source-only gate report; this function performs no external calls."""
    backend_root = backend_root.resolve()
    repository_root = repository_root.resolve()
    lock_path = backend_root / "environment.lock.json"
    allowlist_path = backend_root / "infra/source-allowlist.json"
    fixture_policy_path = backend_root / "infra/preflight/policy.json"
    source_config_path = backend_root / "config/n04-sources.json"
    n05_receipt_path = repository_root / MEM041_RECEIPT
    n042_receipt_path = repository_root / MEM042_RECEIPT

    before_hashes, missing_sources = _source_hashes(repository_root)
    lock = load_json(lock_path)
    allowlist = load_json(allowlist_path)
    fixture_policy = load_json(fixture_policy_path)
    source_config = load_json(source_config_path)
    n05_receipt = load_json(n05_receipt_path)
    n042_receipt = load_json(n042_receipt_path)
    published_admission = n05_receipt.get("admission")
    if not isinstance(published_admission, dict):
        raise ValueError("PUBLISHED_N05_ADMISSION_SUMMARY_REQUIRED")
    facts = _read_candidate_artifacts(backend_root, source_config, published_admission)

    blockers: list[dict[str, str]] = []

    def block(code: str, detail: str) -> None:
        blockers.append({"code": code, "detail": detail})

    lock = _mapping(lock)
    allowlist = _mapping(allowlist)
    fixture_policy = _mapping(fixture_policy)
    prior_runtime = _mapping(_mapping(n042_receipt).get("runtime_observation"))
    linux_runtime = _mapping(lock.get("linux_runtime"))
    tooling = _mapping(lock.get("tooling"))
    model = _mapping(lock.get("model"))
    authorities = _mapping(lock.get("authorities"))
    resource_policy = _mapping(lock.get("resource_policy"))
    approved_execution_images = allowlist.get("approved_execution_images")
    fixture_images = fixture_policy.get("approved_probe_images")
    approved_execution_images_valid = isinstance(approved_execution_images, list)
    fixture_images_valid = isinstance(fixture_images, list)
    approved_image_ids = {
        parsed for item in _list(approved_execution_images)
        if (parsed := _approved_image_id(item)) is not None
    }
    locked_image_ids_raw = linux_runtime.get("image_ids")
    locked_image_ids_valid = isinstance(locked_image_ids_raw, list)
    locked_image_ids = {
        parsed for item in _list(locked_image_ids_raw)
        if (parsed := image_id(item)) is not None
    }

    if lock.get("status") != "INCOMPLETE_NOT_READY" or lock.get("lock_complete") is not False:
        block("ENVIRONMENT_LOCK_NOT_IN_EXPECTED_FAIL_CLOSED_STATE",
              "The source-only review requires the current lock to remain incomplete until every N08 gate is proven.")
    if not approved_execution_images_valid:
        block("EXECUTION_IMAGE_ALLOWLIST_MALFORMED", "The approved execution image catalog must be a list of immutable image references.")
    if not _list(approved_execution_images):
        block("NO_APPROVED_EXECUTION_IMAGES", "The preparation source allowlist currently approves zero execution images.")
    if allowlist.get("downloads_enabled") is not False or allowlist.get("runtime_egress_allowed") is not False:
        block("PREPARATION_OR_RUNTIME_NETWORK_POLICY_NOT_CLOSED",
              "Artifact acquisition must stay preparation-only and runtime egress must remain disabled.")
    if not locked_image_ids_valid or not locked_image_ids:
        block("LOCKED_LINUX_IMAGE_IDS_MISSING_OR_INVALID", "The full environment lock has no valid immutable image IDs.")
    for role, key in (("model", "candidate_model_image_id"), ("defense", "candidate_defense_image_id")):
        candidate_id = facts.get(key)
        if not candidate_id or candidate_id not in approved_image_ids:
            block("N05_CANDIDATE_IMAGE_NOT_ALLOWLISTED",
                  f"The source allowlist does not contain the verified MEM041 {role} image digest.")
        if not candidate_id or candidate_id not in locked_image_ids:
            block("N05_CANDIDATE_IMAGE_NOT_IN_FULL_LOCK",
                  f"The full environment lock does not bind the verified MEM041 {role} image digest.")
    if not isinstance(linux_runtime.get("effective_profile_id"), str) or not linux_runtime.get("effective_profile_id", "").strip():
        block("N08_EFFECTIVE_PROFILE_UNSET", "The N05 profile is not an N08 full-demo profile.")
    block("N08_PROFILE_DEFINITION_NOT_SOURCE_VERIFIED",
          "No source-bound N08 profile definition or approval record is included in this review.")
    if not facts["local_n05_admission_matches_mem041"]:
        block("LOCAL_N05_ADMISSION_UNAVAILABLE_OR_MISMATCHED",
              "The local N05 admission must match the published MEM041 receipt before its fields can be used as candidates.")
    if not facts["model_artifact_matches_mem041"]:
        block("LOCAL_MODEL_ARTIFACT_UNAVAILABLE_OR_MISMATCHED",
              "Current model bytes do not match the model digest in the published MEM041 admission summary.")
    if not facts["license_file_matches_mem041"]:
        block("LOCAL_MODEL_LICENSE_UNAVAILABLE_OR_MISMATCHED",
              "Current model license bytes do not match the published MEM041 admission summary.")
    expected_model_sha = facts.get("published_mem041_model_sha256")
    if not HEX_SHA256.fullmatch(expected_model_sha or "") or model.get("artifact_sha256") != expected_model_sha:
        block("LOCKED_MODEL_ARTIFACT_HASH_MISSING_OR_MISMATCHED",
              "The full lock must equal the verified MEM041 model digest; arbitrary nonempty hashes are not accepted.")
    tokenizer_binding = facts.get("candidate_tokenizer_binding")
    if (tokenizer_binding != "EMBEDDED_IN_EXACT_GGUF" or
            model.get("tokenizer_binding") != tokenizer_binding or
            model.get("tokenizer_sha256") is not None or model.get("artifact_sha256") != expected_model_sha):
        block("TOKENIZER_LOCK_BINDING_UNRESOLVED",
              "A tokenizer digest is unavailable; the lock must explicitly bind the embedded tokenizer to the exact admitted GGUF.")
    expected_backend_revision = facts.get("candidate_llama_source_revision")
    if (not isinstance(expected_backend_revision, str) or
            not re.fullmatch(r"[0-9a-f]{40}", expected_backend_revision) or
            model.get("backend_revision") != expected_backend_revision):
        block("MODEL_BACKEND_REVISION_UNSET_OR_MISMATCHED",
              "The locked model backend revision must exactly match the verified MEM041 N05 candidate revision.")
    expected_license_sha = facts.get("published_mem041_license_sha256")
    if (not HEX_SHA256.fullmatch(expected_license_sha or "") or
            model.get("license_lock") != expected_license_sha):
        block("MODEL_LICENSE_LOCK_UNSET_OR_MISMATCHED",
              "The locked license digest must exactly match the verified MEM041 model license bytes.")
    cap = model.get("model_specific_input_token_cap")
    expected_cap = facts.get("candidate_input_token_cap")
    if type(cap) is not int or type(expected_cap) is not int or cap != expected_cap:
        block("MODEL_SPECIFIC_TOKEN_CAP_UNSET_OR_MISMATCHED",
              "The model-specific token cap must equal the verified N05 candidate; a merely positive cap is insufficient.")
    required_authority_keys = ("demo_ca_key_id", "recorder_public_key_id", "witness_public_key_id")
    if any(not isinstance(authorities.get(key), str) or not authorities[key].strip()
           for key in required_authority_keys):
        block("TRUSTED_DEMO_AUTHORITIES_UNPROVISIONED",
              "N08 needs separately identified demo CA, recorder and witness authorities before export verification can be trusted.")
    if resource_policy.get("policy_frozen") is not True:
        block("N08_RESOURCE_POLICY_NOT_FROZEN", "The source lock does not freeze the N08 host/lane/shaping resource policy.")
    if model.get("three_lane_peak_memory_measured") is not True:
        block("N08_THREE_LANE_PEAK_MEMORY_UNMEASURED",
              "N05's 2 GiB per-cell limit and overlap/reset observations do not measure N08 peak memory.")
    lane_memory = resource_policy.get("model_lane_memory_limit_bytes")
    host_reserve = resource_policy.get("host_memory_reserve_bytes")
    shaping_floor = resource_policy.get("shaping_floor_us")
    lane_cpus = resource_policy.get("model_lane_cpu_sets")
    candidate_cpus = facts.get("candidate_model_cpusets")
    if (type(host_reserve) is not int or host_reserve <= 0 or
            type(lane_memory) is not int or lane_memory <= 0 or
            lane_memory != facts.get("candidate_model_lane_memory_limit_bytes") or
            type(shaping_floor) is not int or shaping_floor <= 0 or
            not isinstance(lane_cpus, list) or len(lane_cpus) != 3 or
            not all(isinstance(item, str) and item.strip() for item in lane_cpus) or
            lane_cpus != candidate_cpus):
        block("N08_RESOURCE_POLICY_FIELDS_INCOMPLETE",
              "Positive integer host reserve, lane memory, shaping floor and the verified three-lane CPU candidate must be locked.")
    # This review compares source and configuration only; it cannot validate a runtime peak-memory receipt.
    block("N08_RESOURCE_MEASUREMENT_NOT_VERIFIED_BY_SOURCE_REVIEW",
          "A fresh N08 peak-memory/capacity measurement requires runtime evidence and cannot be cleared by this source-only report.")
    if not fixture_images_valid:
        block("SYNTHETIC_FIXTURE_CATALOG_MALFORMED", "The preflight fixture image catalog must be a list.")
    if not _list(fixture_images):
        block("NO_APPROVED_SYNTHETIC_PREFLIGHT_IMAGES", "The synthetic preflight policy currently approves zero fixture images.")
    # IDs in a lock are declarations, not proof that the corresponding authority keys are trusted.
    block("TRUSTED_DEMO_AUTHORITY_MATERIAL_NOT_SOURCE_VERIFIABLE",
          "No source-bound trust-root/public-key manifest is available to authenticate the locked CA, recorder and witness identities.")
    block("N08_IMAGE_BUILD_PROVENANCE_NOT_SOURCE_VERIFIED",
          "The source-only inputs do not bind an approved model-cell build receipt to the exact execution image digests.")
    if not (backend_root / "infra/cells/Dockerfile.model").is_file():
        block("N08_MODEL_CELL_BUILD_DEFINITION_MISSING",
              "backend/infra/cells/Dockerfile.model is absent; the N05 prebuilt image is only a candidate, not a reproducible N08 build.")
    if not any((backend_root / "tools").glob("run_n08*.py")):
        block("N08_DEMO_RUNNER_MISSING", "No N08-specific setup/demo runner is present in backend/tools.")
    if n05_receipt.get("n08_acceptance") is not False or n05_receipt.get("guarantee_tier_achieved") is not None:
        block("PUBLISHED_N05_SCOPE_CHANGED", "The published MEM041 receipt must remain bounded and must not claim N08 or a guarantee tier.")
    if missing_sources:
        block("REVIEW_SOURCE_FILES_MISSING", "Some required source/evidence files were not present in the reviewed checkout.")

    image_allowlist_count = len(_list(approved_execution_images))
    fixture_allowlist_count = len(_list(fixture_images))
    n05_run = _mapping(n05_receipt.get("n05_run"))
    current_runtime_lock_drift = {
        "observation_revision": "MEM-042",
        "observation_end_utc": prior_runtime.get("observation_end_utc"),
        "docker_client": {"locked": tooling.get("docker_client_version"),
                           "observed": prior_runtime.get("docker_client_version")},
        "docker_server": {"locked": linux_runtime.get("server_version"),
                           "observed": prior_runtime.get("docker_server_version")},
        "compose": {"locked": tooling.get("compose_client_version"),
                    "observed": prior_runtime.get("docker_compose_version")},
        "scope_note": "MEM-042 is a point-in-time observation, not a current runtime recheck.",
    }
    stale_capacity_wording = {
        "legacy_blocker_present": "Model lane capacity/reset/overlap unmeasured" in _list(lock.get("blocked_prerequisites")),
        "bounded_n05_overlap_ns": n05_run.get("observed_processing_overlap_ns"),
        "bounded_n05_container_replacement_before_reuse": n05_run.get("containers_changed_before_reuse"),
        "still_unmeasured": ["N08 three-lane peak memory", "host CPU exclusivity", "fresh capacity at workload admission"],
        "scope_note": "MEM041 supersedes the broad no-overlap/reset wording only for its bounded N05 sample; it does not complete N08 resource acceptance.",
    }

    after_hashes, missing_after = _source_hashes(repository_root)
    source_unchanged = before_hashes == after_hashes and not missing_sources and not missing_after
    if not source_unchanged:
        block("SOURCE_CHANGED_DURING_REVIEW", "Required source/evidence hashes changed during the review window.")
    facts_after = _read_candidate_artifacts(backend_root, source_config, published_admission)
    artifact_hash_keys = ("local_n05_admission_sha256", "model_artifact_sha256", "license_file_sha256")
    local_artifacts_unchanged = all(facts.get(key) == facts_after.get(key) for key in artifact_hash_keys)
    if not local_artifacts_unchanged:
        block("LOCAL_CANDIDATE_ARTIFACTS_CHANGED_DURING_REVIEW",
              "The local admission, model or license bytes changed while their candidate hashes were being checked.")

    output_path = (backend_root / "tools/review_n08_gates.py").resolve()
    report = {
        "schema_version": "arena-n08-exact-build-admission-gate-review.v1",
        "revision": "MEM-043",
        "status": "INCOMPLETE_NOT_READY",
        "scope": "SOURCE_ONLY_N08_BUILD_AND_ADMISSION_GATE_REVIEW",
        "reviewed_source_commit": reviewed_source_commit,
        "source_commit_provenance": "CALLER_ASSERTED; this tool records working-tree hashes and does not query Git or verify the commit-to-tree mapping.",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_sha256": after_hashes,
        "source_count": len(after_hashes),
        "source_unchanged_during_review": source_unchanged,
        "local_candidate_artifacts_unchanged_during_review": local_artifacts_unchanged,
        "reviewer_sha256": after_hashes.get("backend/tools/review_n08_gates.py"),
        "full_environment_lock": {
            "status": lock.get("status"),
            "lock_complete": lock.get("lock_complete"),
            "unresolved_null_fields": sorted(
                f"{section}.{key}" for section, values in lock.items() if isinstance(values, dict)
                for key, value in values.items() if value is None
            ),
            "approved_execution_image_count": image_allowlist_count,
            "approved_synthetic_preflight_image_count": fixture_allowlist_count,
            "source_allowlist_status": allowlist.get("status"),
            "approved_execution_image_ids": sorted(approved_image_ids),
            "locked_linux_image_ids": sorted(locked_image_ids),
            "downloads_enabled": allowlist.get("downloads_enabled"),
            "runtime_egress_allowed": allowlist.get("runtime_egress_allowed"),
        },
        "mem041_n05_candidate_facts": facts,
        "mem042_historical_runtime_lock_drift": current_runtime_lock_drift,
        "capacity_reset_scope_reconciliation": stale_capacity_wording,
        "blocking_gates": blockers,
        "non_blocking_scope_notes": [
            "The zero-image synthetic preflight catalog is a separate N01 fixture gap; it is not permission to run a fixture.",
            "The guarantee tier remains null by design until the complete applicable evidence and review exist.",
            "N05's observed three-lane overlap, reset/container replacement, and 2 GiB per-cell limit remain bounded N05 evidence only.",
            "Docker and current host/VM capacity were not queried; local N05 model/license bytes were hashed only to compare candidate digests.",
        ],
        "n08_fresh_demo_performed": False,
        "model_workload_started": False,
        "docker_queries_performed": False,
        "docker_mutations_performed": False,
        "network_access_performed": False,
        "frontend_changed": False,
        "historical_evidence_rewritten": False,
        "n07_acceptance": False,
        "n08_acceptance": False,
        "t016_acceptance": False,
        "all_t_p_acceptance": False,
        "arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }
    # A source-only report is never an execution authorization, even if its inputs later change.
    report["workload_authorized"] = False
    report["ready_for_n08_workload"] = False
    return report


def output_path(path: Path, backend_root: Path = BACKEND, repository_root: Path = REPOSITORY) -> Path:
    resolved = path.resolve()
    allowed = (
        (backend_root / "artifacts/n08-gate-review").resolve(),
        (repository_root / "memory files/hackathon/evidence").resolve(),
    )
    if resolved.suffix != ".json" or not any(resolved.is_relative_to(directory) for directory in allowed):
        raise ValueError("OUTPUT_MUST_BE_NEW_JSON_UNDER_N08_REVIEW_OR_PROJECT_EVIDENCE")
    if resolved.exists():
        raise FileExistsError("OUTPUT_ALREADY_EXISTS")
    return resolved


def write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="New sanitized JSON under project evidence or backend/artifacts/n08-gate-review")
    parser.add_argument("--reviewed-source-commit", required=True,
                        help="Commit identified by the caller before the source-only review")
    args = parser.parse_args()
    try:
        if not GIT_COMMIT.fullmatch(args.reviewed_source_commit):
            raise ValueError("REVIEWED_SOURCE_COMMIT_REQUIRED")
        target = output_path(args.output)
        report = review(reviewed_source_commit=args.reviewed_source_commit)
        write_new(target, report)
        relative = target.relative_to(REPOSITORY).as_posix()
        print(json.dumps({"result": report["status"], "blocking_gate_count": len(report["blocking_gates"]),
                          "source_only": True, "workload_authorized": False,
                          "model_workload_started": False, "output": relative}))
        return 2 if report["blocking_gates"] else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("N08 gate review failed: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
