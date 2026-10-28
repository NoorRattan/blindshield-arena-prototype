"""Independently reconcile the private no-model public-JBB verdict preflight."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
ARTIFACTS = BACKEND / "artifacts"
SCHEMA = "arena-n07b-public-jbb-verdict-preflight.v1"
SCOPE = "N07B_PUBLIC_JBB_VERDICT_PREFLIGHT"
EXPECTED_RECORDS = 100
EXPECTED_SPLITS = {"benign": 50, "harmful": 50}
ALLOWED_VERDICTS = {"ALLOW", "BLOCK", "SANITIZE"}
ALLOWED_REASONS = {"NONE", "INJECTION_PATTERN", "TOXICITY_PATTERN", "SCHEMA_POLICY", "UNSUPPORTED", "BUDGET_POLICY"}
EVENT_ACTIONS = {"create", "attach", "start", "die", "destroy"}
COMPLETED_OBSERVATION_FIELDS = {
    "schema_version", "scope", "result", "source_revision", "source_sha256",
    "source_manifest_sha256", "source_file_count", "source_sha256_after",
    "source_unchanged_during_run", "runtime_source_manifest_sha256", "mode",
    "real_public_jbb_inputs_used", "synthetic_inputs_used", "mock_defense_used",
    "real_model_inference_performed", "model_dispatch_count", "model_runtime_start_count",
    "n04_controller_pipeline_exercised", "defense_runtime_entrypoint",
    "defense_runtime_source_sha256", "defense_call_count", "records", "docker_event_trace",
    "container_inventory_before", "container_inventory_after", "container_inventory_unchanged",
    "record_count_expected", "split_counts_expected", "admission_lock_sha256",
    "cell_admission_sha256", "corpus_receipt_sha256", "defense_image_digest",
    "defense_source_sha256", "outcome_aggregate", "p011_complete", "p013_complete",
    "t019_complete", "full_n07_acceptance", "full_arena_acceptance", "guarantee_tier_achieved",
}
RAW_OR_SECRET_FIELDS = {
    "prompt", "text", "record_id", "payload_ref", "call_token", "model_output",
    "private_key", "corpus_key", "corpus_keys", "api_key", "traceback",
}

sys.path.insert(0, str(BACKEND))

from arena.contracts.crypto import sha256  # noqa: E402
from arena.contracts.jsonwire import load_wire  # noqa: E402
from arena.integration.corpus import PreparedPublicCorpus  # noqa: E402
from arena.integration.lanes import LaneAdmission, PinnedCell  # noqa: E402
from arena.integration.runtime import DockerRuntime, runtime_source_hashes  # noqa: E402
from arena.integration.types import AdmissionLock  # noqa: E402
from tools.verify_n04 import sources as backend_sources  # noqa: E402


def digest_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def source_manifest_digest(sources: dict[str, str]) -> str:
    raw = json.dumps(sources, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(raw)


def inside_artifacts(path: Path) -> bool:
    try:
        path.resolve().relative_to(ARTIFACTS.resolve())
        return True
    except ValueError:
        return False


def reject_raw_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in RAW_OR_SECRET_FIELDS:
                raise ValueError("PRIVATE_OBSERVATION_CONTAINS_RAW_OR_SECRET_FIELD")
            reject_raw_fields(item)
    elif isinstance(value, list):
        for item in value:
            reject_raw_fields(item)


def require_exact_fields(value: Any, expected: set[str], failure_code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(failure_code)
    return value


def valid_result_tuple(row: dict[str, Any]) -> bool:
    verdict = row.get("verdict")
    reason = row.get("reason_code")
    transform = row.get("transform_id")
    if verdict == "ALLOW":
        return reason == "NONE" and transform is None
    if verdict == "BLOCK":
        return reason in ALLOWED_REASONS - {"NONE"} and transform is None
    if verdict == "SANITIZE":
        return (
            reason in {"INJECTION_PATTERN", "TOXICITY_PATTERN", "SCHEMA_POLICY"}
            and transform == "REDACT_REGISTERED_MATCHES_V1"
        )
    return False


def aggregate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {name: 0 for name in ("ALLOW", "BLOCK", "SANITIZE")}
    by_split = {split: {name: 0 for name in counts} for split in EXPECTED_SPLITS}
    for row in rows:
        split = row.get("split")
        verdict = row.get("verdict")
        if split not in by_split or verdict not in counts or not valid_result_tuple(row):
            raise ValueError("PRIVATE_RESULT_SYMBOL_INVALID")
        counts[verdict] += 1
        by_split[split][verdict] += 1
    return {
        "record_count": len(rows),
        "verdict_distribution": counts,
        "verdict_distribution_by_split": by_split,
        "varied_verdicts_observed": sum(value > 0 for value in counts.values()) > 1,
    }


def verify(
    *, observation_path: Path, lock_path: Path, model_path: Path,
    corpus_path: Path, corpus_receipt_path: Path, corpus_keys_path: Path,
) -> dict[str, Any]:
    observation_path = observation_path.resolve()
    lock_path, model_path, corpus_path, corpus_receipt_path, corpus_keys_path = (
        path.resolve() for path in (lock_path, model_path, corpus_path, corpus_receipt_path, corpus_keys_path)
    )
    if not inside_artifacts(observation_path):
        raise ValueError("OBSERVATION_OUTSIDE_PRIVATE_ARTIFACTS")
    if not all(path.is_file() for path in (lock_path, model_path, corpus_receipt_path, corpus_keys_path)):
        raise FileNotFoundError("VERIFIER_INPUT_FILE_MISSING")
    if not corpus_path.is_dir():
        raise FileNotFoundError("VERIFIER_CORPUS_DIRECTORY_MISSING")
    if not model_path.is_relative_to(ARTIFACTS.resolve()):
        raise ValueError("PREPARED_MODEL_PATH_OUTSIDE_IGNORED_ARTIFACTS")

    observation = json.loads(observation_path.read_bytes())
    require_exact_fields(observation, COMPLETED_OBSERVATION_FIELDS, "PRIVATE_OBSERVATION_FIELD_SET_INVALID")
    reject_raw_fields(observation)
    if (
        observation.get("schema_version") != SCHEMA
        or observation.get("scope") != SCOPE
        or observation.get("result") != "PUBLIC_JBB_VERDICT_PREFLIGHT_COMPLETE"
        or observation.get("mode") != "INPUT"
        or observation.get("real_public_jbb_inputs_used") is not True
        or observation.get("synthetic_inputs_used") is not False
        or observation.get("mock_defense_used") is not False
        or observation.get("real_model_inference_performed") is not False
        or observation.get("model_dispatch_count") != 0
        or observation.get("model_runtime_start_count") != 0
        or observation.get("n04_controller_pipeline_exercised") is not False
        or observation.get("defense_runtime_entrypoint")
        != "arena.integration.lanes.PinnedCell.evaluate->arena.integration.runtime.DockerRuntime.evaluate"
        or observation.get("p011_complete") is not False
        or observation.get("p013_complete") is not False
        or observation.get("t019_complete") is not False
        or observation.get("full_n07_acceptance") is not False
        or observation.get("full_arena_acceptance") is not False
        or observation.get("guarantee_tier_achieved") is not None
    ):
        raise ValueError("OBSERVATION_SCOPE_OR_STATUS_INVALID")

    revision = observation.get("source_revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("SOURCE_REVISION_INVALID")
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )

    sources = backend_sources()
    if (
        observation.get("source_sha256") != sources
        or observation.get("source_sha256_after") != sources
        or observation.get("source_manifest_sha256") != source_manifest_digest(sources)
        or observation.get("source_file_count") != len(sources)
        or observation.get("source_unchanged_during_run") is not True
    ):
        raise ValueError("MEASUREMENT_SOURCE_MANIFEST_MISMATCH")

    lock_raw = lock_path.read_bytes()
    admission = load_wire(LaneAdmission, lock_raw)
    cell_path = lock_path.parent / "cell-admission.json"
    if not cell_path.is_file() or digest_file(cell_path) != admission.cell_admission_sha256:
        raise ValueError("N05_CELL_ADMISSION_MISMATCH")
    base = load_wire(AdmissionLock, cell_path.read_bytes()).model_dump()
    if any(
        admission.model_dump().get(name) != value
        for name, value in base.items()
        if name not in {"schema_version", "claim_scope"}
    ):
        raise ValueError("N05_BASE_PROFILE_FIELDS_MISMATCH")
    if (
        model_path.name != admission.model_filename
        or digest_file(lock_path) != observation.get("admission_lock_sha256")
        or digest_file(cell_path) != observation.get("cell_admission_sha256")
        or digest_file(corpus_receipt_path) != admission.corpus_receipt_sha256
        or digest_file(corpus_receipt_path) != observation.get("corpus_receipt_sha256")
        or runtime_source_hashes() != admission.runtime_source_sha256
        or source_manifest_digest(admission.runtime_source_sha256)
        != observation.get("runtime_source_manifest_sha256")
        or digest_file(BACKEND / "infra/cells/defense.py") != admission.defense_source_sha256
        or observation.get("defense_source_sha256") != admission.defense_source_sha256
        or observation.get("defense_image_digest") != admission.defense_image
        or observation.get("defense_runtime_source_sha256")
        != sha256((inspect.getsource(PinnedCell.defense_resource_args) + inspect.getsource(DockerRuntime.evaluate)).encode("utf-8"))
    ):
        raise ValueError("ADMITTED_DEFENSE_PROFILE_OR_SOURCE_MISMATCH")

    corpus = PreparedPublicCorpus(
        corpus_path, corpus_receipt_path, corpus_keys_path, admission.corpus_receipt_sha256
    )
    if len(corpus.records) != EXPECTED_RECORDS or dict(
        __import__("collections").Counter(corpus.split.values())
    ) != EXPECTED_SPLITS:
        raise ValueError("ADMITTED_JBB_COHORT_MISMATCH")
    expected: dict[tuple[str, str], str] = {}
    for payload_ref, payload in corpus.records.items():
        if payload.provenance.source_id != "JBB-Behaviors" or payload.provenance.run_label != "REAL_PUBLIC":
            raise ValueError("NON_JBB_OR_NONPUBLIC_RECORD_IN_CORPUS")
        key = (
            sha256(payload.provenance.record_id.encode("utf-8")),
            sha256(payload_ref.encode("utf-8")),
        )
        if key in expected:
            raise ValueError("DUPLICATE_ADMITTED_RECORD_IDENTITY")
        expected[key] = corpus.split[payload_ref]

    rows = observation.get("records")
    if not isinstance(rows, list) or len(rows) != EXPECTED_RECORDS:
        raise ValueError("PRIVATE_RECORD_ROW_COUNT_INVALID")
    actual: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "record_id_sha256", "payload_ref_sha256", "defense_container_id_sha256",
            "defense_container_name_sha256", "split", "verdict", "reason_code", "transform_id"
        }:
            raise ValueError("PRIVATE_RECORD_ROW_SHAPE_INVALID")
        if any(
            not isinstance(row.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", row[field]) is None
            for field in (
                "record_id_sha256", "payload_ref_sha256", "defense_container_id_sha256",
                "defense_container_name_sha256",
            )
        ):
            raise ValueError("PRIVATE_RECORD_HASH_INVALID")
        key = (row["record_id_sha256"], row["payload_ref_sha256"])
        if key in actual or key not in expected or row.get("split") != expected[key]:
            raise ValueError("PRIVATE_RECORD_IDENTITY_OR_LINEAGE_MISMATCH")
        if not valid_result_tuple(row):
            raise ValueError("PRIVATE_DEFENSE_RESULT_TUPLE_INVALID")
        actual[key] = row
    if set(actual) != set(expected):
        raise ValueError("PRIVATE_RECORD_COVERAGE_MISMATCH")

    trace = observation.get("docker_event_trace")
    if not isinstance(trace, dict) or set(trace) != {
        "schema_version", "result", "listener_started", "listener_stopped",
        "observed_container_count", "external_lifecycle_event_count", "unclassified_event_count",
        "unexpected_container_action_count", "capture_failure_code", "action_counts", "containers", "trace_sha256",
    }:
        raise ValueError("DOCKER_EVENT_TRACE_SHAPE_INVALID")
    if trace.get("schema_version") != "arena-docker-defense-event-trace.v1":
        raise ValueError("DOCKER_EVENT_TRACE_SCHEMA_INVALID")
    event_containers = trace.get("containers")
    if not isinstance(event_containers, list) or len(event_containers) != EXPECTED_RECORDS:
        raise ValueError("DOCKER_EVENT_CONTAINER_COUNT_INVALID")
    event_ids: set[str] = set()
    event_names: set[str] = set()
    expected_image_sha256 = sha256(admission.defense_image.encode("utf-8"))
    for item in event_containers:
        if not isinstance(item, dict) or set(item) != {
            "container_id_sha256", "container_name_sha256", "image_sha256", "action_counts", "die_exit_code"
        }:
            raise ValueError("DOCKER_EVENT_CONTAINER_ROW_SHAPE_INVALID")
        for field in ("container_id_sha256", "container_name_sha256", "image_sha256"):
            if not isinstance(item.get(field), str) or re.fullmatch(r"[0-9a-f]{64}", item[field]) is None:
                raise ValueError("DOCKER_EVENT_CONTAINER_HASH_INVALID")
        actions = item.get("action_counts")
        if not isinstance(actions, dict) or set(actions) != EVENT_ACTIONS:
            raise ValueError("DOCKER_EVENT_ACTION_SHAPE_INVALID")
        if (
            actions.get("create") != 1
            or actions.get("start") != 1
            or actions.get("die") != 1
            or actions.get("destroy") != 1
            or actions.get("attach") not in {0, 1}
            or item.get("die_exit_code") != "0"
            or item.get("image_sha256") != expected_image_sha256
        ):
            raise ValueError("DOCKER_EVENT_CONTAINER_LIFECYCLE_INVALID")
        if item["container_id_sha256"] in event_ids or item["container_name_sha256"] in event_names:
            raise ValueError("DOCKER_EVENT_CONTAINER_IDENTITY_DUPLICATE")
        event_ids.add(item["container_id_sha256"])
        event_names.add(item["container_name_sha256"])
    row_event_ids = {row["defense_container_id_sha256"] for row in rows}
    row_event_names = {row["defense_container_name_sha256"] for row in rows}
    if (
        event_ids != row_event_ids
        or event_names != row_event_names
        or [(row["defense_container_id_sha256"], row["defense_container_name_sha256"]) for row in rows]
        != [(item["container_id_sha256"], item["container_name_sha256"]) for item in event_containers]
    ):
        raise ValueError("DOCKER_EVENT_TO_RECORD_BINDING_MISMATCH")
    action_counts = trace.get("action_counts")
    if not isinstance(action_counts, dict) or set(action_counts) != EVENT_ACTIONS:
        raise ValueError("DOCKER_EVENT_AGGREGATE_ACTION_SHAPE_INVALID")
    recomputed_action_counts = {
        action: sum(item["action_counts"][action] for item in event_containers)
        for action in EVENT_ACTIONS
    }
    if action_counts != recomputed_action_counts:
        raise ValueError("DOCKER_EVENT_AGGREGATE_ACTION_MISMATCH")
    if (
        trace.get("result") != "PASS"
        or trace.get("listener_started") is not True
        or trace.get("listener_stopped") is not True
        or trace.get("observed_container_count") != EXPECTED_RECORDS
        or trace.get("external_lifecycle_event_count") != 0
        or trace.get("unclassified_event_count") != 0
        or trace.get("unexpected_container_action_count") != 0
        or trace.get("capture_failure_code") is not None
        or action_counts.get("create") != EXPECTED_RECORDS
        or action_counts.get("start") != EXPECTED_RECORDS
        or action_counts.get("die") != EXPECTED_RECORDS
        or action_counts.get("destroy") != EXPECTED_RECORDS
        or action_counts.get("attach", 0) not in range(EXPECTED_RECORDS + 1)
    ):
        raise ValueError("DOCKER_EVENT_TRACE_NOT_COMPLETE")
    trace_body = {
        "actions": action_counts,
        "containers": event_containers,
        "external_lifecycle_event_count": trace["external_lifecycle_event_count"],
        "unclassified_event_count": trace["unclassified_event_count"],
        "unexpected_container_action_count": trace["unexpected_container_action_count"],
        "capture_failure_code": trace["capture_failure_code"],
    }
    trace_digest = sha256(json.dumps(trace_body, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if trace.get("trace_sha256") != trace_digest:
        raise ValueError("DOCKER_EVENT_TRACE_DIGEST_MISMATCH")

    aggregate = aggregate_rows(rows)
    if (
        observation.get("defense_call_count") != EXPECTED_RECORDS
        or observation.get("record_count_expected") != EXPECTED_RECORDS
        or observation.get("split_counts_expected") != EXPECTED_SPLITS
        or observation.get("outcome_aggregate") != aggregate
    ):
        raise ValueError("PRIVATE_AGGREGATE_MISMATCH")
    before = observation.get("container_inventory_before")
    after = observation.get("container_inventory_after")
    inventory_fields = {
        "container_count", "inventory_sha256", "running_container_count", "running_inventory_sha256"
    }
    require_exact_fields(before, inventory_fields, "CONTAINER_INVENTORY_SHAPE_INVALID")
    require_exact_fields(after, inventory_fields, "CONTAINER_INVENTORY_SHAPE_INVALID")
    if (
        not isinstance(before, dict)
        or not isinstance(after, dict)
        or before != after
        or before.get("running_container_count") != 0
        or after.get("running_container_count") != 0
        or observation.get("container_inventory_unchanged") is not True
    ):
        raise ValueError("CONTAINER_INVENTORY_CHANGED_OR_ACTIVE")

    return {
        "result": "PASS_SOURCE_AND_PUBLIC_JBB_VERDICT_RECONCILIATION",
        "observation_sha256": digest_file(observation_path),
        "source_revision": revision,
        "source_file_count": len(sources),
        "source_manifest_sha256": source_manifest_digest(sources),
        "admission_lock_sha256": digest_file(lock_path),
        "cell_admission_sha256": digest_file(cell_path),
        "corpus_receipt_sha256": admission.corpus_receipt_sha256,
        "defense_image_digest": admission.defense_image,
        "record_count": aggregate["record_count"],
        "split_counts": EXPECTED_SPLITS,
        "verdict_distribution": aggregate["verdict_distribution"],
        "verdict_distribution_by_split": aggregate["verdict_distribution_by_split"],
        "varied_verdicts_observed": aggregate["varied_verdicts_observed"],
        "defense_call_count": EXPECTED_RECORDS,
        "docker_event_container_count": len(event_containers),
        "docker_event_trace_sha256": trace_digest,
        "model_dispatch_count": 0,
        "real_model_inference_performed": False,
        "container_inventory_unchanged": True,
        "p011_complete": False,
        "p013_complete": False,
        "t019_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("observation", "lock", "model", "corpus", "corpus-receipt", "corpus-keys"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(
            observation_path=args.observation,
            lock_path=args.lock,
            model_path=args.model,
            corpus_path=args.corpus,
            corpus_receipt_path=args.corpus_receipt,
            corpus_keys_path=args.corpus_keys,
        )
    except Exception as exc:
        code = str(exc)
        if not code.isascii() or not code.isupper():
            code = None
        print(json.dumps({"result": "FAIL_RECONCILIATION", "failure_type": type(exc).__name__, "failure_code": code}, sort_keys=True), flush=True)
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
