"""Run a no-model public-JBB INPUT verdict preflight through the pinned cell.

This measures only the frozen local defense verdicts for the admitted corpus.
It does not start a model, call the N04 controller, or claim safety accuracy.
Private output contains hashed record identities and finite verdict symbols only.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Callable
from uuid import uuid4


BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
ARTIFACTS = BACKEND / "artifacts"
SCHEMA = "arena-n07b-public-jbb-verdict-preflight.v1"
SCOPE = "N07B_PUBLIC_JBB_VERDICT_PREFLIGHT"
EXPECTED_RECORDS = 100
EXPECTED_SPLITS = {"benign": 50, "harmful": 50}
MAX_RECORDS = 100
DEFENSE_CONTAINER_PREFIX = "arena-n04-defense-"
EVENT_ACTIONS = ("create", "attach", "start", "die", "destroy")
RELEVANT_EXTERNAL_ACTIONS = {"create", "start", "die", "destroy", "kill", "stop", "restart"}

sys.path.insert(0, str(BACKEND))

from arena.contracts.api import DefenseDecision, InputDefenseRequest, PromptContent  # noqa: E402
from arena.contracts.crypto import sha256  # noqa: E402
from arena.contracts.jsonwire import load_wire  # noqa: E402
from arena.integration.corpus import PreparedPublicCorpus  # noqa: E402
from arena.integration.lanes import LaneAdmission, PinnedCell  # noqa: E402
from arena.integration.runtime import DockerRuntime, docker, ensure_local_docker, runtime_source_hashes  # noqa: E402
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


def defense_runtime_source_digest() -> str:
    source = inspect.getsource(PinnedCell.defense_resource_args) + inspect.getsource(DockerRuntime.evaluate)
    return sha256(source.encode("utf-8"))


def current_revision() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    revision = result.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise RuntimeError("SOURCE_REVISION_INVALID")
    return revision


def inventory() -> dict[str, Any]:
    all_rows = docker("ps", "--all", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}").decode().splitlines()
    running_rows = docker("ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}").decode().splitlines()

    def fingerprints(rows: list[str]) -> list[str]:
        values = []
        for row in rows:
            container_id, separator, name = row.partition("\t")
            if not separator or not container_id or not name:
                raise RuntimeError("DOCKER_CONTAINER_INVENTORY_INVALID")
            values.append(sha256((container_id + "\x00" + name).encode("utf-8")))
        return sorted(values)

    all_fingerprints = fingerprints(all_rows)
    running_fingerprints = fingerprints(running_rows)
    return {
        "container_count": len(all_rows),
        "inventory_sha256": sha256("\n".join(all_fingerprints).encode("ascii")),
        "running_container_count": len(running_rows),
        "running_inventory_sha256": sha256("\n".join(running_fingerprints).encode("ascii")),
    }


class DockerEventRecorder:
    """Capture daemon-reported lifecycle evidence for each transient defense cell."""

    def __init__(self, expected_image: str, expected_count: int):
        self.expected_image = expected_image
        self.expected_image_sha256 = sha256(expected_image.encode("utf-8"))
        self.expected_count = expected_count
        self.process: asyncio.subprocess.Process | None = None
        self.reader_task: asyncio.Task | None = None
        self.condition = asyncio.Condition()
        self.containers: dict[str, dict[str, Any]] = {}
        self.action_counts: Counter[str] = Counter()
        self.external_lifecycle_event_count = 0
        self.unclassified_event_count = 0
        self.unexpected_container_action_count = 0
        self.capture_failure_code: str | None = None
        self.listener_started = False
        self.listener_stopped = False
        self._sequence = 0

    async def start(self) -> None:
        self.process = await asyncio.create_subprocess_exec(
            "docker", "events", "--filter", "type=container", "--format", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        if self.process.stdout is None:
            raise RuntimeError("DOCKER_EVENT_STREAM_PIPE_UNAVAILABLE")
        self.reader_task = asyncio.create_task(self._capture())
        # Let the Docker CLI connect before the first evaluation. Events are also
        # reconciled against the completed lifecycle set and the final inventory.
        await asyncio.sleep(0.5)
        if self.process.returncode is not None:
            raise RuntimeError("DOCKER_EVENT_STREAM_UNAVAILABLE")
        self.listener_started = True

    async def _capture(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        try:
            while line := await self.process.stdout.readline():
                if len(line) > 65536:
                    self.capture_failure_code = "DOCKER_EVENT_RECORD_TOO_LARGE"
                    continue
                try:
                    event = json.loads(line)
                    self._accept_event(event)
                    async with self.condition:
                        self.condition.notify_all()
                except Exception:
                    self.capture_failure_code = "DOCKER_EVENT_RECORD_INVALID"
        except Exception:
            self.capture_failure_code = "DOCKER_EVENT_STREAM_READ_FAILED"

    def _accept_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("Type", event.get("type"))
        if event_type != "container":
            return
        action = event.get("Action", event.get("status", event.get("action")))
        actor = event.get("Actor") or {}
        attributes = actor.get("Attributes") or {}
        name = attributes.get("name")
        container_id = actor.get("ID") or event.get("id") or event.get("ID")
        if not isinstance(action, str) or not isinstance(name, str) or not isinstance(container_id, str):
            self.unclassified_event_count += 1
            return
        action = action.lower()
        if name.startswith(DEFENSE_CONTAINER_PREFIX):
            container = self.containers.setdefault(
                container_id,
                {
                    "container_id": container_id,
                    "container_name": name,
                    "image_hashes": set(),
                    "actions": Counter(),
                    "die_exit_codes": [],
                    "sequence": self._sequence,
                },
            )
            self._sequence += 1
            if container["container_name"] != name:
                self.capture_failure_code = "DOCKER_EVENT_CONTAINER_ID_NAME_CHANGED"
            image = attributes.get("image")
            if isinstance(image, str):
                container["image_hashes"].add(sha256(image.encode("utf-8")))
            container["actions"][action] += 1
            if action not in EVENT_ACTIONS:
                self.unexpected_container_action_count += 1
            if action == "die":
                exit_code = attributes.get("exitCode")
                container["die_exit_codes"].append(str(exit_code))
            self.action_counts[action] += 1
            return
        if action in RELEVANT_EXTERNAL_ACTIONS:
            self.external_lifecycle_event_count += 1

    async def wait_for_completed_container(self) -> dict[str, str]:
        if not self.listener_started:
            raise RuntimeError("DOCKER_EVENT_LISTENER_NOT_STARTED")

        def completed_unassigned() -> bool:
            return any(
                not container.get("assigned")
                and container["actions"].get("create", 0) == 1
                and container["actions"].get("start", 0) == 1
                and container["actions"].get("die", 0) == 1
                and container["actions"].get("destroy", 0) == 1
                for container in self.containers.values()
            )

        async with self.condition:
            try:
                await asyncio.wait_for(self.condition.wait_for(completed_unassigned), timeout=15)
            except asyncio.TimeoutError as exc:
                raise RuntimeError("DOCKER_DEFENSE_CONTAINER_EVENT_TIMEOUT") from exc
            container = next(item for item in self.containers.values() if not item.get("assigned") and
                             item["actions"].get("create", 0) == 1 and item["actions"].get("start", 0) == 1 and
                             item["actions"].get("die", 0) == 1 and item["actions"].get("destroy", 0) == 1)
            container["assigned"] = True
            die_codes = container["die_exit_codes"]
            image_hashes = container["image_hashes"]
            if die_codes != ["0"] or image_hashes != {self.expected_image_sha256}:
                raise RuntimeError("DOCKER_DEFENSE_CONTAINER_EVENT_PROFILE_MISMATCH")
            return {
                "defense_container_id_sha256": sha256(container["container_id"].encode("utf-8")),
                "defense_container_name_sha256": sha256(container["container_name"].encode("utf-8")),
            }

    async def stop(self) -> dict[str, Any]:
        if self.process is None:
            return {"result": "NOT_STARTED"}
        if self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.process.kill()
                await asyncio.wait_for(self.process.wait(), timeout=5)
        if self.reader_task is not None:
            try:
                await asyncio.wait_for(self.reader_task, timeout=5)
            except asyncio.TimeoutError:
                self.capture_failure_code = "DOCKER_EVENT_STREAM_DRAIN_TIMEOUT"
        self.listener_stopped = True

        containers = []
        for container in sorted(self.containers.values(), key=lambda item: item["sequence"]):
            actions = {name: container["actions"].get(name, 0) for name in EVENT_ACTIONS}
            image_hashes = sorted(container["image_hashes"])
            die_codes = container["die_exit_codes"]
            containers.append({
                "container_id_sha256": sha256(container["container_id"].encode("utf-8")),
                "container_name_sha256": sha256(container["container_name"].encode("utf-8")),
                "image_sha256": image_hashes[0] if len(image_hashes) == 1 else None,
                "action_counts": actions,
                "die_exit_code": die_codes[0] if len(die_codes) == 1 else None,
            })
        actions = {name: self.action_counts.get(name, 0) for name in EVENT_ACTIONS}
        trace_body = {
            "actions": actions,
            "containers": containers,
            "external_lifecycle_event_count": self.external_lifecycle_event_count,
            "unclassified_event_count": self.unclassified_event_count,
            "unexpected_container_action_count": self.unexpected_container_action_count,
            "capture_failure_code": self.capture_failure_code,
        }
        valid = (
            self.listener_started
            and self.listener_stopped
            and len(containers) == self.expected_count
            and self.external_lifecycle_event_count == 0
            and self.unclassified_event_count == 0
            and self.unexpected_container_action_count == 0
            and self.capture_failure_code is None
            and actions["create"] == self.expected_count
            and actions["start"] == self.expected_count
            and actions["die"] == self.expected_count
            and actions["destroy"] == self.expected_count
            and len({item["container_id_sha256"] for item in containers}) == self.expected_count
            and len({item["container_name_sha256"] for item in containers}) == self.expected_count
            and all(
                item["action_counts"]["create"] == 1
                and item["action_counts"]["start"] == 1
                and item["action_counts"]["die"] == 1
                and item["action_counts"]["destroy"] == 1
                and item["action_counts"]["attach"] <= 1
                and item["image_sha256"] == self.expected_image_sha256
                and item["die_exit_code"] == "0"
                for item in containers
            )
        )
        return {
            "schema_version": "arena-docker-defense-event-trace.v1",
            "result": "PASS" if valid else "INCOMPLETE",
            "listener_started": self.listener_started,
            "listener_stopped": self.listener_stopped,
            "observed_container_count": len(containers),
            "external_lifecycle_event_count": self.external_lifecycle_event_count,
            "unclassified_event_count": self.unclassified_event_count,
            "unexpected_container_action_count": self.unexpected_container_action_count,
            "capture_failure_code": self.capture_failure_code,
            "action_counts": actions,
            "containers": containers,
            "trace_sha256": sha256(json.dumps(trace_body, sort_keys=True, separators=(",", ":")).encode("utf-8")),
        }


def admission_checks(
    *, lock_path: Path, model_path: Path, corpus_path: Path,
    corpus_receipt_path: Path, corpus_keys_path: Path,
) -> tuple[LaneAdmission, Path, PreparedPublicCorpus, dict[str, str]]:
    paths = (lock_path, model_path, corpus_receipt_path, corpus_keys_path)
    if not all(path.is_file() for path in paths) or not corpus_path.is_dir():
        raise FileNotFoundError("PREFLIGHT_INPUT_MISSING")
    if not model_path.resolve().is_relative_to(ARTIFACTS.resolve()):
        raise ValueError("PREPARED_MODEL_PATH_OUTSIDE_IGNORED_ARTIFACTS")

    lock_raw = lock_path.read_bytes()
    admission = load_wire(LaneAdmission, lock_raw)
    cell_lock_path = lock_path.parent / "cell-admission.json"
    if not cell_lock_path.is_file():
        raise FileNotFoundError("N05_CELL_ADMISSION_MISSING")
    cell_raw = cell_lock_path.read_bytes()
    if sha256(cell_raw) != admission.cell_admission_sha256:
        raise RuntimeError("N05_CELL_ADMISSION_MISMATCH")
    cell_admission = load_wire(AdmissionLock, cell_raw).model_dump()
    if any(
        admission.model_dump().get(name) != value
        for name, value in cell_admission.items()
        if name not in {"schema_version", "claim_scope"}
    ):
        raise RuntimeError("N05_BASE_PROFILE_FIELDS_MISMATCH")
    if model_path.name != admission.model_filename:
        raise RuntimeError("MODEL_PROFILE_FILENAME_MISMATCH")
    if digest_file(corpus_receipt_path) != admission.corpus_receipt_sha256:
        raise RuntimeError("CORPUS_RECEIPT_MISMATCH")
    if runtime_source_hashes() != admission.runtime_source_sha256:
        raise RuntimeError("FROZEN_RUNTIME_SOURCE_CHANGED_REPREPARE_ADMISSION")
    if digest_file(BACKEND / "infra/cells/defense.py") != admission.defense_source_sha256:
        raise RuntimeError("DEFENSE_SOURCE_MISMATCH")

    # Verify the exact locally admitted, immutable defense image without starting
    # the model image or building/pulling any image.
    ensure_local_docker()
    image = json.loads(docker("image", "inspect", admission.defense_image))[0]
    if image.get("Config", {}).get("Labels", {}).get("arena.defense_source_sha256") != admission.defense_source_sha256:
        raise RuntimeError("DEFENSE_IMAGE_SOURCE_MISMATCH")

    public_corpus = PreparedPublicCorpus(
        corpus_path, corpus_receipt_path, corpus_keys_path, admission.corpus_receipt_sha256
    )
    if len(public_corpus.records) != EXPECTED_RECORDS or len(public_corpus.records) > MAX_RECORDS:
        raise RuntimeError("ADMITTED_JBB_RECORD_COUNT_MISMATCH")
    split_counts = dict(Counter(public_corpus.split.values()))
    if split_counts != EXPECTED_SPLITS:
        raise RuntimeError("ADMITTED_JBB_SPLIT_COUNTS_MISMATCH")
    for payload in public_corpus.records.values():
        if (
            payload.provenance.source_id != "JBB-Behaviors"
            or payload.provenance.run_label != "REAL_PUBLIC"
        ):
            raise RuntimeError("NON_JBB_OR_NONPUBLIC_RECORD_IN_ADMITTED_CORPUS")
    return admission, cell_lock_path, public_corpus, split_counts


def safe_record_projection(
    payload_ref: str, split: str, decision: DefenseDecision, record_id: str,
    event_identity: dict[str, str | None],
) -> dict[str, str | None]:
    """Persist only hashed identities, split and registered finite result symbols."""
    return {
        "record_id_sha256": sha256(record_id.encode("utf-8")),
        "payload_ref_sha256": sha256(payload_ref.encode("utf-8")),
        "defense_container_id_sha256": event_identity["defense_container_id_sha256"],
        "defense_container_name_sha256": event_identity["defense_container_name_sha256"],
        "split": split,
        "verdict": decision.verdict,
        "reason_code": decision.reason_code,
        "transform_id": decision.transform_id,
    }


def aggregate_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    verdict_counts: Counter[str] = Counter()
    by_split: dict[str, Counter[str]] = {"benign": Counter(), "harmful": Counter()}
    for row in rows:
        split, verdict = row.get("split"), row.get("verdict")
        if split not in by_split or verdict not in {"ALLOW", "BLOCK", "SANITIZE"}:
            raise ValueError("PRIVATE_RESULT_SYMBOL_INVALID")
        verdict_counts[verdict] += 1
        by_split[split][verdict] += 1
    normalized_counts = {name: verdict_counts.get(name, 0) for name in ("ALLOW", "BLOCK", "SANITIZE")}
    normalized_by_split = {
        split: {name: counts.get(name, 0) for name in ("ALLOW", "BLOCK", "SANITIZE")}
        for split, counts in by_split.items()
    }
    return {
        "record_count": len(rows),
        "verdict_distribution": normalized_counts,
        "verdict_distribution_by_split": normalized_by_split,
        "varied_verdicts_observed": sum(count > 0 for count in normalized_counts.values()) > 1,
    }


async def evaluate_public_records(
    evaluator: PinnedCell,
    corpus: PreparedPublicCorpus,
    event_recorder: DockerEventRecorder,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for payload_ref in sorted(corpus.records):
        payload = corpus.records[payload_ref]
        split = corpus.split[payload_ref]
        call_token = str(uuid4())
        request = InputDefenseRequest(
            call_token=call_token,
            mode="INPUT",
            content=PromptContent(prompt=payload.text),
        )
        # Do not invoke evaluator.start(): PinnedCell.evaluate is the exact
        # defense-cell path and does not need or start a model cell.
        decision = DefenseDecision.model_validate((await evaluator.evaluate(request)).model_dump())
        if decision.call_token != call_token:
            raise RuntimeError("DEFENSE_CALL_TOKEN_MISMATCH")
        try:
            event_identity: dict[str, str | None] = await event_recorder.wait_for_completed_container()
        except Exception:
            row = safe_record_projection(
                payload_ref, split, decision, payload.provenance.record_id,
                {"defense_container_id_sha256": None, "defense_container_name_sha256": None},
            )
            rows.append(row)
            if on_result is not None:
                on_result(row)
            raise
        row = safe_record_projection(
            payload_ref, split, decision, payload.provenance.record_id, event_identity
        )
        rows.append(row)
        if on_result is not None:
            on_result(row)
    return rows


def write_private_observation(path: Path, observation: dict[str, Any]) -> None:
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    raw = (json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def failure_code(exc: BaseException) -> str | None:
    value = str(exc)
    return value if re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", value) else None


def verify_output_path(path: Path) -> Path:
    output = path.resolve()
    if not output.is_relative_to(ARTIFACTS.resolve()) or output.exists():
        raise ValueError("NEW_IGNORED_PRIVATE_OUTPUT_REQUIRED")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=False, exist_ok=False)
    return output


def run(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    output = verify_output_path(args.output)
    observation_path = output / "observation.json"
    sources_before = backend_sources()
    observation: dict[str, Any] = {
        "schema_version": SCHEMA,
        "scope": SCOPE,
        "result": "RUNNING",
        "source_revision": current_revision(),
        "source_sha256": sources_before,
        "source_manifest_sha256": source_manifest_digest(sources_before),
        "source_file_count": len(sources_before),
        "runtime_source_manifest_sha256": source_manifest_digest(runtime_source_hashes()),
        "mode": "INPUT",
        "real_public_jbb_inputs_used": False,
        "synthetic_inputs_used": False,
        "mock_defense_used": False,
        "real_model_inference_performed": False,
        "model_dispatch_count": 0,
        "model_runtime_start_count": 0,
        "n04_controller_pipeline_exercised": False,
        "defense_runtime_entrypoint": "arena.integration.lanes.PinnedCell.evaluate->arena.integration.runtime.DockerRuntime.evaluate",
        "defense_runtime_source_sha256": defense_runtime_source_digest(),
        "defense_call_count": 0,
        "records": [],
        "docker_event_trace": None,
        "container_inventory_before": None,
        "container_inventory_after": None,
        "source_unchanged_during_run": False,
        "p011_complete": False,
        "p013_complete": False,
        "t019_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }
    write_private_observation(observation_path, observation)

    failure: BaseException | None = None
    failure_stage = "ADMISSION"
    inventory_before: dict[str, Any] | None = None
    source_after: dict[str, str] | None = None
    try:
        admission, cell_lock_path, corpus, split_counts = admission_checks(
            lock_path=args.lock.resolve(),
            model_path=args.model.resolve(),
            corpus_path=args.corpus.resolve(),
            corpus_receipt_path=args.corpus_receipt.resolve(),
            corpus_keys_path=args.corpus_keys.resolve(),
        )
        inventory_before = inventory()
        observation["container_inventory_before"] = inventory_before
        if inventory_before["running_container_count"] != 0:
            raise RuntimeError("PREEXISTING_RUNNING_CONTAINERS_LEFT_UNTOUCHED")
        observation.update(
            {
                "real_public_jbb_inputs_used": True,
                "record_count_expected": len(corpus.records),
                "split_counts_expected": split_counts,
                "admission_lock_sha256": digest_file(args.lock.resolve()),
                "cell_admission_sha256": digest_file(cell_lock_path),
                "corpus_receipt_sha256": digest_file(args.corpus_receipt.resolve()),
                "defense_image_digest": admission.defense_image,
                "defense_source_sha256": admission.defense_source_sha256,
                "runtime_source_manifest_sha256": source_manifest_digest(admission.runtime_source_sha256),
            }
        )
        write_private_observation(observation_path, observation)

        # The real model path is required by the existing PinnedCell constructor,
        # but it is neither opened nor hashed nor dispatched in this defense-only run.
        evaluator = PinnedCell(
            cell_lock_path,
            args.model.resolve(),
            output / "evaluator-private-root",
            cpuset=admission.model_cpusets[0],
            defense_cpuset=admission.defense_cpuset,
        )
        failure_stage = "EVALUATION"

        def retain(row: dict[str, Any]) -> None:
            observation["records"].append(row)
            observation["defense_call_count"] = len(observation["records"])
            observation["outcome_aggregate"] = aggregate_rows(observation["records"])
            write_private_observation(observation_path, observation)
            if len(observation["records"]) % 10 == 0:
                print(json.dumps({
                    "step": "public_jbb_defense_preflight",
                    "evaluated_records": len(observation["records"]),
                    "total_records": len(corpus.records),
                }, sort_keys=True), flush=True)

        event_recorder = DockerEventRecorder(admission.defense_image, len(corpus.records))

        async def collect_runtime_results() -> None:
            try:
                await event_recorder.start()
                await evaluate_public_records(evaluator, corpus, event_recorder, retain)
            finally:
                observation["docker_event_trace"] = await event_recorder.stop()
                write_private_observation(observation_path, observation)

        asyncio.run(collect_runtime_results())
        failure_stage = "RECONCILIATION"
    except (Exception, KeyboardInterrupt) as exc:
        failure = exc
    finally:
        try:
            observation["container_inventory_after"] = inventory()
        except Exception as exc:
            if failure is None:
                failure = exc
                failure_stage = "POST_RUN_INVENTORY"
        try:
            source_after = backend_sources()
            observation["source_sha256_after"] = source_after
            observation["source_unchanged_during_run"] = source_after == sources_before
        except Exception as exc:
            if failure is None:
                failure = exc
                failure_stage = "POST_RUN_SOURCE_CHECK"

    before = observation.get("container_inventory_before")
    after = observation.get("container_inventory_after")
    inventory_unchanged = (
        isinstance(before, dict)
        and isinstance(after, dict)
        and before == after
        and after.get("running_container_count") == 0
    )
    complete = (
        failure is None
        and observation["source_unchanged_during_run"] is True
        and inventory_unchanged
        and observation["defense_call_count"] == observation.get("record_count_expected")
        and isinstance(observation.get("docker_event_trace"), dict)
        and observation["docker_event_trace"].get("result") == "PASS"
    )
    observation["container_inventory_unchanged"] = inventory_unchanged
    if complete:
        observation["outcome_aggregate"] = aggregate_rows(observation["records"])
        observation["result"] = "PUBLIC_JBB_VERDICT_PREFLIGHT_COMPLETE"
    else:
        observation["result"] = "INCOMPLETE_RETAINED"
        observation["failure_stage"] = failure_stage
        if failure is not None:
            observation["failure_type"] = type(failure).__name__
            observation["failure_code"] = failure_code(failure)
        observation["container_inventory_unchanged"] = inventory_unchanged
    write_private_observation(observation_path, observation)
    summary = {
        "result": observation["result"],
        "record_count": observation["defense_call_count"],
        "source_file_count": observation["source_file_count"],
        "observation_sha256": digest_file(observation_path),
        "observation_path": observation_path.relative_to(BACKEND).as_posix(),
    }
    if complete:
        summary.update(observation["outcome_aggregate"])
    else:
        summary.update(
            failure_type=observation.get("failure_type"),
            failure_code=observation.get("failure_code"),
            failure_stage=observation.get("failure_stage"),
        )
    return (0 if complete else 1), summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True, help="Prepared N05 admission JSON")
    parser.add_argument("--model", type=Path, required=True, help="Prepared model path required by PinnedCell construction; not opened or dispatched")
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--corpus-receipt", type=Path, required=True)
    parser.add_argument("--corpus-keys", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New private directory under backend/artifacts")
    args = parser.parse_args(argv)
    try:
        exit_code, result = run(args)
    except Exception as exc:
        result = {"result": "NOT_STARTED", "failure_type": type(exc).__name__, "failure_code": failure_code(exc)}
        exit_code = 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
