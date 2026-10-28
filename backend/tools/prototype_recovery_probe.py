"""Source-bound real-process Step 5 feedback recovery probe.

This tool has a dry ``--plan`` mode. Real model execution requires the explicit
``--execute-real`` flag, a current committed source freeze, and a valid SERVICE
grant. It exercises two authenticated crash cuts in separate OS processes and
keeps prompts, replies, private keys, and artifact-opening keys out of its
metadata and logs. Private verifier material remains only in ignored artifacts.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import re
import subprocess
import sys
import threading
import time
from typing import Any
from uuid import uuid4


BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
sys.path.insert(0, str(BACKEND / "src"))


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + uuid4().hex)
    temporary.write_bytes(_json_bytes(value))
    os.replace(temporary, path)


def _command_record(command: list[str], started: str, start_ns: int, result: subprocess.CompletedProcess,
                    output_dir: Path, name: str) -> dict[str, Any]:
    stdout = result.stdout if isinstance(result.stdout, bytes) else str(result.stdout or "").encode()
    stderr = result.stderr if isinstance(result.stderr, bytes) else str(result.stderr or "").encode()
    stdout_path = output_dir / (name + ".stdout.bin")
    stderr_path = output_dir / (name + ".stderr.bin")
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    return {
        "argv": command,
        "started_at_utc": started,
        "duration_ns": time.monotonic_ns() - start_ns,
        "exit_code": result.returncode,
        "stdout_sha256": _sha(stdout),
        "stderr_sha256": _sha(stderr),
        "stdout_path": stdout_path.relative_to(output_dir).as_posix(),
        "stderr_path": stderr_path.relative_to(output_dir).as_posix(),
    }


def _run_logged(command: list[str], *, cwd: Path, env: dict[str, str] | None,
                timeout: int, output_dir: Path, name: str) -> dict[str, Any]:
    started, start_ns = _utc(), time.monotonic_ns()
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        result = subprocess.CompletedProcess(command, 124, exc.stdout or b"", exc.stderr or b"TIMEOUT")
    record = _command_record(command, started, start_ns, result, output_dir, name)
    record["timed_out"] = result.returncode == 124
    return record


def _repo_head() -> str:
    value = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, timeout=15, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise RuntimeError("SOURCE_COMMIT_INVALID")
    return value


def _corpus_inputs_available(corpus: Path, receipt: Path, key_file: Path) -> bool:
    """Require the prepared corpus directory and regular receipt/key files."""
    return (
        corpus.is_dir() and not corpus.is_symlink()
        and receipt.is_file() and not receipt.is_symlink()
        and key_file.is_file() and not key_file.is_symlink()
    )


def _preflight(args):
    """Validate the complete committed profile/grant and external keys, no model start."""
    from arena.contracts.crypto import canonical_bytes
    from arena.contracts.jsonwire import load_wire
    from arena.model_runtime import ModelProfile, file_digest, validate_assets
    from arena.prototype.admission import (
        PrototypeProfile, authority_public, key_from_file, key_public, source_hashes,
        verify_gate,
    )
    from arena.recovery.anchor import load_recovery_authorities

    profile_path = args.profile.resolve(strict=True)
    public = key_public(args.authority_public_key)
    profile = load_wire(PrototypeProfile, profile_path.read_bytes())
    gate = verify_gate(args.service_grant, profile_path, public, "SERVICE")
    if gate.receipt.observations.get("result") != "READY_FOR_BOUNDED_ARENA_EXECUTION":
        raise RuntimeError("CURRENT_SERVICE_GRANT_RESULT_REJECTED")
    if profile.cold_resume_authorized or profile.scope != "LOCAL_OFFLINE_PROTOTYPE_NOT_FULL_T_P_ACCEPTANCE":
        raise RuntimeError("PROFILE_COLD_RESUME_OR_SCOPE_REJECTED")
    head = _repo_head()
    if profile.source_commit != head:
        raise RuntimeError("PROFILE_SOURCE_COMMIT_IS_NOT_CURRENT_HEAD")
    # ``verify_gate`` binds the whole source set to the gate's committed source.
    # Re-read it here for the signed report's stable hash and explicit refusal.
    current_sources = source_hashes()
    if profile.source_sha256 != current_sources:
        raise RuntimeError("CURRENT_PROFILE_SOURCE_HASH_MISMATCH")
    validate_assets(profile.component, args.model.resolve(strict=True))
    _ = load_wire(ModelProfile, (BACKEND / "infra/model-component/profile.json").read_bytes())

    authority_dir = args.authority_directory.resolve(strict=True)
    if authority_dir.is_relative_to(REPO):
        raise RuntimeError("AUTHORITY_KEYS_MUST_REMAIN_OUTSIDE_REPOSITORY")
    for role in ("recorder", "witness"):
        private = key_from_file(authority_dir / (role + "-private.pem"))
        if private.public_key().public_bytes_raw() != authority_public(role):
            raise RuntimeError("OWNER_EVIDENCE_AUTHORITY_MISMATCH")
    ca_key = authority_dir / "demo-ca-private.pem"
    if ca_key.is_symlink() or not ca_key.is_file():
        raise RuntimeError("OWNER_DEMO_CA_PRIVATE_KEY_MISSING")

    authorities = load_recovery_authorities(BACKEND / "infra/prototype/recovery-authorities.json")
    recovery_dir = authority_dir.parent / "prototype-recovery"
    key_digests = {}
    for role in ("anchor", "recovery", "invalid_export"):
        record = authorities[role]
        path = recovery_dir / (record["key_id"] + "-private.pem")
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("RECOVERY_AUTHORITY_PRIVATE_KEY_MISSING")
        private = key_from_file(path)
        if private.public_key().public_bytes_raw() != record["public_key_bytes"]:
            raise RuntimeError("RECOVERY_AUTHORITY_PRIVATE_KEY_MISMATCH")
        key_digests[role] = _file_sha(path)

    offline_python = args.offline_python.resolve(strict=True)
    if not offline_python.is_file():
        raise RuntimeError("REPRODUCIBLE_OFFLINE_PYTHON_MISSING")
    if not _corpus_inputs_available(args.corpus, args.corpus_receipt, args.corpus_keys):
        raise RuntimeError("ADMITTED_PUBLIC_CORPUS_INPUT_MISSING")
    source_hash = _sha(canonical_bytes(current_sources))
    return {
        "profile": profile,
        "profile_path": profile_path,
        "profile_sha256": file_digest(profile_path),
        "service_grant_sha256": file_digest(args.service_grant),
        "source_commit": head,
        "profile_source_commit": profile.source_commit,
        "source_sha256": source_hash,
        "model_image_id": profile.component.assembled_image_id,
        "authority_public_key": public,
        "authorities": authorities,
        "private_key_file_sha256": key_digests,
        "authority_directory": authority_dir,
        "recovery_directory": recovery_dir,
        "offline_python": offline_python,
    }


def _read_credential_key(authority_dir: Path):
    from arena.prototype.admission import key_from_file
    return key_from_file(authority_dir / "recorder-private.pem")


def _ensure_private_artifact_dir(path: Path) -> Path:
    from arena.model_runtime import BACKEND as MODEL_BACKEND
    absolute = path.absolute()
    if absolute.is_symlink() or not absolute.resolve().is_relative_to(MODEL_BACKEND / "artifacts"):
        raise ValueError("PRIVATE_STEP5_OUTPUT_MUST_STAY_IN_BACKEND_ARTIFACTS")
    if absolute.exists():
        raise ValueError("STEP5_OUTPUT_MUST_BE_NEW")
    absolute.parent.mkdir(parents=True, exist_ok=True)
    return absolute


def _record_root_summary(service, runtime, turn_key: str,
                        trace_count_before: int) -> dict[str, Any]:
    from arena.contracts.crypto import event_digest
    from arena.integration.runtime import docker
    from arena.model_runtime import file_digest
    from arena.integration.controller import ACTOR

    recorder = service.controller.recorder
    events = recorder.get_events(service.ctx)
    event_bytes = recorder.get_event_bytes(service.ctx)
    with closing(service.store.connect()) as conn:
        turn = conn.execute("SELECT id,state,session_id,turn_index FROM turns WHERE experiment_id=?", (service.ctx.experiment_id,)).fetchone()
        internal = conn.execute("SELECT state,known_execution,receipt_json FROM n04_turns WHERE turn_id=?", (turn["id"],)).fetchone()
        job = conn.execute("SELECT state,known_execution,body_ref,published,client_key FROM n06_jobs WHERE turn_id=?", (turn["id"],)).fetchone()
        budget = conn.execute("SELECT admitted FROM budgets WHERE experiment_id=? AND subject_id='red'", (service.ctx.experiment_id,)).fetchone()
        reservation_count = conn.execute("SELECT count(*) FROM idempotency WHERE experiment_id=? AND action='turns'", (service.ctx.experiment_id,)).fetchone()[0]
        run = conn.execute("SELECT public_commitment FROM experiments WHERE id=?", (service.ctx.experiment_id,)).fetchone()
    if not turn or not internal or not job or not budget or not run:
        raise RuntimeError("CRASH_CUT_STORE_BINDING_MISSING")
    cell_ids = []
    for cell in runtime.cells:
        inspected = json.loads(docker("inspect", cell.container))[0]
        cell_ids.append(inspected["Id"])
    dispatches = sum(event.event_type == "MODEL_RESULT" and event.outcome_code == "OK" for event in events)
    trace_count_after = len(runtime.model.trace)
    trace_delta = trace_count_after - trace_count_before
    checks = {
        "event_chain_present": len(events) > 0,
        "one_signed_dispatch": dispatches == 1,
        "one_new_runtime_trace": trace_delta == 1,
        "execution_known": internal["known_execution"] == "EXECUTED",
        "queue_still_claimed": job["state"] == "CLAIMED",
        "queue_not_published": job["published"] == 0,
        "queue_body_absent": job["body_ref"] is None,
        "turn_still_dispatched": turn["state"] == "DISPATCHED",
        "receipt_not_yet_persisted": internal["receipt_json"] is None,
        "idempotency_key_matches": job["client_key"] == turn_key,
        "budget_admitted_once": budget[0] == 1,
        "reservation_recorded_once": reservation_count == 1,
    }
    failed_checks = [name for name, passed in checks.items() if not passed]
    if failed_checks:
        error = RuntimeError("CRASH_CUT_NOT_EXACTLY_ONE_EXECUTED_ORPHAN")
        error.failed_checks = failed_checks
        raise error
    return {
        "context": service.ctx.model_dump(mode="json"),
        "turn_id": turn["id"],
        "session_id": turn["session_id"],
        "turn_index": turn["turn_index"],
        "idempotency_key": turn_key,
        "public_manifest_digest": run["public_commitment"],
        "real_model_dispatch_count": dispatches,
        "dispatch_count": dispatches,
        "runtime_model_trace_count_before": trace_count_before,
        "runtime_model_trace_count_after": trace_count_after,
        "reservation_count": reservation_count,
        "budget_admitted": budget[0],
        "event_count": len(events),
        "event_bytes_sha256": _sha(event_bytes),
        "final_event_digest": event_digest(events[-1]),
        "cell_ids": cell_ids,
        "anchor_port": service.anchor_process.port,
        "anchor_pid": service.anchor_process.process.pid,
        "anchor_db_sha256": file_digest(service.recovery_directory / "anchor-data" / "anchor.sqlite3"),
        "child_pid": os.getpid(),
        "service_port": service.server.server_address[1],
        "actor_id": ACTOR,
    }


def _write_boundary_rejection(path: Path, exc: BaseException,
                              trace_count_before: int, trace_count_after: int) -> None:
    code = str(exc)
    safe_code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{3,95}", code) else "INTERNAL_FAILURE"
    missing_attribute = getattr(exc, "name", None) if isinstance(exc, AttributeError) else None
    if not isinstance(missing_attribute, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,63}", missing_attribute
    ):
        missing_attribute = None
    _write_json(path.with_name("boundary-failure.json"), {
        "event": "BOUNDARY_REJECTED", "error_code": safe_code,
        "error_type": type(exc).__name__,
        "error_attribute": missing_attribute,
        "failed_checks": [item for item in getattr(exc, "failed_checks", [])
                          if isinstance(item, str) and re.fullmatch(r"[a-z_]{3,48}", item)],
        "runtime_model_trace_count_before": trace_count_before,
        "runtime_model_trace_count_after": trace_count_after,
    })


def _pause_for_parent(metadata: dict[str, Any], boundary_file: Path, *, case: str) -> None:
    """Publish metadata-only boundary, then wait forever for hard parent termination."""
    if case not in {"orphan", "original-receipt"}:
        raise ValueError("UNKNOWN_CRASH_CASE")
    metadata = {**metadata, "event": "BOUNDARY", "boundary_at_utc": _utc(), "case": case}
    _write_json(boundary_file, metadata)
    # Keep the pipe log public-safe. Full recovery request material remains in
    # the private ignored case directory, never in captured stdout/stderr.
    marker = {key: metadata[key] for key in (
        "event", "boundary_at_utc", "case", "boundary", "child_pid",
        "turn_id", "profile_sha256", "source_commit",
    ) if key in metadata}
    sys.stdout.write(json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    threading.Event().wait()


def _after_durable_authorization(authorize, on_persisted):
    async def intercepted(*args, **kwargs):
        signed_receipt = await authorize(*args, **kwargs)
        on_persisted(signed_receipt)
        return signed_receipt
    return intercepted


async def _initial_child(args) -> None:
    from arena.contracts.jsonwire import load_wire
    from arena.integration.corpus import PreparedPublicCorpus
    from arena.model_runtime import file_digest
    from arena.prototype.admission import PrototypeProfile, key_public, verify_gate
    from arena.prototype.demo import admin, request
    from arena.prototype.runtime import PrototypeRuntime
    from arena.prototype.service import PrototypeService
    from arena.ports import DependencyUnavailable

    profile = load_wire(PrototypeProfile, args.profile.read_bytes())
    public_key = key_public(args.authority_public_key)
    signed = verify_gate(args.service_grant, args.profile, public_key, "SERVICE")
    if signed.receipt.observations.get("result") != "READY_FOR_BOUNDED_ARENA_EXECUTION":
        raise RuntimeError("CURRENT_SERVICE_GRANT_RESULT_REJECTED")
    case_root = args.case_root.resolve()
    if not case_root.is_relative_to((BACKEND / "artifacts").resolve()) or case_root.exists():
        raise RuntimeError("NEW_PRIVATE_CASE_ROOT_REQUIRED")
    case_root.mkdir(parents=True, exist_ok=False)
    corpus = PreparedPublicCorpus(
        args.corpus, args.corpus_receipt, args.corpus_keys,
        profile.component.admission.corpus_receipt_sha256,
    )
    candidate = next((item for item in corpus.records.values()
                      if item.provenance.record_id == "benign:34"
                      and corpus.split[item.payload_ref] == "benign"), None)
    if candidate is None:
        raise RuntimeError("PINNED_PUBLIC_JBB_CANARY_CASE_MISSING")

    runtime = PrototypeRuntime(
        args.profile, args.service_grant, public_key, args.model,
        case_root / "runtime",
    )
    service = None
    try:
        service = PrototypeService(runtime, corpus, case_root, args.authority_directory,
                                   mode="INTERACTIVE", defense_mode="INPUT")
        service.startup_preflight()
        await asyncio.to_thread(runtime.start)
        port = service.listen(0)
        ready = {
            "event": "SERVICE_READY",
            "case": args.case,
            "child_pid": os.getpid(),
            "service_port": port,
            "anchor_port": service.anchor_process.port,
            "anchor_pid": service.anchor_process.process.pid,
            "model_image_id": profile.component.assembled_image_id,
            "profile_sha256": file_digest(args.profile),
            "model_started": True,
            "workers_started": True,
            "authority_scope": "OWNER_DELEGATED_SELF_ATTESTED_PROTOTYPE_SCOPE",
        }
        sys.stdout.write(json.dumps(ready, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()

        created = await asyncio.to_thread(request, service, "operator", "POST", "/v1/experiments",
                                          service.request.model_dump(), "step5-create-" + args.case)
        if created["status"] != 201:
            raise RuntimeError("EXPERIMENT_CREATE_FAILED")
        context = service.ctx
        attack = {"epoch": context.epoch,
                  "items": [{"item_id": "step5-public-item", "text": candidate.text}]}
        uploaded = await asyncio.to_thread(request, service, "red", "POST", "attacks", attack,
                                           "step5-upload-" + args.case)
        if uploaded["status"] != 201:
            raise RuntimeError("PUBLIC_JBB_ADMISSION_FAILED")
        sealed = await asyncio.to_thread(request, service, "operator", "POST", "seal",
                                         {"epoch": context.epoch}, "step5-seal-" + args.case)
        if sealed["status"] != 200:
            raise RuntimeError("SEALED_EXPERIMENT_REQUIRED")
        await admin(service, "start")
        sessions = []
        for lane in range(3):
            value = await asyncio.to_thread(request, service, "operator", "POST", "sessions",
                                            {"epoch": context.epoch},
                                            f"step5-session-{args.case}-{lane}")
            if value["status"] != 201:
                raise RuntimeError("THREE_SESSION_ADMISSION_FAILED")
            sessions.append(json.loads(value["body"])["session_id"])
        deadline = time.monotonic() + 15
        while service.participant is None:
            if time.monotonic() >= deadline:
                raise RuntimeError("PARTICIPANT_ACTIVATION_TIMEOUT")
            await asyncio.sleep(0.05)

        turn_key = "step5-turn-" + args.case + "-" + uuid4().hex
        turn_request = {"epoch": context.epoch, "turn_index": 0, "text": candidate.text}
        trace_count_before = len(runtime.model.trace)
        original_event = service.controller._event

        if args.case == "orphan":
            async def pause_after_event(kind, outcome="OK", refs=(), turn=None, operation=None):
                event = await original_event(kind, outcome, refs, turn, operation)
                if kind == "FEEDBACK_AUTHORIZED" and turn is not None:
                    try:
                        metadata = _record_root_summary(
                            service, runtime, turn_key, trace_count_before
                        )
                    except BaseException as exc:
                        _write_boundary_rejection(
                            args.boundary_file, exc, trace_count_before,
                            len(runtime.model.trace),
                        )
                        raise
                    receipt_fields = {
                        "receipt_persisted": False,
                        "receipt_sha256": None,
                        "signature_sha256": None,
                    }
                    _pause_for_parent({**metadata, **receipt_fields,
                                       "boundary": "AFTER_FEEDBACK_AUTHORIZED_BEFORE_RECEIPT",
                                       "profile_sha256": file_digest(args.profile),
                                       "source_commit": args.source_commit}, args.boundary_file,
                                      case=args.case)
                return event
            service.controller._event = pause_after_event
        elif args.case == "original-receipt":
            original_authorize = service.controller.recorder.authorize_bound_turn
            def pause_after_original_receipt(signed_receipt):
                try:
                    metadata = _record_root_summary(
                        service, runtime, turn_key, trace_count_before
                    )
                except BaseException as exc:
                    _write_boundary_rejection(
                        args.boundary_file, exc, trace_count_before,
                        len(runtime.model.trace),
                    )
                    raise
                receipt_bytes = signed_receipt.model_dump_json().encode()
                public_receipt = signed_receipt.receipt.model_dump(mode="json")
                _pause_for_parent({
                    **metadata,
                    "receipt_persisted": True,
                    "receipt_sha256": _sha(receipt_bytes),
                    "signature_sha256": _sha(signed_receipt.signature.encode("ascii")),
                    "public_receipt": public_receipt,
                    "boundary": "AFTER_RECORDER_AUTHORIZATION_BEFORE_BROKER_PROJECTION",
                    "profile_sha256": file_digest(args.profile),
                    "source_commit": args.source_commit,
                }, args.boundary_file, case=args.case)
            service.controller.recorder.authorize_bound_turn = _after_durable_authorization(
                original_authorize, pause_after_original_receipt
            )
        else:
            raise RuntimeError("UNKNOWN_CRASH_CASE")

        submitted = await asyncio.to_thread(
            request, service, "red", "POST",
            f"sessions/{sessions[0]}/turns", turn_request, turn_key,
        )
        if submitted.get("status") not in {200, 201, 202}:
            raise RuntimeError("STEP5_TURN_SUBMISSION_REFUSED")
        # Interactive admission returns before the worker finishes the queued
        # turn. Keep this process alive until the worker reaches the exact
        # anchored crash cut and publishes its metadata-only boundary marker.
        deadline = time.monotonic() + 180
        failure_file = args.boundary_file.with_name("boundary-failure.json")
        while not args.boundary_file.is_file():
            if failure_file.is_file():
                raise RuntimeError("CRASH_BOUNDARY_REJECTED")
            with closing(service.store.connect()) as conn:
                current = conn.execute(
                    "SELECT phase,integrity FROM experiments WHERE id=?",
                    (service.ctx.experiment_id,),
                ).fetchone()
            if current and (current[0] == "INVALID" or current[1] == "INVALID"):
                _write_json(failure_file, {
                    "event": "BOUNDARY_REJECTED",
                    "error_code": "TURN_OR_RUN_INVALIDATED_BEFORE_BOUNDARY",
                    "runtime_model_trace_count_before": trace_count_before,
                    "runtime_model_trace_count_after": len(runtime.model.trace),
                })
                raise RuntimeError("TURN_OR_RUN_INVALIDATED_BEFORE_BOUNDARY")
            if time.monotonic() >= deadline:
                raise RuntimeError("CRASH_BOUNDARY_TIMEOUT")
            await asyncio.sleep(0.05)
        await asyncio.Event().wait()
    finally:
        # Parent deliberately terminates this process at the boundary. Graceful
        # cleanup is only for pre-boundary setup failures.
        if service is not None:
            await service.shutdown()
        else:
            await asyncio.to_thread(runtime.stop)


def _child_main(args) -> int:
    try:
        asyncio.run(_initial_child(args))
    except BaseException as exc:
        # No exception string, request text, model output, or credentials reach stdout.
        code = str(exc)
        safe_code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{3,95}", code) else "CHILD_FAILURE"
        sys.stderr.write(json.dumps({"error_type": type(exc).__name__, "error_code": safe_code}) + "\n")
        sys.stderr.flush()
        return 1
    return 3


def _case_snapshot(service) -> dict[str, Any]:
    events = service.recorder.get_events(service.ctx)
    event_bytes = service.recorder.get_event_bytes(service.ctx)
    with closing(service.store.connect()) as conn:
        row = conn.execute(
            "SELECT (SELECT count(*) FROM turns WHERE experiment_id=?),"
            "(SELECT admitted FROM budgets WHERE experiment_id=? AND subject_id='red'),"
            "(SELECT count(*) FROM idempotency WHERE experiment_id=? AND action='turns'),"
            "(SELECT state FROM turns WHERE id=?),"
            "(SELECT state FROM n06_jobs WHERE turn_id=?),"
            "(SELECT known_execution FROM n04_turns WHERE turn_id=?)",
            (service.ctx.experiment_id, service.ctx.experiment_id, service.ctx.experiment_id,
             service.recovery_inspection["recovery_turn_id"],
             service.recovery_inspection["recovery_turn_id"],
             service.recovery_inspection["recovery_turn_id"]),
        ).fetchone()
    return {
        "event_count": len(events),
        "event_bytes_sha256": _sha(event_bytes),
        "event_bytes": event_bytes,
        "dispatch_count": sum(event.event_type == "MODEL_RESULT" and event.outcome_code == "OK" for event in events),
        "reservation_count": row[2],
        "turn_count": row[0],
        "budget_admitted": row[1],
        "turn_state": row[3],
        "job_state": row[4],
        "known_execution": row[5],
    }


def _request_recovery(service, role: str, turn_id: str, idempotency_key: str,
                      *, header_key: str | None = None) -> tuple[int, bytes]:
    import http.client

    connection = http.client.HTTPSConnection(
        "127.0.0.1", service.server.server_address[1],
        context=service.clients[role], timeout=30,
    )
    body = json.dumps({"turn_id": turn_id, "idempotency_key": idempotency_key}, separators=(",", ":"))
    headers = {
        "Content-Type": "application/json",
        "Idempotency-Key": header_key if header_key is not None else idempotency_key,
        "Accept": "application/vnd.arena.feedback-replay.v1+json",
    }
    try:
        connection.request("POST", "/v1/turn-feedback/recovery", body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _public_receipt_metadata(raw: bytes, *, original: dict[str, Any] | None) -> dict[str, Any]:
    from arena.contracts.evidence import TurnFeedback
    from arena.recovery.feedback import FeedbackReplay
    value = json.loads(raw)
    if "feedback_receipt" in value:
        feedback = TurnFeedback.model_validate(value)
        signed = feedback.feedback_receipt
        public = signed.receipt.model_dump(mode="json")
        signature_hash = _sha(signed.signature.encode("ascii"))
        exact_original = bool(original is not None and
            _sha(signed.model_dump_json().encode()) == original["receipt_sha256"]
            and signature_hash == original["signature_sha256"]
            and public == original["public_receipt"])
        # Never retain the raw response object: it contains public_reply and
        # padding. The copied receipt and signature are represented by hashes.
        return {
            "response_kind": "ORIGINAL_TURN_FEEDBACK",
            "receipt": public,
            "signature_sha256": signature_hash,
            "receipt_sha256": _sha(signed.model_dump_json().encode()),
            "matches_original_receipt": exact_original,
            "public_response_sha256": _sha(raw),
        }

    replay = FeedbackReplay.model_validate(value)
    proof = replay.feedback_reconciliation
    return {
        "response_kind": "SIGNED_FEEDBACK_REPLAY",
        "schema_version": replay.schema_version,
        "turn_id": replay.turn_id,
        "session_id": replay.session_id,
        "turn_index": replay.turn_index,
        "public_status": replay.public_status,
        "response_commitment": replay.response_commitment,
        "reconciliation": proof.model_dump(mode="json", exclude={"signature"}),
        "reconciliation_signature_sha256": _sha(proof.signature.encode("ascii")),
        "replay_signature_sha256": _sha(replay.signature.encode("ascii")),
        "matches_original_receipt": False,
        "public_response_sha256": _sha(raw),
    }


async def _recovery_child_async(args) -> dict[str, Any]:
    from arena.contracts.crypto import event_digest
    from arena.contracts.evidence import SignedTurnReceipt
    from arena.contracts.jsonwire import load_wire
    from arena.integration.corpus import PreparedPublicCorpus
    from arena.integration.controller import ACTOR
    from arena.prototype.admission import PrototypeProfile
    from arena.prototype.demo import admin, request
    from arena.prototype.service import PrototypeService
    from arena.recovery.feedback import FeedbackRecoveryRequest

    boundary = json.loads(args.boundary_file.read_bytes())
    profile = load_wire(PrototypeProfile, args.profile.read_bytes())
    corpus = PreparedPublicCorpus(args.corpus, args.corpus_receipt, args.corpus_keys,
                                  profile.component.admission.corpus_receipt_sha256)
    startup_ns = time.monotonic_ns()
    service = PrototypeService.open_existing_recovery(
        corpus, args.case_root, args.authority_directory, startup_monotonic_ns=startup_ns
    )
    report: dict[str, Any] = {
        "case": args.case,
        "startup_action": service.recovery_inspection.get("recovery_only_action"),
        "recovery_turn_id": service.recovery_inspection.get("recovery_turn_id"),
        "model_started": False,
        "workers_started": False,
        "profile_sha256": boundary["profile_sha256"],
        "source_commit": boundary["source_commit"],
        "child_pid": os.getpid(),
        "startup_at_utc": _utc(),
        "recovery_context": service.ctx.model_dump(mode="json"),
    }
    with closing(service.store.connect()) as conn:
        public_manifest = conn.execute(
            "SELECT public_commitment FROM experiments WHERE id=?",
            (service.ctx.experiment_id,),
        ).fetchone()
    if not public_manifest or not public_manifest[0]:
        raise RuntimeError("RECOVERY_PUBLIC_MANIFEST_BINDING_MISSING")
    report["public_manifest_digest"] = public_manifest[0]
    try:
        service.startup_recovery_preflight()
        port = service.listen(0)
        report["service_port"] = port
        if (service.recovery_inspection.get("recovery_turn_id") != boundary["turn_id"]
                or service.recovery_inspection.get("recovery_only_action") not in {
                    "RECONCILE_ORPHAN", "REPLAY_STORED_RECOVERY"
                }
                or service.runtime is not None or service.queue is not None or service.worker is not None
                or service.participant is not None):
            raise RuntimeError("RECOVERY_ONLY_STARTUP_SCOPE_MISMATCH")

        turn_id, turn_key = boundary["turn_id"], boundary["idempotency_key"]
        before = _case_snapshot(service)
        if (before["turn_count"] != 1 or before["reservation_count"] != 1
                or before["dispatch_count"] != 1 or before["known_execution"] != "EXECUTED"
                or before["budget_admitted"] != 1):
            raise RuntimeError("PRE_RECOVERY_DISPATCH_RESERVATION_OR_BUDGET_MISMATCH")
        original_signed = service.recorder.get_turn_authorization(service.ctx, turn_id)
        if bool(original_signed) != bool(boundary["receipt_persisted"]):
            raise RuntimeError("ORIGINAL_RECORDER_RECEIPT_BOUNDARY_MISMATCH")
        original_metadata = None
        if original_signed is not None:
            original_metadata = {
                "receipt_sha256": _sha(original_signed.model_dump_json().encode()),
                "signature_sha256": _sha(original_signed.signature.encode("ascii")),
                "public_receipt": original_signed.receipt.model_dump(mode="json"),
            }
            if (original_metadata["receipt_sha256"] != boundary["receipt_sha256"]
                    or original_metadata["signature_sha256"] != boundary["signature_sha256"]):
                raise RuntimeError("ORIGINAL_RECORDER_RECEIPT_HASH_CHANGED")

        wrong_role_status, wrong_role_body = await asyncio.to_thread(
            _request_recovery, service, "blue-human", turn_id, turn_key
        )
        wrong_key_status, wrong_key_body = await asyncio.to_thread(
            _request_recovery, service, "red", turn_id, turn_key,
            header_key="wrong-key-" + uuid4().hex,
        )
        if wrong_role_status != 403 or wrong_key_status != 409:
            raise RuntimeError("RECOVERY_ROLE_OR_IDEMPOTENCY_DENIAL_FAILED")
        early_status, early_body = await asyncio.to_thread(
            _request_recovery, service, "red", turn_id, turn_key
        )
        if early_status != 503:
            raise RuntimeError("RECOVERY_COLD_START_FLOOR_EARLY_REFUSAL_NOT_OBSERVED")
        policy = service.recovery_policy.policy
        if policy.release_floor_ms != 61000:
            raise RuntimeError("RECOVERY_COLD_START_FLOOR_CHANGED")
        while time.monotonic_ns() < service._recovery_floor_not_before_ns:
            await asyncio.sleep(min(0.25, max(0.01,
                (service._recovery_floor_not_before_ns - time.monotonic_ns()) / 1_000_000_000)))
        if time.monotonic_ns() < service._recovery_floor_not_before_ns:
            raise RuntimeError("RECOVERY_COLD_START_FLOOR_NOT_ELAPSED")

        recovery_request = FeedbackRecoveryRequest(turn_id=turn_id, idempotency_key=turn_key)
        first_status, first_body = await asyncio.to_thread(
            _request_recovery, service, "red", turn_id, turn_key
        )
        if first_status != 200:
            raise RuntimeError("RECOVERY_REQUEST_DID_NOT_COMPLETE")
        first_receipt = _public_receipt_metadata(first_body, original=original_metadata)
        after_first = _case_snapshot(service)
        if after_first["event_bytes"] != before["event_bytes"]:
            raise RuntimeError("RECOVERY_CHANGED_ORIGINAL_EVENT_BYTES")
        if (after_first["reservation_count"] != before["reservation_count"]
                or after_first["turn_count"] != before["turn_count"]
                or after_first["dispatch_count"] != before["dispatch_count"]
                or after_first["budget_admitted"] != before["budget_admitted"]):
            raise RuntimeError("RECOVERY_CHANGED_RESERVATION_DISPATCH_OR_BUDGET")

        retry_status, retry_body = await asyncio.to_thread(
            _request_recovery, service, "red", turn_id, turn_key
        )
        retry_hash = hashlib.sha256(retry_body).hexdigest()
        first_hash = hashlib.sha256(first_body).hexdigest()
        after_retry = _case_snapshot(service)
        if (retry_status != 200 or retry_hash != first_hash
                or after_retry["event_bytes"] != before["event_bytes"]
                or after_retry["reservation_count"] != before["reservation_count"]
                or after_retry["turn_count"] != before["turn_count"]
                or after_retry["dispatch_count"] != before["dispatch_count"]
                or after_retry["budget_admitted"] != before["budget_admitted"]):
            raise RuntimeError("RECOVERY_IDEMPOTENCY_OR_NO_REDISPATCH_CHECK_FAILED")

        copy_directions: list[str] = []
        original_copy_verified = False
        if args.case == "original-receipt":
            if (not first_receipt["matches_original_receipt"] or original_signed is None):
                raise RuntimeError("ORIGINAL_RECEIPT_COPY_NOT_BYTE_IDENTICAL")
            with closing(service.store.connect()) as conn:
                copied = conn.execute(
                    "SELECT receipt_json FROM n04_receipt_copies WHERE experiment_id=? AND turn_id=?",
                    (service.ctx.experiment_id, turn_id),
                ).fetchone()
                projected = conn.execute("SELECT receipt_json FROM n04_turns WHERE turn_id=?", (turn_id,)).fetchone()
            if (not copied or not projected
                    or SignedTurnReceipt.model_validate_json(copied[0]) != original_signed
                    or SignedTurnReceipt.model_validate_json(projected[0]) != original_signed):
                raise RuntimeError("ORIGINAL_RECEIPT_RECORDER_TO_BROKER_COPY_MISMATCH")
            copy_directions.append("RECORDER_TO_BROKER")

            # Storage-fault control: remove only the recorder authorization row,
            # then exercise the public recovery route to restore the exact
            # already-copied signature from broker bytes.
            feedback_event = next(event for event in service.recorder.get_events(service.ctx)
                                  if event.event_type == "FEEDBACK_AUTHORIZED" and event.turn_id == turn_id)
            refs = feedback_event.artifact_ciphertext_refs
            if len(refs) != 2:
                raise RuntimeError("ORIGINAL_RECEIPT_COPY_EVENT_REFS_INVALID")
            with service.recorder._get_connection() as conn:
                conn.execute(
                    "DELETE FROM turn_authorizations WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                    (service.ctx.domain_id, service.ctx.experiment_id, service.ctx.epoch, turn_id),
                )
            if service.recorder.get_turn_authorization(service.ctx, turn_id) is not None:
                raise RuntimeError("RECORDER_COPY_CONTROL_DID_NOT_REMOVE_ROW")
            copy_retry_status, copy_retry_body = await asyncio.to_thread(
                _request_recovery, service, "red", turn_id, turn_key
            )
            after_copy_retry = _case_snapshot(service)
            if (copy_retry_status != 200 or copy_retry_body != first_body
                    or service.recorder.get_turn_authorization(service.ctx, turn_id) != original_signed
                    or after_copy_retry["event_bytes"] != before["event_bytes"]
                    or after_copy_retry["reservation_count"] != before["reservation_count"]
                    or after_copy_retry["turn_count"] != before["turn_count"]
                    or after_copy_retry["dispatch_count"] != before["dispatch_count"]
                    or after_copy_retry["budget_admitted"] != before["budget_admitted"]):
                raise RuntimeError("BROKER_TO_RECORDER_COPY_CHANGED_SIGNATURE")
            copy_directions.append("BROKER_TO_RECORDER")
            original_copy_verified = copy_directions == ["RECORDER_TO_BROKER", "BROKER_TO_RECORDER"]

            # Inject one trusted, anchored invalidity, then prove the copied
            # receipt cannot be replayed as a valid result or clear INVALID.
            turn = {**service.ctx.model_dump(), "session_id": boundary["session_id"],
                    "turn_id": turn_id, "turn_index": boundary["turn_index"]}
            await service.controller._event("INTEGRITY_VIOLATION", "FAILED", turn=turn)
            service.controller._invalidate()
            invalid_retry_error: list[str] = []
            original_recover = service.controller.recover_feedback
            async def observe_refusal(principal, request_value):
                try:
                    return await original_recover(principal, request_value)
                except BaseException as exc:
                    invalid_retry_error.append(str(exc))
                    raise
            service.controller.recover_feedback = observe_refusal
            invalid_retry_status, invalid_retry_body = await asyncio.to_thread(
                _request_recovery, service, "red", turn_id, turn_key
            )
            if invalid_retry_status == 200 or not invalid_retry_error:
                raise RuntimeError("INVALID_RECOVERY_RETRY_WAS_NOT_REFUSED")
            invalid_refusal_code = invalid_retry_error[0]
            with closing(service.store.connect()) as conn:
                invalid_state = conn.execute(
                    "SELECT phase,integrity FROM experiments WHERE id=?", (service.ctx.experiment_id,)
                ).fetchone()
            if tuple(invalid_state) != ("INVALID", "INVALID"):
                raise RuntimeError("INVALIDITY_WAS_CLEARED_OR_NOT_PRESERVED")
            invalid_before_close = {
                "status": invalid_retry_status,
                "refusal_code": invalid_refusal_code,
                "body_sha256": _sha(invalid_retry_body),
                "integrity": invalid_state[1],
            }
            close_operation = await admin(service, "close")
            with closing(service.store.connect()) as conn:
                closed_state = conn.execute(
                    "SELECT phase,integrity FROM experiments WHERE id=?", (service.ctx.experiment_id,)
                ).fetchone()
            if tuple(closed_state) != ("CLOSED", "INVALID"):
                raise RuntimeError("INVALID_CLOSE_INTEGRITY_NOT_PRESERVED")
            exported = await asyncio.to_thread(request, service, "auditor", "GET", "invalid-evidence")
            if exported["status"] != 200 or not exported["body"].startswith(b"PK"):
                raise RuntimeError("INVALID_EVIDENCE_EXPORT_FAILED")
            invalid_path = args.case_root / "invalid-evidence.zip"
            invalid_path.write_bytes(exported["body"])
            report["invalid_evidence"] = {
                "sha256": _sha(exported["body"]),
                "size_bytes": len(exported["body"]),
                "path": str(invalid_path),
                "close_operation": close_operation.get("result"),
                "close_integrity": closed_state[1],
                "recovery_refusal": invalid_before_close,
                "no_upgrade": True,
            }
            report["invalid_recovery_refusal_code"] = invalid_refusal_code
            report["invalidity_preserved"] = True
            report["invalid_close_integrity"] = "INVALID"
        else:
            close_operation = await admin(service, "close")
            with closing(service.store.connect()) as conn:
                closed_state = conn.execute(
                    "SELECT phase,integrity FROM experiments WHERE id=?", (service.ctx.experiment_id,)
                ).fetchone()
            if tuple(closed_state) != ("CLOSED", "VALID_WITHIN_PROFILE"):
                raise RuntimeError("VALID_RECONCILIATION_CLOSE_FAILED")
            evidence_path = args.case_root / "evidence.zip"
            anchor_path = args.case_root / "anchor-records.jsonl"
            replay_keys_path = args.case_root / "replay-keys.json"
            for path in (evidence_path, anchor_path, replay_keys_path):
                if not path.is_file() or path.is_symlink():
                    raise RuntimeError("VALID_RECONCILED_EVIDENCE_OUTPUT_MISSING")
            report["valid_evidence"] = {
                "sha256": _sha(evidence_path.read_bytes()),
                "size_bytes": evidence_path.stat().st_size,
                "path": str(evidence_path),
                "anchor_records_sha256": _sha(anchor_path.read_bytes()),
                "replay_keys_sha256": _sha(replay_keys_path.read_bytes()),
                "replay_keys_path": str(replay_keys_path),
                "anchor_records_path": str(anchor_path),
                "close_operation": close_operation.get("result"),
            }
            report["valid_close_integrity"] = "VALID_WITHIN_PROFILE"

        final = _case_snapshot(service)
        if (final["reservation_count"] != before["reservation_count"]
                or final["turn_count"] != before["turn_count"]
                or final["dispatch_count"] != before["dispatch_count"]
                or final["budget_admitted"] != before["budget_admitted"]):
            raise RuntimeError("CLOSE_CHANGED_RESERVED_DISPATCHED_OR_BUDGET_COUNT")
        report.update({
            "early_floor_refused": True,
            "wrong_role_refused": True,
            "wrong_key_refused": True,
            "floor_wait_ms": policy.release_floor_ms,
            "startup_recovery_only": True,
            "first_response": first_receipt,
            "retry_response_sha256": retry_hash,
            "retry_identical": retry_hash == first_hash,
            "event_bytes_before_recovery_sha256": before["event_bytes_sha256"],
            "event_bytes_after_recovery_sha256": after_retry["event_bytes_sha256"],
            "event_bytes_unchanged_through_retry": before["event_bytes"] == after_retry["event_bytes"],
            "reservation_count_before_recovery": before["reservation_count"],
            "reservation_count_after_recovery": after_retry["reservation_count"],
            "dispatch_count_before_recovery": before["dispatch_count"],
            "dispatch_count_after_recovery": after_retry["dispatch_count"],
            "budget_admitted_before": before["budget_admitted"],
            "budget_admitted_after": after_retry["budget_admitted"],
            "budget_refund_count": 0,
            "recovered_execution": after_retry["known_execution"],
            "real_model_dispatch_count": boundary["real_model_dispatch_count"],
            "original_receipt_copy_verified": original_copy_verified,
            "original_receipt_copy_directions": copy_directions,
            "no_redispatch": before["dispatch_count"] == after_retry["dispatch_count"] == 1,
            "recovery_request": {"turn_id": turn_id,
                                  "idempotency_key_sha256": _sha(turn_key.encode("ascii"))},
            "wrong_role_response": {"status": wrong_role_status, "body_sha256": _sha(wrong_role_body)},
            "wrong_key_response": {"status": wrong_key_status, "body_sha256": _sha(wrong_key_body)},
            "early_floor_response": {"status": early_status, "body_sha256": _sha(early_body)},
            "containers_cleaned_up_after_close": False,
        })
        return report
    finally:
        await service.shutdown()


def _recovery_child_main(args) -> int:
    try:
        result = asyncio.run(_recovery_child_async(args))
        # The public summary has no request text, model reply, signatures, or keys.
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        return 0
    except BaseException as exc:
        code = str(exc)
        safe_code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{3,95}", code) else "CHILD_FAILURE"
        sys.stderr.write(json.dumps({"error_type": type(exc).__name__, "error_code": safe_code}) + "\n")
        sys.stderr.flush()
        return 1


def _child_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--service-grant", required=True, type=Path)
    parser.add_argument("--authority-public-key", required=True, type=Path)
    parser.add_argument("--authority-directory", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--corpus-receipt", required=True, type=Path)
    parser.add_argument("--corpus-keys", required=True, type=Path)
    parser.add_argument("--offline-python", required=True, type=Path)


def _wait_for_line(reader_queue: queue.Queue, timeout: float) -> bytes:
    try:
        value = reader_queue.get(timeout=timeout)
    except queue.Empty:
        raise TimeoutError("CHILD_BOUNDARY_TIMEOUT") from None
    if value is None:
        raise RuntimeError("CHILD_EXITED_BEFORE_BOUNDARY")
    return value


def _wait_for_boundary_line(reader_queue: queue.Queue, boundary_file: Path,
                            timeout: float) -> bytes:
    failure_file = boundary_file.with_name("boundary-failure.json")
    deadline = time.monotonic() + timeout
    while True:
        if failure_file.is_file():
            failure = json.loads(failure_file.read_bytes())
            code = failure.get("error_code")
            if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{3,95}", code):
                code = "INTERNAL_FAILURE"
            raise RuntimeError("CRASH_BOUNDARY_REJECTED_" + code)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("CHILD_BOUNDARY_TIMEOUT") from None
        try:
            value = reader_queue.get(timeout=min(0.25, remaining))
        except queue.Empty:
            continue
        if value is None:
            raise RuntimeError("CHILD_EXITED_BEFORE_BOUNDARY")
        return value


def _process_exited(pid: int) -> bool:
    """Inspect a process without signaling it (signal zero terminates on Windows)."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE only
        if not handle:
            if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: no such PID
                return True
            raise RuntimeError("PROCESS_STATUS_UNAVAILABLE")
        try:
            state = kernel.WaitForSingleObject(handle, 0)
            if state not in {0, 258}:  # WAIT_OBJECT_0 / WAIT_TIMEOUT
                raise RuntimeError("PROCESS_STATUS_UNAVAILABLE")
            return state == 0
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def _child_python(env: dict[str, str]) -> str:
    """Keep the venv while bypassing its Windows redirector for exact PID control."""
    if os.name == "nt":
        env["__PYVENV_LAUNCHER__"] = sys.executable
        return sys._base_executable
    return sys.executable


def _anchor_shutdown(boundary: dict[str, Any], case_root: Path, authorities: dict[str, Any],
                     recovery_directory: Path, output_dir: Path, case: str) -> dict[str, Any]:
    from arena.recovery.client import RecoveryAnchorClient
    anchor = authorities["anchor"]
    tls = case_root / "tls"
    # The service uses this exact private key path and these exact mTLS identities.
    # The path and port are supplied by the process that owned the listener.
    cert = tls / "client-recorder.pem"
    private = tls / "client-recorder.key"
    ca = tls / "ca.pem"
    client = RecoveryAnchorClient(
        "127.0.0.1", boundary["anchor_port"], ca, cert, private,
        anchor["public_key_bytes"], anchor["key_id"], anchor["authority_id"],
    )
    started, start_ns = _utc(), time.monotonic_ns()
    client.health()
    client.shutdown()
    deadline = time.monotonic() + 5
    pid = boundary["anchor_pid"]
    while time.monotonic() < deadline:
        if _process_exited(pid):
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("ORPHAN_ANCHOR_SHUTDOWN_NOT_CONFIRMED")
    anchor_db = recovery_directory / "anchor-data" / "anchor.sqlite3"
    if not anchor_db.is_file():
        raise RuntimeError("EXTERNAL_ANCHOR_LEDGER_NOT_FOUND_AFTER_SHUTDOWN")
    record = {
        "operation": "mTLS_SHUTDOWN_EXACT_OWNED_ANCHOR",
        "endpoint": f"127.0.0.1:{boundary['anchor_port']}",
        "client_identity": "client-recorder",
        "child_anchor_pid": pid,
        "started_at_utc": started,
        "duration_ns": time.monotonic_ns() - start_ns,
        "process_exit_observed": True,
        "ledger_sha256_after_shutdown": _file_sha(anchor_db),
    }
    _write_json(output_dir / (case + "-anchor-shutdown.json"), record)
    return record


def _cleanup_failed_crash_case(case_dir: Path, meta: dict[str, Any], child_pid: int,
                               ready: dict[str, Any] | None, case: str) -> None:
    """Clean only resources bound to this failed child; preserve the original failure."""
    report = {"case": case, "removed_cell_ids": [], "errors": []}
    try:
        boundary_file = case_dir / "boundary.json"
        boundary = json.loads(boundary_file.read_bytes()) if boundary_file.is_file() else None
        owner = boundary or ready
        if (not isinstance(owner, dict) or owner.get("child_pid") != child_pid
                or owner.get("profile_sha256") != meta["profile_sha256"]):
            raise RuntimeError("FAILED_CHILD_RESOURCE_BINDING_UNAVAILABLE")
        if not _process_exited(owner["anchor_pid"]):
            _anchor_shutdown(owner, case_dir / "store", meta["authorities"],
                             meta["recovery_directory"], case_dir, case)
        if boundary is not None:
            if boundary.get("source_commit") != meta["source_commit"]:
                raise RuntimeError("FAILED_CHILD_SOURCE_BINDING_MISMATCH")
            listed = subprocess.check_output(
                ["docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}"],
                text=True, timeout=15,
            ).splitlines()
            owned = []
            for cell_id in boundary.get("cell_ids", []):
                if not isinstance(cell_id, str) or not re.fullmatch(r"[0-9a-f]{64}", cell_id):
                    raise RuntimeError("FAILED_CHILD_CELL_ID_INVALID")
                if cell_id not in listed:
                    continue
                observed = json.loads(subprocess.check_output(
                    ["docker", "inspect", cell_id], text=True, timeout=15,
                ))[0]
                if (observed["Id"] != cell_id or observed["Image"] != meta["model_image_id"]
                        or observed["Config"].get("Labels", {}).get("arena.n04") != "true"
                        or not observed["Name"].startswith("/arena-prototype-model-")):
                    raise RuntimeError("FAILED_CHILD_CELL_OWNERSHIP_MISMATCH")
                owned.append(cell_id)
            if owned:
                subprocess.run(["docker", "rm", "--force", *owned], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            report["removed_cell_ids"] = owned
    except BaseException as exc:
        code = str(exc)
        report["errors"].append(code if re.fullmatch(r"[A-Z][A-Z0-9_]{3,95}", code)
                                else type(exc).__name__)
    _write_json(case_dir / "failed-run-cleanup.json", report)


def _spawn_crash_case(args, case: str, case_dir: Path, meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    env = os.environ.copy()
    command = [_child_python(env), str(Path(__file__).resolve()), "--internal-initial", "--execute-real",
               "--case", case, "--case-root", str(case_dir / "store"),
               "--boundary-file", str(case_dir / "boundary.json"),
               "--source-commit", meta["source_commit"]]
    for name in ("profile", "service_grant", "authority_public_key", "authority_directory",
                 "model", "corpus", "corpus_receipt", "corpus_keys", "offline_python"):
        command.extend(["--" + name.replace("_", "-"), str(getattr(args, name))])
    env["PYTHONPATH"] = str(BACKEND / "src") + os.pathsep + env.get("PYTHONPATH", "")
    stdout_file = case_dir / "service-child.stdout.jsonl"
    stderr_file = case_dir / "service-child.stderr.log"
    started, start_ns = _utc(), time.monotonic_ns()
    with stdout_file.open("wb") as stdout_stream, stderr_file.open("wb") as stderr_stream:
        process = subprocess.Popen(command, cwd=BACKEND, env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=stderr_stream, close_fds=True)
        lines: queue.Queue = queue.Queue()
        def pump_stdout():
            try:
                assert process.stdout is not None
                for line in iter(process.stdout.readline, b""):
                    lines.put(line)
            finally:
                lines.put(None)
        reader = threading.Thread(target=pump_stdout, daemon=True)
        reader.start()
        ready = None
        boundary = None
        try:
            deadline = 300
            while ready is None:
                line = _wait_for_line(lines, deadline)
                stdout_stream.write(line)
                value = json.loads(line)
                if value.get("event") == "SERVICE_READY":
                    ready = value
                else:
                    raise RuntimeError("SERVICE_READY_METADATA_INVALID")
            line = _wait_for_boundary_line(lines, case_dir / "boundary.json", 300)
            stdout_stream.write(line)
            marker = json.loads(line)
            if marker.get("event") != "BOUNDARY" or marker.get("case") != case:
                raise RuntimeError("CRASH_BOUNDARY_METADATA_INVALID")
            boundary = json.loads((case_dir / "boundary.json").read_bytes())
            if (boundary.get("event") != "BOUNDARY" or boundary.get("case") != case
                    or marker.get("turn_id") != boundary.get("turn_id")
                    or marker.get("boundary") != boundary.get("boundary")):
                raise RuntimeError("PRIVATE_CRASH_BOUNDARY_BINDING_MISMATCH")
        except BaseException:
            if process.poll() is None:
                if not (case_dir / "boundary.json").is_file():
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        pass
                if process.poll() is None:
                    process.terminate()
            process.wait(timeout=10)
            reader.join(timeout=2)
            if process.stdout:
                process.stdout.close()
            _cleanup_failed_crash_case(case_dir, meta, process.pid, ready, case)
            raise
        # This is an OS process kill, not SIGINT, a Python exception, or service shutdown.
        process.terminate()
        process.wait(timeout=10)
        reader.join(timeout=2)
        if process.stdout:
            process.stdout.close()
        stdout_stream.flush()
    process_record = {
        "argv": command,
        "started_at_utc": started,
        "duration_ns": time.monotonic_ns() - start_ns,
        "child_pid": process.pid,
        "return_code_after_forced_termination": process.returncode,
        "forced_termination": True,
        "process_death_observed": process.poll() is not None,
        "graceful_service_shutdown_called": False,
        "stdout_sha256": _file_sha(stdout_file),
        "stderr_sha256": _file_sha(stderr_file),
        "stdout_path": stdout_file.name,
        "stderr_path": stderr_file.name,
        "ready": {key: value for key, value in ready.items() if key not in {"service_port", "anchor_port"}},
        "boundary": boundary,
    }
    if not process_record["process_death_observed"] or boundary["child_pid"] != process.pid:
        raise RuntimeError("SERVICE_PROCESS_DEATH_NOT_PROVEN")
    _write_json(case_dir / "process-boundary.json", process_record)
    anchor_record = _anchor_shutdown(
        boundary, case_dir / "store", meta["authorities"],
        meta["recovery_directory"], case_dir, case,
    )
    return process_record, anchor_record


def _spawn_recovery_case(args, case: str, case_dir: Path, meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    env = os.environ.copy()
    command = [_child_python(env), str(Path(__file__).resolve()), "--internal-recovery",
               "--execute-real", "--case", case,
               "--case-root", str(case_dir / "store"),
               "--boundary-file", str(case_dir / "boundary.json")]
    for name in ("profile", "service_grant", "authority_public_key", "authority_directory",
                 "model", "corpus", "corpus_receipt", "corpus_keys", "offline_python"):
        command.extend(["--" + name.replace("_", "-"), str(getattr(args, name))])
    env["PYTHONPATH"] = str(BACKEND / "src") + os.pathsep + env.get("PYTHONPATH", "")
    record = _run_logged(command, cwd=BACKEND, env=env, timeout=240,
                         output_dir=case_dir, name="recovery-child")
    if record["exit_code"] != 0:
        raise RuntimeError("RECOVERY_CHILD_FAILED")
    stdout_path = case_dir / record["stdout_path"]
    result = json.loads(stdout_path.read_bytes())
    if result.get("model_started") is not False or result.get("workers_started") is not False:
        raise RuntimeError("RECOVERY_CHILD_STARTED_MODEL_OR_WORKERS")
    _write_json(case_dir / "recovery-summary.json", result)
    return record, result


def _base_offline_args(bundle: Path, context: dict[str, Any], manifest_digest: str,
                       args, meta: dict[str, Any]) -> list[str]:
    from arena.contracts.crypto import canonical_bytes
    from arena.integration.controller import ACTOR
    from arena.prototype.admission import authority_public
    from cryptography.hazmat.primitives import serialization
    recorder_public = authority_public("recorder")
    witness_public = authority_public("witness")
    return [
        str(meta["offline_python"]), "-m", "arena.verifier.cli",
        "--bundle", str(bundle),
        "--recorder-key", recorder_public.hex(), "--recorder-key-id", "n08-prototype-recorder-001",
        "--witness-key", witness_public.hex(), "--witness-key-id", "n08-prototype-witness-001",
        "--domain-id", context["domain_id"], "--experiment-id", context["experiment_id"],
        "--epoch", str(context["epoch"]), "--manifest-digest", manifest_digest,
        "--defense-mode", "INPUT", "--broker-actor", ACTOR,
    ]


def _verify_valid(args, case_dir: Path, result: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    from arena.contracts.crypto import canonical_bytes
    authorities = meta["authorities"]
    from arena.prototype.admission import authority_public
    recorder = authority_public("recorder")
    command = _base_offline_args(
        Path(result["valid_evidence"]["path"]), result["recovery_context"],
        result["public_manifest_digest"], args, meta,
    ) + [
        "--anchor-records", result["valid_evidence"]["anchor_records_path"],
        "--anchor-key", authorities["anchor"]["public_key_bytes"].hex(),
        "--anchor-key-id", authorities["anchor"]["key_id"],
        "--anchor-authority-id", authorities["anchor"]["authority_id"],
        "--recovery-key", authorities["recovery"]["public_key_bytes"].hex(),
        "--recovery-key-id", authorities["recovery"]["key_id"],
        "--recovery-authority-id", authorities["recovery"]["authority_id"],
        "--keys-json", result["valid_evidence"]["replay_keys_path"],
        "--require-transport-profile",
        "--transport-profile-key", recorder.hex(),
        "--transport-profile-key-id", "n08-prototype-recorder-001",
        "--feedback-policy-key", recorder.hex(),
        "--feedback-policy-key-id", "n08-prototype-recorder-001",
    ]
    record = _run_logged(command, cwd=BACKEND, env=None, timeout=90,
                         output_dir=case_dir, name="valid-offline-verifier")
    output = json.loads((case_dir / record["stdout_path"]).read_bytes())
    if record["exit_code"] != 0 or output.get("status") != "PASS_RECONCILED_EVIDENCE":
        raise RuntimeError("VALID_RECONCILED_OFFLINE_VERIFIER_FAILED")
    if (output.get("integrity_status") != "VALID_WITHIN_PROFILE"
            or output.get("participant_release_authorized") is not False):
        raise RuntimeError("VALID_RECONCILED_VERIFIER_SCOPE_MISMATCH")
    _write_json(case_dir / "reconciled-verifier.json", output)
    return {"command": record, "status": output["status"], "exit_code": record["exit_code"],
            "integrity_status": output["integrity_status"],
            "participant_release_authorized": output["participant_release_authorized"],
            "stdout_sha256": record["stdout_sha256"], "stderr_sha256": record["stderr_sha256"]}


def _verify_invalid(args, case_dir: Path, result: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    authorities = meta["authorities"]
    from arena.prototype.admission import authority_public
    command = _base_offline_args(
        Path(result["invalid_evidence"]["path"]), result["recovery_context"],
        result["public_manifest_digest"], args, meta,
    ) + [
        "--invalid-export-key", authorities["invalid_export"]["public_key_bytes"].hex(),
        "--invalid-export-key-id", authorities["invalid_export"]["key_id"],
        "--anchor-key", authorities["anchor"]["public_key_bytes"].hex(),
        "--anchor-key-id", authorities["anchor"]["key_id"],
        "--recovery-key", authorities["recovery"]["public_key_bytes"].hex(),
        "--recovery-key-id", authorities["recovery"]["key_id"],
    ]
    record = _run_logged(command, cwd=BACKEND, env=None, timeout=90,
                         output_dir=case_dir, name="invalid-offline-verifier")
    stdout_path = case_dir / record["stdout_path"]
    stderr_path = case_dir / record["stderr_path"]
    content = stdout_path.read_bytes() or stderr_path.read_bytes()
    output = json.loads(content)
    if record["exit_code"] != 2 or output.get("status") != "AUTHENTIC_INVALID_INCOMPLETE":
        raise RuntimeError("INVALID_EVIDENCE_OFFLINE_VERIFICATION_FAILED")
    if (output.get("integrity_status") != "INVALID"
            or output.get("participant_release_authorized") is not False):
        raise RuntimeError("INVALID_VERIFIER_SCOPE_MISMATCH")
    _write_json(case_dir / "invalid-verifier.json", output)
    return {"command": record, "status": output["status"], "exit_code": record["exit_code"],
            "integrity_status": output["integrity_status"],
            "participant_release_authorized": output["participant_release_authorized"],
            "stdout_sha256": record["stdout_sha256"], "stderr_sha256": record["stderr_sha256"]}


def _run_unknown_control(args, output_dir: Path) -> dict[str, Any]:
    """Run a focused, explicitly synthetic no-model unknown-execution control."""
    command = [
        str(args.offline_python.resolve()), "-m", "pytest", "-q",
        "tests/integration/test_feedback_recovery.py::test_synthetic_orphan_recovery_persists_stable_separately_signed_replay[unknown_execution]",
    ]
    record = _run_logged(command, cwd=BACKEND, env=None, timeout=240,
                         output_dir=output_dir, name="unknown-execution-synthetic-control")
    if record["exit_code"] != 0:
        raise RuntimeError("UNKNOWN_EXECUTION_SYNTHETIC_CONTROL_FAILED")
    return {"scope": "SYNTHETIC_NO_MODEL_DISPATCH", "refusal_verified": True,
            "refusal_code": "FEEDBACK_RECOVERY_EXECUTION_UNKNOWN", "command": record}


def _public_evidence_prefix(value: str) -> str:
    from pathlib import PurePosixPath
    normalized = PurePosixPath(value.replace("\\", "/"))
    root = PurePosixPath("memory files/hackathon/evidence")
    if (normalized.is_absolute() or not normalized.is_relative_to(root)
            or normalized == root or any(part in {".", ".."} for part in normalized.parts)):
        raise ValueError("PUBLIC_EVIDENCE_PREFIX_OUTSIDE_CANONICAL_EVIDENCE_ROOT")
    return normalized.as_posix()


def _write_public_copy_source(output: Path, public_prefix: str, relative_path: str,
                              value: Any, copy_manifest: list[dict[str, Any]]) -> dict[str, Any]:
    source = output / "public-evidence-copy" / relative_path
    _write_json(source, value)
    destination = f"{public_prefix}/{relative_path.replace(os.sep, '/')}"
    digest = _file_sha(source)
    copy_manifest.append({"destination": destination,
                          "source_path": source.relative_to(output).as_posix(),
                          "sha256": digest})
    return {"output_path": destination, "output_sha256": digest}


def _add_log_copy_sources(output: Path, public_prefix: str, commands: list[dict[str, Any]],
                          copy_manifest: list[dict[str, Any]]) -> None:
    seen = set()
    for item in commands:
        case = item.get("case")
        base = output / "cases" / case if case in {"orphan", "original-receipt"} else output
        for field in ("stdout_path", "stderr_path"):
            relative = item.get(field)
            if not isinstance(relative, str):
                continue
            source = base / relative
            if not source.is_file() or source.is_symlink():
                continue
            source_relative = source.relative_to(output).as_posix()
            if source_relative in seen:
                continue
            seen.add(source_relative)
            destination = f"{public_prefix}/logs/{source_relative}"
            copy_manifest.append({"destination": destination,
                                  "source_path": source_relative,
                                  "sha256": _file_sha(source)})


async def _collect(args) -> dict[str, Any]:
    from arena.contracts.crypto import canonical_bytes
    from arena.prototype.admission import key_from_file
    from arena.recovery.anchor import load_recovery_authorities
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    meta = _preflight(args)
    public_prefix = _public_evidence_prefix(args.public_evidence_prefix)
    public_root = REPO.joinpath(*public_prefix.split("/"))
    if public_root.exists() or public_root.is_symlink():
        raise RuntimeError("PUBLIC_EVIDENCE_PREFIX_ALREADY_EXISTS")
    output = _ensure_private_artifact_dir(args.output)
    output.mkdir(parents=True, exist_ok=False)
    case_dirs = {case: output / "cases" / case for case in ("orphan", "original-receipt")}
    for directory in case_dirs.values():
        directory.mkdir(parents=True, exist_ok=False)
    commands: list[dict[str, Any]] = []
    run_started_at_utc = _utc()
    run_started_ns = time.monotonic_ns()
    case_receipts: list[dict[str, Any]] = []
    recovered_by_case: dict[str, dict[str, Any]] = {}
    aggregate_before_dispatch = 0
    aggregate_after_dispatch = 0
    aggregate_before_budget = 0
    aggregate_after_budget = 0
    real_model_dispatches = 0
    invalid_refusal_code = None
    original_copy_verified = False
    containers_cleaned = True
    process_death = True
    startup_recovery_only = True
    valid_verifier_passed = False
    invalid_verifier_passed = False
    invalidity_preserved = False
    per_case_process = {}

    for case in ("orphan", "original-receipt"):
        case_dir = case_dirs[case]
        process_record, anchor_shutdown = _spawn_crash_case(args, case, case_dir, meta)
        per_case_process[case] = process_record
        commands.append({"case": case, "stage": "service-process", **{
            key: process_record[key] for key in (
                "argv", "started_at_utc", "duration_ns", "return_code_after_forced_termination",
                "forced_termination", "stdout_sha256", "stderr_sha256", "stdout_path", "stderr_path",
            )
        }})
        _write_json(case_dir / "boundary.json", process_record["boundary"])
        process_death = process_death and process_record["process_death_observed"]
        commands.append({"case": case, "stage": "anchor-mtls-shutdown", **anchor_shutdown})

        recovery_command, recovered = _spawn_recovery_case(args, case, case_dir, meta)
        commands.append({"case": case, "stage": "recovery-process", **recovery_command})
        if recovered.get("startup_action") not in {"RECONCILE_ORPHAN", "REPLAY_STORED_RECOVERY"}:
            raise RuntimeError("RECOVERY_STARTUP_ACTION_MISMATCH")
        recovered_by_case[case] = recovered
        startup_recovery_only = startup_recovery_only and recovered.get("startup_recovery_only") is True
        real_model_dispatches += recovered["real_model_dispatch_count"]
        aggregate_before_dispatch += recovered["dispatch_count_before_recovery"]
        aggregate_after_dispatch += recovered["dispatch_count_after_recovery"]
        aggregate_before_budget += recovered["budget_admitted_before"]
        aggregate_after_budget += recovered["budget_admitted_after"]
        invalid_refusal_code = recovered.get("invalid_recovery_refusal_code") or invalid_refusal_code
        if case == "original-receipt":
            original_copy_verified = recovered.get("original_receipt_copy_verified") is True
            invalidity_preserved = recovered.get("invalidity_preserved") is True
            if recovered.get("original_receipt_copy_directions") != ["RECORDER_TO_BROKER", "BROKER_TO_RECORDER"]:
                raise RuntimeError("ORIGINAL_RECEIPT_COPY_DIRECTION_COVERAGE_INCOMPLETE")
            verifier = _verify_invalid(args, case_dir, recovered, meta)
            invalid_verifier_passed = verifier["status"] == "AUTHENTIC_INVALID_INCOMPLETE" and verifier["exit_code"] == 2
        else:
            verifier = _verify_valid(args, case_dir, recovered, meta)
            valid_verifier_passed = verifier["status"] == "PASS_RECONCILED_EVIDENCE" and verifier["exit_code"] == 0

        commands.append({"case": case, "stage": "offline-verifier", **verifier["command"]})

        ids = process_record["boundary"]["cell_ids"]
        listing_command = ["docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}"]
        listing_record = _run_logged(listing_command, cwd=BACKEND, env=None, timeout=30,
                                     output_dir=case_dir, name="container-cleanup-check")
        if listing_record["exit_code"] != 0:
            raise RuntimeError("DOCKER_CONTAINER_CLEANUP_CHECK_FAILED")
        listed = (case_dir / listing_record["stdout_path"]).read_text(encoding="ascii").splitlines()
        case_clean = not set(ids).intersection(listed)
        containers_cleaned = containers_cleaned and case_clean
        commands.append({"case": case, "stage": "container-cleanup-check", **listing_record,
                         "old_cell_ids_absent": case_clean})
        if not case_clean:
            raise RuntimeError("OLD_MODEL_CONTAINERS_REMAIN_AFTER_RECOVERY_CLOSE")

        case_record = {
            "case": case,
            "boundary": process_record["boundary"]["boundary"],
            "child_pid": process_record["child_pid"],
            "service_child_forced_exit_code": process_record["return_code_after_forced_termination"],
            "process_death_observed": process_record["process_death_observed"],
            "startup_action": recovered["startup_action"],
            "startup_model_started": recovered["model_started"],
            "startup_workers_started": recovered["workers_started"],
            "real_model_dispatch_count": recovered["real_model_dispatch_count"],
            "dispatch_count_before_recovery": recovered["dispatch_count_before_recovery"],
            "dispatch_count_after_recovery": recovered["dispatch_count_after_recovery"],
            "reservation_count_before_recovery": recovered["reservation_count_before_recovery"],
            "reservation_count_after_recovery": recovered["reservation_count_after_recovery"],
            "budget_admitted_before": recovered["budget_admitted_before"],
            "budget_admitted_after": recovered["budget_admitted_after"],
            "retry_identical": recovered["retry_identical"],
            "event_bytes_unchanged_through_retry": recovered["event_bytes_unchanged_through_retry"],
            "containers_cleaned_up": case_clean,
            "recovery_summary_sha256": _file_sha(case_dir / "recovery-summary.json"),
            "offline_verification": {key: verifier[key] for key in (
                "status", "exit_code", "integrity_status", "participant_release_authorized",
                "stdout_sha256", "stderr_sha256",
            )},
        }
        if case == "original-receipt":
            case_record.update({
                "original_receipt_copy_verified": recovered["original_receipt_copy_verified"],
                "original_receipt_copy_directions": recovered["original_receipt_copy_directions"],
                "invalid_recovery_refused": recovered["invalid_evidence"]["recovery_refusal"]["status"] != 200,
                "invalidity_preserved": recovered["invalidity_preserved"],
                "invalid_close_integrity": recovered["invalid_close_integrity"],
                "invalid_recovery_refusal_code": recovered["invalid_recovery_refusal_code"],
            })
        case_receipts.append(case_record)
        _write_json(case_dir / "case-metadata.json", case_record)

    unknown_control = _run_unknown_control(args, output)
    commands.append({"stage": "unknown-execution-control", **unknown_control["command"]})
    _write_json(output / "unknown-execution-control.json", {
        "scope": unknown_control["scope"],
        "refusal_verified": unknown_control["refusal_verified"],
        "refusal_code": unknown_control["refusal_code"],
        "command": unknown_control["command"],
    })
    if not (
        process_death and startup_recovery_only and original_copy_verified and valid_verifier_passed
        and invalid_verifier_passed and invalidity_preserved and containers_cleaned
        and real_model_dispatches == 2 and aggregate_before_dispatch == aggregate_after_dispatch == 2
        and aggregate_before_budget == aggregate_after_budget == 2
        and unknown_control["refusal_verified"]
    ):
        raise RuntimeError("STEP5_RECOVERY_ACCEPTANCE_INCOMPLETE")

    owner_key = _read_credential_key(meta["authority_directory"])
    recorder_public = owner_key.public_key().public_bytes_raw()
    from arena.prototype.admission import authority_public
    if recorder_public != authority_public("recorder"):
        raise RuntimeError("STEP5_RECEIPT_SIGNER_MISMATCH")
    if invalid_refusal_code not in {
        "FEEDBACK_RECOVERY_NOT_ELIGIBLE", "FEEDBACK_RECOVERY_PRIOR_INVALIDITY",
        "FEEDBACK_RECOVERY_ORIGINAL_RECEIPT_INVALID",
    }:
        raise RuntimeError("INVALID_RECOVERY_REFUSAL_CODE_UNEXPECTED")
    startup_actions = {case["startup_action"] for case in case_receipts}
    if len(startup_actions) != 1:
        raise RuntimeError("RECOVERY_STARTUP_ACTIONS_INCONSISTENT")
    copy_manifest: list[dict[str, Any]] = []
    case_metadata_entries = {}
    for case_record in case_receipts:
        case = case_record["case"]
        case_metadata_entries[case] = _write_public_copy_source(
            output, public_prefix, f"case-{case}.json", case_record, copy_manifest
        )

    reconciled_output = json.loads((case_dirs["orphan"] / "reconciled-verifier.json").read_bytes())
    invalid_output = json.loads((case_dirs["original-receipt"] / "invalid-verifier.json").read_bytes())
    reconciled_entry = _write_public_copy_source(
        output, public_prefix, "reconciled-verifier.json", reconciled_output, copy_manifest
    )
    invalid_entry = _write_public_copy_source(
        output, public_prefix, "invalid-verifier.json", invalid_output, copy_manifest
    )

    original_receipt_sha256 = per_case_process["original-receipt"]["boundary"].get("receipt_sha256")
    if not isinstance(original_receipt_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", original_receipt_sha256):
        raise RuntimeError("ORIGINAL_RECEIPT_COPY_SOURCE_DIGEST_MISSING")
    controls = {}
    control_payloads = {
        "receipt_copy_recorder_to_broker": {
            "result": "PASS", "provenance": "REAL_RECORDER_AUTHORIZATION",
            "source_receipt_sha256": original_receipt_sha256,
            "real_model_dispatches_during_control": 0,
        },
        "receipt_copy_broker_to_recorder": {
            "result": "PASS", "provenance": "REAL_BROKER_PROJECTION_AFTER_RECORDER_AUTH_LOSS",
            "source_receipt_sha256": original_receipt_sha256,
            "real_model_dispatches_during_control": 0,
        },
        "unknown_execution": {
            "result": "REFUSED", "provenance": "FOCUSED_INTEGRATION_NEGATIVE_CONTROL",
            "refusal_code": "FEEDBACK_RECOVERY_EXECUTION_UNKNOWN",
            "real_model_dispatches_during_control": 0,
            "command_argv": unknown_control["command"]["argv"],
            "command_exit_code": unknown_control["command"]["exit_code"],
            "command_stdout_sha256": unknown_control["command"]["stdout_sha256"],
            "command_stderr_sha256": unknown_control["command"]["stderr_sha256"],
        },
        "invalid_recovery": {
            "result": "REFUSED", "provenance": "REAL_INVALIDITY_EVENT",
            "refusal_code": invalid_refusal_code,
            "integrity_before": "INVALID", "integrity_after": "INVALID",
            "real_model_dispatches_during_control": 0,
        },
    }
    for name, payload in control_payloads.items():
        exported = _write_public_copy_source(
            output, public_prefix, f"controls/{name}.json", payload, copy_manifest
        )
        controls[name] = {**payload, **exported}

    commands_record = {
        "invocation": {"argv": sys.argv, "started_at_utc": run_started_at_utc,
                       "duration_ns": time.monotonic_ns() - run_started_ns},
        "commands": commands,
    }
    commands_entry = _write_public_copy_source(
        output, public_prefix, "commands.json", commands_record, copy_manifest
    )
    _add_log_copy_sources(output, public_prefix, commands, copy_manifest)
    _write_json(output / "evidence-copy-manifest.json", copy_manifest)

    receipt = {
        "schema_version": "arena.prototype-step5-recovery.v1",
        "result": "PASS_STEP5_RECOVERY",
        "scope": "CURRENT_QWEN_LOCAL_STEP5_CRASH_RECOVERY_ONLY",
        "authority": "OWNER-DELEGATED SELF-ATTESTED PROTOTYPE-SCOPE",
        "source_commit": meta["source_commit"],
        "profile_sha256": meta["profile_sha256"],
        "service_grant_sha256": meta["service_grant_sha256"],
        "source_sha256": meta["source_sha256"],
        "public_evidence_prefix": public_prefix,
        "recovery_output_path": f"{public_prefix}/recovery.json",
        "model_image_id": meta["model_image_id"],
        "started_at_utc": _utc(),
        "environment": {"runtime": "python", "version": platform.python_version(),
                         "platform": platform.platform()},
        "real_model_dispatch_count": real_model_dispatches,
        "dispatch_count_before_recovery": aggregate_before_dispatch,
        "dispatch_count_after_recovery": aggregate_after_dispatch,
        "reservation_count_before_recovery": sum(case["reservation_count_before_recovery"] for case in case_receipts),
        "reservation_count_after_recovery": sum(case["reservation_count_after_recovery"] for case in case_receipts),
        "budget_admitted_before": aggregate_before_budget,
        "budget_admitted_after": aggregate_after_budget,
        "budget_refund_count": 0,
        "process_death_observed": process_death,
        "startup_recovery_only": startup_recovery_only,
        "original_receipt_copy_verified": original_copy_verified,
        "valid_reconciled_verification_passed": valid_verifier_passed,
        "invalid_recovery_refused": (
            invalid_verifier_passed and invalidity_preserved and bool(invalid_refusal_code)
        ),
        "invalidity_preserved": invalidity_preserved,
        "invalid_close_integrity": "INVALID",
        "invalid_recovery_refusal_code": invalid_refusal_code,
        "containers_cleaned_up": containers_cleaned,
        "no_redispatch": aggregate_before_dispatch == aggregate_after_dispatch,
        "recovered_execution": "EXECUTED",
        "startup_action": next(iter(startup_actions)),
        "original_receipt_copy_directions": ["RECORDER_TO_BROKER", "BROKER_TO_RECORDER"],
        "unknown_execution_recovery_refused": unknown_control["refusal_verified"],
        "unknown_execution_control_scope": unknown_control["scope"],
        "full_t_p_acceptance": False,
        "normal_cold_worker_resume_authorized": False,
        "controls": controls,
        "per_case_metadata": [
            {"path": case_metadata_entries[case["case"]]["output_path"],
             "sha256": case_metadata_entries[case["case"]]["output_sha256"]}
            for case in case_receipts
        ],
        "reconciled_verifier": reconciled_entry,
        "invalid_verifier": invalid_entry,
        "commands_path": commands_entry["output_path"],
        "commands_sha256": commands_entry["output_sha256"],
        "evidence_copy_manifest_path": "evidence-copy-manifest.json",
        "evidence_copy_manifest_sha256": _file_sha(output / "evidence-copy-manifest.json"),
    }
    signature = owner_key.sign(b"arena.prototype/step5-recovery\0" + canonical_bytes(receipt)).hex()
    envelope = {"receipt": receipt, "signature": signature}
    _write_json(output / "recovery.json", envelope)
    _write_json(output / "run-summary.json", {
        "result": receipt["result"],
        "recovery_receipt_sha256": _file_sha(output / "recovery.json"),
        "output_directory": str(output),
    })
    return {"result": receipt["result"], "recovery_receipt_sha256": _file_sha(output / "recovery.json"),
            "output_directory": str(output),
            "recovery_output_path": receipt["recovery_output_path"],
            "evidence_copy_manifest": str(output / "evidence-copy-manifest.json")}


def _plan() -> dict[str, Any]:
    return {
        "scope": "CURRENT_QWEN_LOCAL_STEP5_CRASH_RECOVERY_ONLY",
        "model_starts": False,
        "cases": [
            {"case": "orphan", "boundary": "after anchored FEEDBACK_AUTHORIZED before arena receipt"},
            {"case": "original-receipt", "boundary": "after recorder authorize_bound_turn commit before broker projection"},
        ],
        "recovery": "new OS process via PrototypeService.open_existing_recovery; no model/worker/queue startup",
        "required_service_args": ["profile", "service-grant", "authority-public-key", "authority-directory", "model", "corpus", "corpus-receipt", "corpus-keys", "offline-python"],
        "outputs": ["signed recovery.json", "per-case metadata", "hashed stdout/stderr logs", "offline valid/invalid verification logs"],
        "controls": ["mTLS wrong role/key", "61-second floor refusal", "idempotent recovery", "no redispatch/refund", "synthetic UNKNOWN refusal"],
        "claim_limits": {"full_t_p_acceptance": False, "normal_cold_worker_resume_authorized": False},
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true", help="Print a dry plan; starts no process or model")
    parser.add_argument("--execute-real", action="store_true", help="Authorize the two real Qwen crash cases after current-grant preflight")
    parser.add_argument("--internal-initial", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--internal-recovery", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--case", choices=("orphan", "original-receipt"))
    parser.add_argument("--case-root", type=Path)
    parser.add_argument("--boundary-file", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--profile", type=Path, default=BACKEND / "infra/model-component/profile.json")
    parser.add_argument("--service-grant", type=Path, default=BACKEND / "artifacts/prototype-new/service.json")
    parser.add_argument("--authority-public-key", type=Path, default=BACKEND / "infra/prototype/admission-public.hex")
    parser.add_argument("--authority-directory", type=Path, required=False)
    parser.add_argument("--model", type=Path, default=BACKEND / "artifacts/n04-release-preparation/qwen2.5-0.5b-instruct-q4_k_m.gguf")
    parser.add_argument("--corpus", type=Path, default=BACKEND / "artifacts/public-corpus")
    parser.add_argument("--corpus-receipt", type=Path, default=BACKEND / "artifacts/public-corpus/corpus-receipt.json")
    parser.add_argument("--corpus-keys", type=Path, default=BACKEND / "artifacts/public-corpus/corpus-keys.json")
    parser.add_argument("--offline-python", type=Path, default=BACKEND / "artifacts/repro-env/Scripts/python.exe")
    parser.add_argument("--output", type=Path, default=BACKEND / "artifacts/step5-recovery-probe")
    parser.add_argument(
        "--public-evidence-prefix",
        default="memory files/hackathon/evidence/step5-recovery-20261026",
        help="Canonical future evidence destination; the probe writes privately and signs exact paths and hashes.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.plan:
        print(json.dumps(_plan(), indent=2))
        return 0
    if args.internal_initial or args.internal_recovery:
        if not args.execute_real or not all((args.case, args.case_root, args.boundary_file,
                                             args.authority_directory)):
            print(json.dumps({"status": "BLOCKED", "code": "INTERNAL_CHILD_ARGUMENTS_INVALID"}))
            return 2
        return _child_main(args) if args.internal_initial else _recovery_child_main(args)
    if not args.execute_real:
        print(json.dumps({"status": "BLOCKED", "code": "EXPLICIT_EXECUTE_REAL_REQUIRED",
                          "dry_plan": _plan()}, indent=2))
        return 2
    if args.authority_directory is None:
        print(json.dumps({"status": "BLOCKED", "code": "AUTHORITY_DIRECTORY_REQUIRED"}))
        return 2
    try:
        summary = asyncio.run(_collect(args))
        print(json.dumps(summary, sort_keys=True))
        return 0
    except BaseException as exc:
        # No exception message can carry a request, reply, or a key. The failure
        # code is coarse; full private details remain in child stderr artifacts.
        code = str(exc)
        safe_code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{3,95}", code) else "STEP5_PROBE_FAILED"
        print(json.dumps({"status": "INCOMPLETE", "error_type": type(exc).__name__,
                          "error_code": safe_code}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
