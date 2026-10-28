"""Read-only pre-admission consumer for an existing local prototype store."""

from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives import serialization

from arena.contracts.common import Context
from arena.contracts.crypto import (
    event_digest, validate_chain, verify, verify_checkpoint, verify_witness_close, witness_message,
)
from arena.contracts.evidence import (
    Checkpoint, Event, SignedCheckpoint, SignedWitnessClose, SignedWitnessStart,
    StartResponse, WitnessClose, WitnessStart,
)
from arena.contracts.jsonwire import load_wire
from arena.model_runtime import BACKEND

from .anchor import RecoveryAnchorError, load_recovery_authorities, verify_anchor_records
from .process import RecoveryAnchorProcess


RECORDER_KEY_ID = "n08-prototype-recorder-001"
WITNESS_KEY_ID = "n08-prototype-witness-001"


def _read_only(path: Path):
    if path.is_symlink() or not path.is_file():
        raise RecoveryAnchorError("STARTUP_STORE_MISSING_OR_UNSAFE")
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
    result = connection.execute("PRAGMA quick_check(1)").fetchone()
    if not result or result[0] != "ok":
        connection.close()
        raise RecoveryAnchorError("STARTUP_STORE_CORRUPT")
    return connection


def inspect_existing_prototype(
    root: Path, authority_directory: Path, *, allow_feedback_recovery: bool = False
) -> dict:
    """Compare protected stores to the external anchor before any runtime starts.

    This authenticates the snapshot but never authorizes workers or a model to
    resume. The only mutation allowed is completing an exact PREPARED anchor
    operation when its byte-identical event is already durable in the recorder.
    """
    root, authority_directory = Path(root), Path(authority_directory)
    if root.is_symlink() or not root.is_dir():
        raise RecoveryAnchorError("STARTUP_ROOT_MISSING_OR_UNSAFE")
    tls = root / "tls"
    authorities = load_recovery_authorities(BACKEND / "infra/prototype/recovery-authorities.json")
    recovery_dir = authority_directory.resolve().parent / "prototype-recovery"
    anchor_db = recovery_dir / "anchor-data" / "anchor.sqlite3"
    # An inspection must not initialize a new anchor beside an old protected
    # store; that would silently bless a rollback with a new empty watermark.
    marker = recovery_dir / "anchor-instance.json"
    if (marker.is_symlink() or not marker.is_file() or anchor_db.is_symlink()
            or not anchor_db.is_file()):
        raise RecoveryAnchorError("ANCHOR_LEDGER_MISSING_OR_UNSAFE")
    manager = RecoveryAnchorProcess(
        data_directory=anchor_db.parent,
        private_key_path=recovery_dir / (authorities["anchor"]["key_id"] + "-private.pem"),
        public_key=authorities["anchor"]["public_key_bytes"],
        authority_id=authorities["anchor"]["authority_id"], key_id=authorities["anchor"]["key_id"],
        ca=tls / "ca.pem", server_certificate=tls / "server.pem", server_private_key=tls / "server.key",
        recorder_certificate=tls / "client-recorder.pem", recorder_private_key=tls / "client-recorder.key",
    )
    client = manager.start(require_existing=True)
    try:
        jobs = []
        events = []
        stored_checkpoint = None
        recovery_turn_ids = []
        receipt_copy_turn_ids = []
        recovery_failure_turn_ids = []
        close_operation_state = None
        run_state = None
        with closing(_read_only(root / "broker.sqlite3")) as broker:
            experiments = broker.execute(
                "SELECT id,domain_id,epoch,phase,integrity,public_commitment FROM experiments"
            ).fetchall()
            if len(experiments) != 1:
                raise RecoveryAnchorError("STARTUP_EXPERIMENT_CARDINALITY_INVALID")
            run = experiments[0]
            context = Context(domain_id=run["domain_id"], experiment_id=run["id"], epoch=run["epoch"])
            table_names = {row[0] for row in broker.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            if "prototype_operations" in table_names:
                operation_columns = {row[1] for row in broker.execute(
                    "PRAGMA table_info(prototype_operations)"
                )}
                if not {"experiment_id", "action", "state"}.issubset(operation_columns):
                    raise RecoveryAnchorError("STARTUP_OPERATION_SCHEMA_INVALID")
                operation = broker.execute(
                    "SELECT state FROM prototype_operations WHERE experiment_id=? AND action='close'",
                    (context.experiment_id,),
                ).fetchone()
                close_operation_state = operation[0] if operation else None
            required_columns = {
                "n04_runs": {"experiment_id", "state", "start_json", "close_json", "witness_json", "manifest_digest"},
                "n04_turns": {"turn_id", "source_ref", "state", "known_execution", "result_json", "feedback_ref", "receipt_json"},
                "n04_recoveries": {"domain_id", "experiment_id", "epoch", "turn_id", "owner", "client_key", "proof_json", "replay_ref"},
                "n04_receipt_copies": {"domain_id", "experiment_id", "epoch", "turn_id", "owner", "client_key", "receipt_json", "body_ref"},
                "n06_policies": {"experiment_id", "signed_json"},
                "n06_jobs": {"turn_id", "experiment_id", "session_id", "owner", "client_key", "clock_id", "release_ns", "state", "body_ref", "known_execution", "published"},
            }
            for table, expected in required_columns.items():
                if table not in table_names:
                    raise RecoveryAnchorError("STARTUP_RECOVERY_SCHEMA_MISSING")
                actual = {row[1] for row in broker.execute(f"PRAGMA table_info({table})")}
                if not expected.issubset(actual):
                    raise RecoveryAnchorError("STARTUP_RECOVERY_SCHEMA_INVALID")
            if "n04_recovery_failures" in table_names:
                actual = {row[1] for row in broker.execute(
                    "PRAGMA table_info(n04_recovery_failures)"
                )}
                if not {"turn_id", "internal_execution", "job_execution", "original_body_ref",
                        "original_receipt_json", "original_feedback_ref"}.issubset(actual):
                    raise RecoveryAnchorError("STARTUP_RECOVERY_FAILURE_SCHEMA_INVALID")
            controller = broker.execute(
                "SELECT * FROM n04_runs WHERE experiment_id=?", (context.experiment_id,)
            ).fetchone()
            if not controller or controller["manifest_digest"] != run["public_commitment"]:
                raise RecoveryAnchorError("STARTUP_CONTROLLER_BINDING_MISMATCH")
            queue_summary = {}
            if "n06_jobs" in table_names:
                queue_summary = dict(broker.execute(
                    "SELECT state,count(*) FROM n06_jobs WHERE experiment_id=? GROUP BY state",
                    (context.experiment_id,),
                ).fetchall())
                jobs = [dict(item) for item in broker.execute(
                    "SELECT turn_id,state,body_ref,published,clock_id,deadline_ns,release_ns,"
                    "session_id,owner,client_key,known_execution "
                    "FROM n06_jobs WHERE experiment_id=? ORDER BY turn_id",
                    (context.experiment_id,),
                ).fetchall()]
            if "n04_runs" in table_names:
                run_state = broker.execute(
                    "SELECT state FROM n04_runs WHERE experiment_id=?",
                    (context.experiment_id,),
                ).fetchone()
            if "n04_recoveries" in table_names:
                recovery_turn_ids = [item[0] for item in broker.execute(
                    "SELECT turn_id FROM n04_recoveries WHERE domain_id=? AND experiment_id=? AND epoch=?",
                    (context.domain_id, context.experiment_id, context.epoch),
                )]
            if "n04_receipt_copies" in table_names:
                receipt_copy_turn_ids = [item[0] for item in broker.execute(
                    "SELECT turn_id FROM n04_receipt_copies "
                    "WHERE domain_id=? AND experiment_id=? AND epoch=?",
                    (context.domain_id, context.experiment_id, context.epoch),
                )]
            if "n04_recovery_failures" in table_names:
                recovery_failure_turn_ids = [item[0] for item in broker.execute(
                    "SELECT f.turn_id FROM n04_recovery_failures f "
                    "JOIN turns t ON t.id=f.turn_id WHERE t.experiment_id=? ORDER BY f.turn_id",
                    (context.experiment_id,),
                )]

        recorder_public_pem = (BACKEND / "infra/owner-delegated-n08/recorder-public.pem").read_bytes()
        witness_public_pem = (BACKEND / "infra/owner-delegated-n08/witness-public.pem").read_bytes()
        recorder_key = serialization.load_pem_public_key(recorder_public_pem).public_bytes_raw()
        witness_key = serialization.load_pem_public_key(witness_public_pem).public_bytes_raw()

        with closing(_read_only(root / "recorder.sqlite3")) as recorder:
            identity = dict(recorder.execute("SELECT key,value FROM recorder_identity").fetchall())
            if identity != {"key_id": RECORDER_KEY_ID, "public_key": recorder_key.hex()}:
                raise RecoveryAnchorError("STARTUP_RECORDER_AUTHORITY_MISMATCH")
            manifest = recorder.execute(
                "SELECT manifest_digest FROM runs WHERE domain_id=? AND experiment_id=? AND epoch=?",
                (context.domain_id, context.experiment_id, context.epoch),
            ).fetchone()
            if not manifest or manifest[0] != run["public_commitment"]:
                raise RecoveryAnchorError("STARTUP_RECORDER_CONTEXT_MISMATCH")
            event_rows = recorder.execute(
                "SELECT sequence,canonical_json,digest,previous_digest FROM events "
                "WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY sequence",
                (context.domain_id, context.experiment_id, context.epoch),
            ).fetchall()
            events = [Event.model_validate_json(row["canonical_json"]) for row in event_rows]
            checkpoint_tables = {row[0] for row in recorder.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            if "checkpoints" not in checkpoint_tables:
                raise RecoveryAnchorError("STARTUP_RECORDER_CHECKPOINT_SCHEMA_MISSING")
            checkpoint_columns = {row[1] for row in recorder.execute(
                "PRAGMA table_info(checkpoints)"
            )}
            if not {"domain_id", "experiment_id", "epoch", "checkpoint_json", "signature"}.issubset(checkpoint_columns):
                raise RecoveryAnchorError("STARTUP_RECORDER_CHECKPOINT_SCHEMA_INVALID")
            checkpoint_row = recorder.execute(
                "SELECT checkpoint_json,signature FROM checkpoints "
                "WHERE domain_id=? AND experiment_id=? AND epoch=?",
                (context.domain_id, context.experiment_id, context.epoch),
            ).fetchone()
            stored_checkpoint = tuple(checkpoint_row) if checkpoint_row else None
            previous = "0" * 64
            for expected_sequence, (row, event) in enumerate(zip(event_rows, events, strict=True), start=1):
                if (row["sequence"] != expected_sequence or event.sequence != expected_sequence
                        or event_digest(event) != row["digest"] or event.previous_digest != previous
                        or row["previous_digest"] != previous
                        or (event.domain_id, event.experiment_id, event.epoch,
                            event.public_manifest_digest) != (
                            context.domain_id, context.experiment_id, context.epoch,
                            run["public_commitment"])):
                    raise RecoveryAnchorError("STARTUP_RECORDER_EVENT_INDEX_MISMATCH")
                previous = row["digest"]

        with closing(_read_only(root / "witness.sqlite3")) as witness_db:
            metadata = dict(witness_db.execute(
                "SELECT identity,value FROM authority_metadata"
            ).fetchall())
            expected_metadata = {
                "witness_key_id": WITNESS_KEY_ID,
                "public_key": witness_key.hex(),
                "recorder_key": recorder_key.hex(),
                "recorder_key_id": RECORDER_KEY_ID,
            }
            if metadata != expected_metadata:
                raise RecoveryAnchorError("STARTUP_WITNESS_AUTHORITY_MISMATCH")
            stored_start = witness_db.execute(
                "SELECT receipt_json,signature,manifest_digest FROM start_receipts "
                "WHERE domain_id=? AND experiment_id=? AND epoch=?",
                (context.domain_id, context.experiment_id, context.epoch),
            ).fetchone()
            stored_close = witness_db.execute(
                "SELECT receipt_json,signature,checkpoint_digest FROM close_receipts "
                "WHERE domain_id=? AND experiment_id=? AND epoch=?",
                (context.domain_id, context.experiment_id, context.epoch),
            ).fetchone()
            watermark = witness_db.execute(
                "SELECT highest_committed_epoch,current_active_epoch FROM epoch_watermarks "
                "WHERE domain_id=? AND experiment_id=?",
                (context.domain_id, context.experiment_id),
            ).fetchone()
            reservation = witness_db.execute(
                "SELECT highest_reserved,experiment_id,epoch FROM domain_reservations WHERE domain_id=?",
                (context.domain_id,),
            ).fetchone()

        vault_root = root / "vault"
        vault_db_path = vault_root / "custody.sqlite3"
        if (vault_root.is_symlink() or vault_db_path.is_symlink() or not vault_db_path.is_file()):
            raise RecoveryAnchorError("STARTUP_VAULT_STORE_MISSING_OR_UNSAFE")
        with closing(_read_only(vault_db_path)) as vault_db:
            vault_tables = {row[0] for row in vault_db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            if "artifacts" not in vault_tables:
                raise RecoveryAnchorError("STARTUP_VAULT_SCHEMA_MISSING")
            vault_columns = {row[1] for row in vault_db.execute("PRAGMA table_info(artifacts)")}
            if not {"id", "aad", "wrapped", "digest"}.issubset(vault_columns):
                raise RecoveryAnchorError("STARTUP_VAULT_SCHEMA_INVALID")

        if not controller["start_json"]:
            if stored_start or stored_close or controller["close_json"] or controller["witness_json"]:
                raise RecoveryAnchorError("STARTUP_WITNESS_STATE_PARTIAL")
            state = verify_anchor_records(
                client.records(context), context, authorities["anchor"]["public_key_bytes"],
                authorities["anchor"]["key_id"], authorities["anchor"]["authority_id"])
            if state["event_sequence"] != len(events):
                raise RecoveryAnchorError("STARTUP_UNSTARTED_RECORDER_STATE_MISMATCH")
            start = None
        else:
            start_response = load_wire(StartResponse, controller["start_json"].encode("utf-8"))
            start = start_response.witness_start_receipt
            stored_start_receipt = load_wire(WitnessStart, stored_start[0].encode("utf-8")) if stored_start else None
            if (not stored_start or stored_start_receipt != start.receipt
                    or stored_start[1] != start.signature
                    or stored_start[2] != run["public_commitment"]
                    or start.receipt.witness_key_id != WITNESS_KEY_ID
                    or (start.receipt.domain_id, start.receipt.experiment_id, start.receipt.epoch,
                        start.receipt.public_manifest_digest) != (
                        context.domain_id, context.experiment_id, context.epoch,
                        run["public_commitment"])
                    or start.receipt.event_count < 1 or start.receipt.event_count > len(events)
                    or start.receipt.prefix_root != event_digest(events[start.receipt.event_count - 1])
                    or not verify(witness_message(start.receipt), start.signature, witness_key)):
                raise RecoveryAnchorError("STARTUP_WITNESS_START_INVALID")
            if (not watermark or not reservation or reservation[0] < context.epoch
                    or reservation[1:] != (context.experiment_id, context.epoch)):
                raise RecoveryAnchorError("STARTUP_WITNESS_WATERMARK_MISMATCH")

        records = client.records(context)
        state = verify_anchor_records(
            records, context, authorities["anchor"]["public_key_bytes"],
            authorities["anchor"]["key_id"], authorities["anchor"]["authority_id"],
        )
        if state["pending"]:
            for operation in sorted(state["pending"]):
                prepared = state["prepared"][operation]
                candidate = next((event for event in events if event.sequence == prepared["event_sequence"]), None)
                if candidate is None or event_digest(candidate) != prepared["event_digest"]:
                    raise RecoveryAnchorError("ANCHOR_PREPARE_UNRESOLVED")
                client.commit(candidate)
            records = client.records(context)
            state = verify_anchor_records(records, context, authorities["anchor"]["public_key_bytes"],
                authorities["anchor"]["key_id"], authorities["anchor"]["authority_id"])
        if state["event_sequence"] > len(events):
            raise RecoveryAnchorError("ANCHOR_AHEAD")
        if state["event_sequence"] < len(events):
            raise RecoveryAnchorError("ANCHOR_BEHIND")
        client.verify_events(context, events)

        pending_close = bool(
            controller["state"] == "CLOSING" and controller["close_json"]
            and not controller["witness_json"]
            and run["phase"] in {"SCORED", "INVALID"}
            and ((run["phase"] == "SCORED" and run["integrity"] == "PENDING")
                 or (run["phase"] == "INVALID" and run["integrity"] == "INVALID"))
        )
        publication_retry = bool(
            allow_feedback_recovery and not pending_close
            and run["phase"] == "CLOSED"
            and run["integrity"] == "VALID_WITHIN_PROFILE"
            and run_state and run_state["state"] == "CLOSED"
            and controller["close_json"] and controller["witness_json"]
            and stored_close and state["terminal"]
            and close_operation_state in {"PENDING", "RUNNING", "FAILED"}
        )
        pending_checkpoint = None
        pending_witness_close = None
        if controller["close_json"] or controller["witness_json"]:
            if not controller["close_json"]:
                raise RecoveryAnchorError("STARTUP_TERMINAL_AUTHORITY_PARTIAL")
            checkpoint = load_wire(SignedCheckpoint, controller["close_json"].encode())
            if (not verify_checkpoint(checkpoint, recorder_key, context, run["public_commitment"], RECORDER_KEY_ID)
                    or not stored_checkpoint):
                raise RecoveryAnchorError("STARTUP_TERMINAL_CHECKPOINT_INVALID")
            recorder_checkpoint = Checkpoint.model_validate_json(stored_checkpoint[0])
            if (recorder_checkpoint != checkpoint.checkpoint
                    or stored_checkpoint[1] != checkpoint.signature):
                raise RecoveryAnchorError("STARTUP_TERMINAL_CHECKPOINT_MISMATCH")
            try:
                validate_chain(tuple(events), checkpoint.checkpoint)
            except Exception as exc:
                raise RecoveryAnchorError("STARTUP_TERMINAL_EVENT_BINDING_INVALID") from exc

            if stored_close:
                close_receipt = load_wire(WitnessClose, stored_close[0].encode("utf-8"))
                pending_witness_close = SignedWitnessClose(
                    receipt=close_receipt, signature=stored_close[1]
                )
                if (stored_close[2] != close_receipt.checkpoint_digest
                        or not verify_witness_close(
                            pending_witness_close, witness_key, checkpoint.checkpoint,
                            context, WITNESS_KEY_ID,
                        )):
                    raise RecoveryAnchorError("STARTUP_TERMINAL_WITNESS_INVALID")

            if pending_close:
                if (not watermark or not reservation
                        or reservation[0] < context.epoch
                        or reservation[1:] != (context.experiment_id, context.epoch)):
                    raise RecoveryAnchorError("STARTUP_WITNESS_WATERMARK_MISMATCH")
                if pending_witness_close:
                    if watermark[1] is not None or watermark[0] < context.epoch:
                        raise RecoveryAnchorError("STARTUP_CLOSED_WITNESS_STILL_ACTIVE")
                    if state["terminal"]:
                        terminal_integrity = state["terminal"]["final_integrity"]
                        if run["integrity"] == "PENDING":
                            # The independent terminal record may have committed
                            # before its ACK reached this controller. Reconcile
                            # only the valid-close case from that authenticated
                            # record; all other local/remote disagreements fail.
                            if (run["phase"] != "SCORED"
                                    or terminal_integrity != "VALID_WITHIN_PROFILE"):
                                raise RecoveryAnchorError("ANCHOR_TERMINAL_MISMATCH")
                        elif terminal_integrity != run["integrity"]:
                            raise RecoveryAnchorError("ANCHOR_TERMINAL_MISMATCH")
                        client.verify_terminal(
                            context, checkpoint, pending_witness_close, terminal_integrity
                        )
                elif (watermark[0] >= context.epoch or watermark[1] != context.epoch
                      or state["terminal"]):
                    raise RecoveryAnchorError("STARTUP_WITNESS_WATERMARK_MISMATCH")
                with closing(_read_only(root / "broker.sqlite3")) as broker:
                    unsettled = broker.execute(
                        "SELECT 1 FROM turns WHERE experiment_id=? AND state IN ('RESERVED','DISPATCHED') LIMIT 1",
                        (context.experiment_id,),
                    ).fetchone()
                if unsettled or any(job["state"] in {"QUEUED", "CLAIMED"} for job in jobs):
                    raise RecoveryAnchorError("STARTUP_PENDING_CLOSE_NOT_QUIESCENT")
                pending_checkpoint = checkpoint
            else:
                if not controller["witness_json"] or not stored_close or not pending_witness_close:
                    raise RecoveryAnchorError("STARTUP_TERMINAL_AUTHORITY_PARTIAL")
                close = load_wire(SignedWitnessClose, controller["witness_json"].encode())
                if close != pending_witness_close:
                    raise RecoveryAnchorError("STARTUP_TERMINAL_SIGNATURE_INVALID")
                if state["terminal"]:
                    client.verify_terminal(context, checkpoint, close, run["integrity"])
                elif run["phase"] in {"CLOSED", "RELEASED"} and run["integrity"] != "INVALID":
                    raise RecoveryAnchorError("ANCHOR_TERMINAL_MISSING")
                if watermark[1] is not None or watermark[0] < context.epoch:
                    raise RecoveryAnchorError("STARTUP_CLOSED_WITNESS_STILL_ACTIVE")
            if publication_retry:
                pending_checkpoint = checkpoint
        elif state["terminal"] or stored_close:
            raise RecoveryAnchorError("ANCHOR_AHEAD")
        elif start is not None:
            if (not watermark or watermark[0] >= context.epoch
                    or watermark[1] != context.epoch):
                raise RecoveryAnchorError("STARTUP_WITNESS_WATERMARK_MISMATCH")

        if run["phase"] in {"CLOSED", "RELEASED"} and run["integrity"] == "VALID_WITHIN_PROFILE" and not state["terminal"]:
            raise RecoveryAnchorError("ANCHOR_TERMINAL_MISSING")
        recovery_only_action = None
        recovery_turn_id = None
        if allow_feedback_recovery:
            if set(recovery_turn_ids) & set(receipt_copy_turn_ids):
                raise RecoveryAnchorError("STARTUP_RECOVERY_RECORD_CONFLICT")
            stored_recovery_ids = set(recovery_turn_ids) | set(receipt_copy_turn_ids)
            if len(stored_recovery_ids) > 1:
                raise RecoveryAnchorError("STARTUP_RECOVERY_RECORD_CARDINALITY_INVALID")
            if pending_close or publication_retry:
                recovery_only_action = "RETRY_PENDING_CLOSE"
            elif run["phase"] == "INVALID" or run["integrity"] == "INVALID":
                active_jobs = [job for job in jobs if job["state"] in {"QUEUED", "CLAIMED"}]
                if (run["phase"] != "INVALID" or run["integrity"] != "INVALID"
                        or not run_state or run_state["state"] != "INVALID"
                        or not controller["start_json"] or controller["close_json"]
                        or controller["witness_json"] or stored_close
                        or state["terminal"] or stored_recovery_ids
                        or len(recovery_failure_turn_ids) != 1 or active_jobs):
                    raise RecoveryAnchorError("STARTUP_INVALID_RUN_RESUME_REFUSED")
                recovery_turn_id = recovery_failure_turn_ids[0]
                with closing(_read_only(root / "broker.sqlite3")) as broker:
                    failure = broker.execute(
                        "SELECT f.internal_execution,f.job_execution,f.original_body_ref,"
                        "f.original_receipt_json,f.original_feedback_ref,t.state AS turn_state,"
                        "t.result_json AS turn_result,t.session_id,n.state AS internal_state,"
                        "n.known_execution AS internal_now,n.receipt_json,n.feedback_ref,"
                        "j.state AS job_state,j.body_ref,j.known_execution AS job_now,j.published,"
                        "s.quarantined FROM n04_recovery_failures f "
                        "JOIN turns t ON t.id=f.turn_id JOIN n04_turns n ON n.turn_id=t.id "
                        "JOIN n06_jobs j ON j.turn_id=t.id JOIN sessions s ON s.id=t.session_id "
                        "WHERE f.turn_id=? AND t.experiment_id=?",
                        (recovery_turn_id, context.experiment_id),
                    ).fetchone()
                    unresolved = broker.execute(
                        "SELECT 1 FROM turns WHERE experiment_id=? AND state IN ('RESERVED','DISPATCHED') LIMIT 1",
                        (context.experiment_id,),
                    ).fetchone()
                invalid_events = [event for event in events if (
                    event.event_type == "INTEGRITY_VIOLATION" and event.turn_id == recovery_turn_id
                )]
                if (not failure or unresolved or len(invalid_events) > 1
                        or failure["turn_state"] not in {"UNKNOWN", "FAILED"}
                        or failure["internal_state"] != "RECOVERY_INVALID"
                        or failure["job_state"] != "FAILED" or failure["body_ref"] is not None
                        or failure["published"] != 0 or failure["quarantined"] != 1
                        or failure["turn_result"] is None
                        or failure["internal_now"] not in {"NOT_EVALUATED", "EXECUTED", "UNKNOWN"}
                        or failure["job_now"] not in {"NOT_EVALUATED", "EXECUTED", "UNKNOWN"}):
                    raise RecoveryAnchorError("STARTUP_INVALID_CLOSE_STATE_INVALID")
                recovery_only_action = "CLOSE_INVALID"
            elif stored_recovery_ids:
                recovery_turn_id = next(iter(stored_recovery_ids))
                recovery_only_action = "REPLAY_STORED_RECOVERY"
            elif (
                run["phase"] == "RUNNING"
                and run_state
                and run_state["state"] == "RUNNING"
                and controller["start_json"]
            ):
                active_jobs = [job for job in jobs if job["state"] in {"QUEUED", "CLAIMED"}]
                orphan_jobs = [job for job in active_jobs if (
                    job["state"] == "CLAIMED" and job["published"] == 0
                    and job["body_ref"] is None
                )]
                if len(active_jobs) == 1 and len(orphan_jobs) == 1:
                    job = orphan_jobs[0]
                    candidate_turn_id = job["turn_id"]
                    with closing(_read_only(root / "broker.sqlite3")) as broker:
                        turn_projection = broker.execute(
                            "SELECT t.state AS turn_state,t.result_json AS turn_result,t.session_id,"
                            "t.turn_index,t.owner AS turn_owner,s.owner AS session_owner,s.quarantined,"
                            "n.state AS internal_state,n.known_execution AS internal_execution,"
                            "n.source_ref,n.result_json AS internal_result,n.feedback_ref,n.receipt_json "
                            "FROM turns t JOIN sessions s ON s.id=t.session_id "
                            "LEFT JOIN n04_turns n ON n.turn_id=t.id "
                            "WHERE t.id=? AND t.experiment_id=?",
                            (candidate_turn_id, context.experiment_id),
                        ).fetchone()
                    feedback_events = [event for event in events if (
                        event.event_type == "FEEDBACK_AUTHORIZED"
                        and event.turn_id == candidate_turn_id
                    )]
                    exact_projection = bool(
                        turn_projection
                        and turn_projection["session_id"] == job["session_id"]
                        and turn_projection["turn_owner"] == job["owner"]
                        and turn_projection["session_owner"] == job["owner"]
                        and turn_projection["quarantined"] == 0
                        and turn_projection["turn_state"] == "DISPATCHED"
                        and turn_projection["turn_result"] is None
                        and turn_projection["internal_state"] == "DISPATCHED"
                        and turn_projection["internal_execution"] == "EXECUTED"
                        and turn_projection["source_ref"] is not None
                        and turn_projection["internal_result"] is None
                        and turn_projection["feedback_ref"] is None
                        and job["known_execution"] in {"NOT_EVALUATED", "EXECUTED"}
                    )
                    if exact_projection and len(feedback_events) == 1:
                        recovery_turn_id = candidate_turn_id
                        recovery_only_action = "RECONCILE_ORPHAN"
                    elif (turn_projection and turn_projection["session_id"] == job["session_id"]
                            and turn_projection["turn_owner"] == job["owner"]
                            and turn_projection["session_owner"] == job["owner"]
                            and turn_projection["turn_state"] in {"RESERVED", "DISPATCHED", "UNKNOWN", "FAILED"}
                            and (turn_projection["turn_state"] != "DISPATCHED"
                                 or turn_projection["turn_result"] is not None
                                 or turn_projection["internal_state"] != "DISPATCHED"
                                 or turn_projection["internal_execution"] != "EXECUTED"
                                 or turn_projection["source_ref"] is None
                                 or turn_projection["internal_result"] is not None
                                 or turn_projection["feedback_ref"] is not None
                                 or turn_projection["receipt_json"] is not None
                                 or job["known_execution"] not in {"NOT_EVALUATED", "EXECUTED"}
                                 or len(feedback_events) != 1)):
                        recovery_turn_id = candidate_turn_id
                        recovery_only_action = "INVALIDATE_AMBIGUOUS"
            else:
                raise RecoveryAnchorError("STARTUP_NO_EXACT_RECOVERY_CANDIDATE")
            if recovery_only_action is None:
                raise RecoveryAnchorError("STARTUP_NO_EXACT_RECOVERY_CANDIDATE")
        else:
            if run["phase"] == "INVALID" or run["integrity"] == "INVALID":
                raise RecoveryAnchorError("STARTUP_INVALID_RUN_RESUME_REFUSED")
            if queue_summary.get("CLAIMED", 0):
                raise RecoveryAnchorError("STARTUP_CLAIMED_JOB_REQUIRES_EXPLICIT_RECOVERY")

        return {
            "status": (
                "AUTHENTICATED_STORE_MATCH_RECOVERY_ONLY"
                if recovery_only_action
                else "AUTHENTICATED_STORE_MATCH_COLD_RESUME_UNSUPPORTED"
            ),
            "context": context.model_dump(),
            "phase": run["phase"],
            "integrity": run["integrity"],
            "event_count": len(events),
            "anchor_record_count": len(records),
            "queue_states": queue_summary,
            "recovery_only_action": recovery_only_action,
            "recovery_turn_id": recovery_turn_id,
            "pending_checkpoint_json": (
                controller["close_json"] if recovery_only_action == "RETRY_PENDING_CLOSE" else None
            ),
            "pending_close_kind": (
                "PUBLICATION_ACK" if publication_retry
                else "AUTHORITY_ACK" if pending_close
                else None
            ),
            "pending_witness_json": (
                controller["witness_json"] if publication_retry else None
            ),
            "recovery_only_ready": recovery_only_action is not None,
            "trusted_resume_authorized": False,
            "workers_started": False,
            "model_started": False,
        }
    finally:
        manager.stop()
