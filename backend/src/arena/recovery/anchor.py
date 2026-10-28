"""Append-only, independently stored signed recovery-anchor journal.

This journal is intended to run in a separate local process and data directory.
It detects rollback of the protected application stores while its own state and
signing key remain intact. It does not resist a host administrator who can
replace both stores.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import sqlite3
import unicodedata
from pathlib import Path
import re
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from arena.contracts.common import Context
from arena.contracts.crypto import canonical_bytes, checkpoint_digest, event_digest
from arena.contracts.evidence import Event, SignedCheckpoint, SignedWitnessClose


ZERO = "0" * 64
ANCHOR_PREFIX = b"arena.recovery-anchor.v1\0"
OPERATION_PREFIX = b"arena.recovery-anchor.operation.v1\0"
TERMINAL_PREFIX = b"arena.recovery-anchor.terminal.v1\0"
SCHEMA = "arena.recovery-anchor.v1"
RECORDER_PRINCIPAL = "n08-prototype-recorder-001"
ABORT_CODES = frozenset({"RECORDER_APPEND_NOT_COMMITTED"})

PREPARED_FIELDS = frozenset(
    {
        "schema_version", "transition", "authority_id", "key_id",
        "recorder_principal_id", "domain_id", "experiment_id", "epoch",
        "anchor_sequence", "operation_id", "previous_anchor_record_digest",
        "event_sequence", "event_digest", "previous_event_root",
        "resulting_event_root", "event_type", "signature",
    }
)
COMMITTED_FIELDS = PREPARED_FIELDS | {"prepared_record_digest"}
ABORTED_FIELDS = PREPARED_FIELDS | {"prepared_record_digest", "abort_reason_code"}
TERMINAL_FIELDS = frozenset(
    {
        "schema_version", "transition", "authority_id", "key_id",
        "recorder_principal_id", "domain_id", "experiment_id", "epoch",
        "anchor_sequence", "operation_id", "previous_anchor_record_digest",
        "recorder_event_count", "final_event_root", "checkpoint_digest",
        "witness_close_digest", "final_integrity", "signature",
    }
)


class RecoveryAnchorError(ValueError):
    """A fail-closed anchor protocol refusal."""


def _canonical(value: Any) -> bytes:
    _validate_json_value(value)
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _validate_json_value(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise RecoveryAnchorError("ANCHOR_INTEGER_RANGE")
        return
    if isinstance(value, float):
        raise RecoveryAnchorError("ANCHOR_FLOAT_NOT_ALLOWED")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value or any(
            unicodedata.category(ch) == "Cc" for ch in value
        ):
            raise RecoveryAnchorError("ANCHOR_STRING_NOT_CANONICAL")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise RecoveryAnchorError("ANCHOR_OBJECT_KEY_INVALID")
        for key, item in value.items():
            _validate_json_value(key)
            _validate_json_value(item)
        return
    raise RecoveryAnchorError("ANCHOR_VALUE_TYPE_INVALID")


def operation_id(context: Context, sequence: int, digest: str) -> str:
    payload = {
        "domain_id": context.domain_id,
        "experiment_id": context.experiment_id,
        "epoch": context.epoch,
        "event_sequence": sequence,
        "event_digest": digest,
    }
    return hashlib.sha256(OPERATION_PREFIX + _canonical(payload)).hexdigest()


def load_recovery_authorities(path: Path) -> dict[str, Any]:
    """Load source-pinned public roots with duplicate and unknown-field refusal."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RecoveryAnchorError("RECOVERY_AUTHORITY_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique)
    except Exception as exc:
        if isinstance(exc, RecoveryAnchorError):
            raise
        raise RecoveryAnchorError("RECOVERY_AUTHORITY_FILE_INVALID") from exc
    if (not isinstance(value, dict) or set(value) != {
        "schema_version", "anchor", "recovery", "invalid_export", "recorder_principal_id"
    } or value.get("schema_version") != "arena.prototype-recovery-authorities.v1"):
        raise RecoveryAnchorError("RECOVERY_AUTHORITY_FIELDS_INVALID")
    if value["recorder_principal_id"] != RECORDER_PRINCIPAL:
        raise RecoveryAnchorError("RECOVERY_RECORDER_PIN_MISMATCH")
    for kind in ("anchor", "recovery", "invalid_export"):
        item = value[kind]
        if not isinstance(item, dict) or set(item) != {"authority_id", "key_id", "public_key"}:
            raise RecoveryAnchorError("RECOVERY_AUTHORITY_FIELDS_INVALID")
        if any(not isinstance(item[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", item[key])
               for key in ("authority_id", "key_id")):
            raise RecoveryAnchorError("RECOVERY_AUTHORITY_ID_INVALID")
        try:
            public = bytes.fromhex(item["public_key"])
            Ed25519PublicKey.from_public_bytes(public)
        except Exception as exc:
            raise RecoveryAnchorError("RECOVERY_AUTHORITY_PUBLIC_KEY_INVALID") from exc
        if len(public) != 32:
            raise RecoveryAnchorError("RECOVERY_AUTHORITY_PUBLIC_KEY_INVALID")
        item["public_key_bytes"] = public
    keys = [value[kind]["public_key_bytes"] for kind in ("anchor", "recovery", "invalid_export")]
    ids = [(value[kind]["authority_id"], value[kind]["key_id"]) for kind in ("anchor", "recovery", "invalid_export")]
    if len(set(keys)) != 3 or len(set(ids)) != 3:
        raise RecoveryAnchorError("RECOVERY_AUTHORITIES_MUST_BE_DISTINCT")
    return value


def terminal_operation_id(
    context: Context, event_count: int, final_root: str, checkpoint_sha: str,
    witness_sha: str, integrity: str,
) -> str:
    payload = {
        "domain_id": context.domain_id,
        "experiment_id": context.experiment_id,
        "epoch": context.epoch,
        "recorder_event_count": event_count,
        "final_event_root": final_root,
        "checkpoint_digest": checkpoint_sha,
        "witness_close_digest": witness_sha,
        "final_integrity": integrity,
    }
    return hashlib.sha256(TERMINAL_PREFIX + _canonical(payload)).hexdigest()


def record_digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


def _unsigned(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "signature"}


def _check_record_shape(record: dict[str, Any]) -> None:
    if not isinstance(record, dict):
        raise RecoveryAnchorError("ANCHOR_RECORD_INVALID")
    transition = record.get("transition")
    expected = {
        "PREPARED": PREPARED_FIELDS,
        "COMMITTED": COMMITTED_FIELDS,
        "ABORTED": ABORTED_FIELDS,
        "TERMINAL_CLOSED": TERMINAL_FIELDS,
    }.get(transition)
    if expected is None or frozenset(record) != expected:
        raise RecoveryAnchorError("ANCHOR_RECORD_FIELDS_INVALID")
    _validate_json_value(record)
    for key in (
        "event_digest", "previous_event_root", "resulting_event_root",
        "previous_anchor_record_digest", "prepared_record_digest",
        "final_event_root", "checkpoint_digest", "witness_close_digest",
        "operation_id",
    ):
        if key in record and (
            not isinstance(record[key], str)
            or len(record[key]) != 64
            or any(ch not in "0123456789abcdef" for ch in record[key])
        ):
            raise RecoveryAnchorError("ANCHOR_DIGEST_INVALID")
    for key in ("schema_version", "transition", "authority_id", "key_id", "recorder_principal_id"):
        if not isinstance(record.get(key), str) or not record[key]:
            raise RecoveryAnchorError("ANCHOR_STRING_INVALID")
    for key in ("epoch", "anchor_sequence"):
        if isinstance(record.get(key), bool) or not isinstance(record.get(key), int):
            raise RecoveryAnchorError("ANCHOR_INTEGER_INVALID")
    if record["epoch"] < 1 or record["anchor_sequence"] < 1:
        raise RecoveryAnchorError("ANCHOR_INTEGER_INVALID")
    if transition != "TERMINAL_CLOSED":
        if isinstance(record.get("event_sequence"), bool) or not isinstance(
            record.get("event_sequence"), int
        ) or record["event_sequence"] < 1:
            raise RecoveryAnchorError("ANCHOR_INTEGER_INVALID")
    elif isinstance(record.get("recorder_event_count"), bool) or not isinstance(
        record.get("recorder_event_count"), int
    ) or record["recorder_event_count"] < 1 or record.get("final_integrity") not in {
        "VALID_WITHIN_PROFILE", "INVALID"
    }:
        raise RecoveryAnchorError("ANCHOR_INTEGER_INVALID")


def verify_record(
    record: dict[str, Any], public_key: bytes, key_id: str,
    authority_id: str | None = None,
) -> None:
    _check_record_shape(record)
    if (
        record["schema_version"] != SCHEMA
        or record["key_id"] != key_id
        or (authority_id is not None and record["authority_id"] != authority_id)
        or record["recorder_principal_id"] != RECORDER_PRINCIPAL
        or not isinstance(record["signature"], str)
    ):
        raise RecoveryAnchorError("ANCHOR_TRUST_BINDING_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(record["signature"]), ANCHOR_PREFIX + _canonical(_unsigned(record))
        )
    except Exception as exc:
        raise RecoveryAnchorError("ANCHOR_BAD_SIGNATURE") from exc


def verify_anchor_records(
    records: list[dict[str, Any]], context: Context, public_key: bytes, key_id: str,
    authority_id: str | None = None,
) -> dict[str, Any]:
    """Verify an independently supplied signed append-only sequence for one run."""
    anchor_seq, record_head = 0, ZERO
    event_seq, event_root = 0, ZERO
    prepared: dict[str, dict[str, Any]] = {}
    committed: dict[str, dict[str, Any]] = {}
    aborted: dict[str, dict[str, Any]] = {}
    terminal = None
    for record in records:
        verify_record(record, public_key, key_id, authority_id)
        if (record["domain_id"], record["experiment_id"], record["epoch"]) != (
            context.domain_id, context.experiment_id, context.epoch
        ):
            raise RecoveryAnchorError("ANCHOR_CONTEXT_MISMATCH")
        if record["anchor_sequence"] != anchor_seq + 1 or record["previous_anchor_record_digest"] != record_head:
            raise RecoveryAnchorError("ANCHOR_SEQUENCE_OR_EQUIVOCATION")
        transition = record["transition"]
        if transition == "PREPARED":
            if set(prepared) - set(committed) - set(aborted):
                raise RecoveryAnchorError("ANCHOR_PREPARE_UNRESOLVED")
            expected_op = operation_id(context, record["event_sequence"], record["event_digest"])
            if (
                record["operation_id"] != expected_op
                or record["event_sequence"] != event_seq + 1
                or record["previous_event_root"] != event_root
                or record["resulting_event_root"] != record["event_digest"]
                or expected_op in prepared
                or terminal is not None
            ):
                raise RecoveryAnchorError("ANCHOR_PREPARED_CHAIN_MISMATCH")
            prepared[expected_op] = record
        elif transition in {"COMMITTED", "ABORTED"}:
            operation = record["operation_id"]
            prior = prepared.get(operation)
            if not prior or record["prepared_record_digest"] != record_digest(prior):
                raise RecoveryAnchorError("ANCHOR_PREPARED_RECORD_MISMATCH")
            for key in ("domain_id", "experiment_id", "epoch", "operation_id",
                        "event_sequence", "event_digest", "previous_event_root",
                        "resulting_event_root", "event_type"):
                if record.get(key) != prior.get(key):
                    raise RecoveryAnchorError("ANCHOR_PREPARED_RECORD_MISMATCH")
            if transition == "COMMITTED":
                if operation in committed or operation in aborted or (
                    record["event_sequence"] != event_seq + 1
                    or record["event_digest"] != prior["event_digest"]
                    or record["resulting_event_root"] != prior["resulting_event_root"]
                    or record["previous_event_root"] != event_root
                ):
                    raise RecoveryAnchorError("ANCHOR_COMMIT_MISMATCH")
                event_seq, event_root = record["event_sequence"], record["resulting_event_root"]
                committed[operation] = record
            elif (operation in committed or operation in aborted
                    or not isinstance(record["abort_reason_code"], str)
                    or record["abort_reason_code"] not in ABORT_CODES):
                raise RecoveryAnchorError("ANCHOR_ABORT_CODE_INVALID")
            else:
                aborted[operation] = record
        else:
            if set(prepared) - set(committed) - set(aborted):
                raise RecoveryAnchorError("ANCHOR_PREPARE_UNRESOLVED")
            expected_terminal_op = terminal_operation_id(
                context, record["recorder_event_count"], record["final_event_root"],
                record["checkpoint_digest"], record["witness_close_digest"],
                record["final_integrity"],
            )
            if (terminal is not None or record["operation_id"] != expected_terminal_op
                    or record["recorder_event_count"] != event_seq
                    or record["final_event_root"] != event_root):
                raise RecoveryAnchorError("ANCHOR_TERMINAL_MISMATCH")
            if record["final_integrity"] not in {"VALID_WITHIN_PROFILE", "INVALID"}:
                raise RecoveryAnchorError("ANCHOR_TERMINAL_INTEGRITY_INVALID")
            terminal = record
        anchor_seq = record["anchor_sequence"]
        record_head = record_digest(record)
    return {
        "anchor_sequence": anchor_seq,
        "record_digest": record_head,
        "event_sequence": event_seq,
        "event_root": event_root,
        "prepared": prepared,
        "committed": committed,
        "aborted": aborted,
        "pending": set(prepared) - set(committed) - set(aborted),
        "terminal": terminal,
    }


class RecoveryAnchor:
    """The anchor-process journal. Call only in the separate anchor process."""

    def __init__(self, db_path: Path, private_key: Ed25519PrivateKey, authority_id: str, key_id: str):
        if Path(db_path).is_symlink():
            raise RecoveryAnchorError("ANCHOR_LEDGER_SYMLINK_REFUSED")
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.private_key, self.authority_id, self.key_id = private_key, authority_id, key_id
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        existed = self.db_path.exists()
        if self.db_path.is_symlink():
            raise RecoveryAnchorError("ANCHOR_LEDGER_SYMLINK_REFUSED")
        if existed:
            try:
                with closing(sqlite3.connect(f"file:{self.db_path.as_posix()}?mode=ro", uri=True)) as check:
                    healthy = check.execute("PRAGMA integrity_check").fetchone()[0]
                    tables = {row[0] for row in check.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    )}
                    if healthy != "ok" or tables != {
                        "anchor_identity", "recovery_runs", "recovery_records", "recovery_operations"
                    }:
                        raise RecoveryAnchorError("ANCHOR_LEDGER_CORRUPT_OR_INCOMPLETE")
                    identity = dict(check.execute("SELECT key,value FROM anchor_identity"))
            except RecoveryAnchorError:
                raise
            except Exception as exc:
                raise RecoveryAnchorError("ANCHOR_LEDGER_CORRUPT_OR_INCOMPLETE") from exc
            expected_identity = {
                "authority_id": self.authority_id,
                "key_id": self.key_id,
                "public_key": self.private_key.public_key().public_bytes_raw().hex(),
            }
            if identity != expected_identity:
                raise RecoveryAnchorError("ANCHOR_LEDGER_IDENTITY_MISMATCH")
        with closing(self._connect()) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS anchor_identity(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS recovery_runs(
                    domain_id TEXT NOT NULL, experiment_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                    anchor_sequence INTEGER NOT NULL, event_sequence INTEGER NOT NULL,
                    event_root TEXT NOT NULL, record_digest TEXT NOT NULL, terminal INTEGER NOT NULL,
                    PRIMARY KEY(domain_id,experiment_id,epoch));
                CREATE TABLE IF NOT EXISTS recovery_records(
                    domain_id TEXT NOT NULL, experiment_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                    anchor_sequence INTEGER NOT NULL, transition TEXT NOT NULL, operation_id TEXT NOT NULL,
                    record_json TEXT NOT NULL, record_digest TEXT NOT NULL,
                    PRIMARY KEY(domain_id,experiment_id,epoch,anchor_sequence));
                CREATE TABLE IF NOT EXISTS recovery_operations(
                    domain_id TEXT NOT NULL, experiment_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                    operation_id TEXT NOT NULL, event_sequence INTEGER NOT NULL, event_digest TEXT NOT NULL,
                    prepared_record_digest TEXT NOT NULL, state TEXT NOT NULL,
                    PRIMARY KEY(domain_id,experiment_id,epoch,operation_id));
            """)
            if not existed:
                conn.executemany("INSERT INTO anchor_identity VALUES(?,?)", {
                    "authority_id": self.authority_id,
                    "key_id": self.key_id,
                    "public_key": self.private_key.public_key().public_bytes_raw().hex(),
                }.items())

    @staticmethod
    def _scope(context: Context):
        return (context.domain_id, context.experiment_id, context.epoch)

    def _begin(self, conn, context: Context):
        scope = self._scope(context)
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT OR IGNORE INTO recovery_runs VALUES(?,?,?,0,0,?,?,0)",
            (*scope, ZERO, ZERO),
        )
        row = conn.execute(
            "SELECT * FROM recovery_runs WHERE domain_id=? AND experiment_id=? AND epoch=?", scope
        ).fetchone()
        stored_records = list(conn.execute(
            "SELECT record_json,record_digest FROM recovery_records WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY anchor_sequence",
            scope,
        ))
        records = []
        for item in stored_records:
            try:
                record = json.loads(item["record_json"])
            except Exception as exc:
                raise RecoveryAnchorError("ANCHOR_RECORD_JSON_INVALID") from exc
            if record_digest(record) != item["record_digest"]:
                raise RecoveryAnchorError("ANCHOR_RECORD_INDEX_MISMATCH")
            records.append(record)
        state = verify_anchor_records(
            records, context, self.private_key.public_key().public_bytes_raw(),
            self.key_id, self.authority_id,
        )
        if (row["anchor_sequence"], row["event_sequence"], row["event_root"],
                row["record_digest"], bool(row["terminal"])) != (
                state["anchor_sequence"], state["event_sequence"], state["event_root"],
                state["record_digest"], bool(state["terminal"])):
            raise RecoveryAnchorError("ANCHOR_LEDGER_HEAD_MISMATCH")
        statuses = {
            record["operation_id"]: record["transition"]
            for record in records if record["transition"] in {"COMMITTED", "ABORTED"}
        }
        ops = list(conn.execute(
            "SELECT operation_id,state,prepared_record_digest FROM recovery_operations WHERE domain_id=? AND experiment_id=? AND epoch=?",
            scope,
        ))
        if len(ops) != len(state["prepared"]):
            raise RecoveryAnchorError("ANCHOR_OPERATION_LEDGER_MISMATCH")
        for operation, status, prepared_digest in ops:
            if (operation not in state["prepared"]
                    or record_digest(state["prepared"][operation]) != prepared_digest
                    or statuses.get(operation) != {"COMMITTED": "COMMITTED", "ABORTED": "ABORTED"}.get(status)):
                raise RecoveryAnchorError("ANCHOR_OPERATION_LEDGER_MISMATCH")
        return scope, row

    def _append_record(self, conn, scope, row, value):
        sequence = row["anchor_sequence"] + 1
        record = {
            **value,
            "schema_version": SCHEMA,
            "authority_id": self.authority_id,
            "key_id": self.key_id,
            "recorder_principal_id": RECORDER_PRINCIPAL,
            "anchor_sequence": sequence,
            "previous_anchor_record_digest": row["record_digest"],
        }
        record["signature"] = self.private_key.sign(ANCHOR_PREFIX + _canonical(record)).hex()
        _check_record_shape(record)
        digest = record_digest(record)
        conn.execute(
            "INSERT INTO recovery_records VALUES(?,?,?,?,?,?,?,?)",
            (*scope, sequence, record["transition"], record["operation_id"],
             _canonical(record).decode("utf-8"), digest),
        )
        conn.execute(
            "UPDATE recovery_runs SET anchor_sequence=?,record_digest=? WHERE domain_id=? AND experiment_id=? AND epoch=?",
            (sequence, digest, *scope),
        )
        return record, digest

    def prepare(self, event_value: dict) -> dict:
        event = Event.model_validate(event_value)
        context = Context(domain_id=event.domain_id, experiment_id=event.experiment_id, epoch=event.epoch)
        digest = event_digest(event)
        operation = operation_id(context, event.sequence, digest)
        with closing(self._connect()) as conn:
            scope, row = self._begin(conn, context)
            try:
                old = conn.execute(
                    "SELECT o.*,p.record_json FROM recovery_operations o JOIN recovery_records p "
                    "ON p.domain_id=o.domain_id AND p.experiment_id=o.experiment_id AND p.epoch=o.epoch "
                    "AND p.record_digest=o.prepared_record_digest WHERE o.domain_id=? AND o.experiment_id=? AND o.epoch=? AND o.operation_id=?",
                    (*scope, operation),
                ).fetchone()
                if old:
                    if old["event_digest"] != digest or old["event_sequence"] != event.sequence:
                        raise RecoveryAnchorError("ANCHOR_OPERATION_EQUIVOCATION")
                    if old["state"] == "ABORTED":
                        raise RecoveryAnchorError("ANCHOR_OPERATION_ABORTED")
                    conn.execute("COMMIT")
                    return json.loads(old["record_json"])
                if row["terminal"]:
                    raise RecoveryAnchorError("ANCHOR_RUN_TERMINAL")
                pending = conn.execute(
                    "SELECT 1 FROM recovery_operations WHERE domain_id=? AND experiment_id=? AND epoch=? AND state='PREPARED'",
                    scope,
                ).fetchone()
                if pending:
                    raise RecoveryAnchorError("ANCHOR_PREPARE_UNRESOLVED")
                if event.sequence != row["event_sequence"] + 1 or event.previous_digest != row["event_root"]:
                    raise RecoveryAnchorError("ANCHOR_EVENT_COMPARE_AND_SWAP_FAILED")
                record, digest_record = self._append_record(conn, scope, row, {
                    "transition": "PREPARED", "domain_id": context.domain_id,
                    "experiment_id": context.experiment_id, "epoch": context.epoch,
                    "operation_id": operation, "event_sequence": event.sequence,
                    "event_digest": digest, "previous_event_root": event.previous_digest,
                    "resulting_event_root": digest, "event_type": event.event_type,
                })
                conn.execute(
                    "INSERT INTO recovery_operations VALUES(?,?,?,?,?,?,?,'PREPARED')",
                    (*scope, operation, event.sequence, digest, digest_record),
                )
                conn.execute("COMMIT")
                return record
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def commit(self, event_value: dict) -> dict:
        event = Event.model_validate(event_value)
        context = Context(domain_id=event.domain_id, experiment_id=event.experiment_id, epoch=event.epoch)
        digest = event_digest(event)
        operation = operation_id(context, event.sequence, digest)
        with closing(self._connect()) as conn:
            scope, row = self._begin(conn, context)
            try:
                op = conn.execute(
                    "SELECT * FROM recovery_operations WHERE domain_id=? AND experiment_id=? AND epoch=? AND operation_id=?",
                    (*scope, operation),
                ).fetchone()
                if not op or op["event_digest"] != digest or op["event_sequence"] != event.sequence:
                    raise RecoveryAnchorError("ANCHOR_PREPARE_REQUIRED")
                if op["state"] == "COMMITTED":
                    found = conn.execute(
                        "SELECT record_json FROM recovery_records WHERE domain_id=? AND experiment_id=? AND epoch=? AND operation_id=? AND transition='COMMITTED'",
                        (*scope, operation),
                    ).fetchone()
                    conn.execute("COMMIT")
                    return json.loads(found[0])
                if op["state"] == "ABORTED":
                    raise RecoveryAnchorError("ANCHOR_OPERATION_ABORTED")
                if op["state"] != "PREPARED" or row["terminal"] or (
                    event.sequence != row["event_sequence"] + 1 or event.previous_digest != row["event_root"]
                ):
                    raise RecoveryAnchorError("ANCHOR_COMMIT_COMPARE_AND_SWAP_FAILED")
                prepared = json.loads(conn.execute(
                    "SELECT record_json FROM recovery_records WHERE domain_id=? AND experiment_id=? AND epoch=? AND record_digest=?",
                    (*scope, op["prepared_record_digest"]),
                ).fetchone()[0])
                committed, committed_digest = self._append_record(conn, scope, row, {
                    key: value for key, value in prepared.items() if key not in {
                        "schema_version", "authority_id", "key_id", "recorder_principal_id",
                        "anchor_sequence", "previous_anchor_record_digest", "signature"
                    }
                } | {"transition": "COMMITTED", "prepared_record_digest": op["prepared_record_digest"]})
                conn.execute(
                    "UPDATE recovery_operations SET state='COMMITTED' WHERE domain_id=? AND experiment_id=? AND epoch=? AND operation_id=?",
                    (*scope, operation),
                )
                conn.execute(
                    "UPDATE recovery_runs SET event_sequence=?,event_root=? WHERE domain_id=? AND experiment_id=? AND epoch=?",
                    (event.sequence, digest, *scope),
                )
                conn.execute("COMMIT")
                return committed
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def abort(self, event_value: dict, reason_code: str) -> dict:
        if reason_code not in ABORT_CODES:
            raise RecoveryAnchorError("ANCHOR_ABORT_CODE_INVALID")
        event = Event.model_validate(event_value)
        context = Context(domain_id=event.domain_id, experiment_id=event.experiment_id, epoch=event.epoch)
        digest = event_digest(event)
        operation = operation_id(context, event.sequence, digest)
        with closing(self._connect()) as conn:
            scope, row = self._begin(conn, context)
            try:
                op = conn.execute(
                    "SELECT * FROM recovery_operations WHERE domain_id=? AND experiment_id=? AND epoch=? AND operation_id=?",
                    (*scope, operation),
                ).fetchone()
                if not op:
                    raise RecoveryAnchorError("ANCHOR_ABORT_REQUIRES_PREPARED")
                if op["state"] == "ABORTED":
                    old = conn.execute(
                        "SELECT record_json FROM recovery_records WHERE domain_id=? AND experiment_id=? AND epoch=? AND operation_id=? AND transition='ABORTED'",
                        (*scope, operation),
                    ).fetchone()
                    conn.execute("COMMIT")
                    return json.loads(old[0])
                if op["state"] != "PREPARED":
                    raise RecoveryAnchorError("ANCHOR_ABORT_REQUIRES_PREPARED")
                prepared = json.loads(conn.execute(
                    "SELECT record_json FROM recovery_records WHERE domain_id=? AND experiment_id=? AND epoch=? AND record_digest=?",
                    (*scope, op["prepared_record_digest"]),
                ).fetchone()[0])
                aborted, _ = self._append_record(conn, scope, row, {
                    key: value for key, value in prepared.items() if key not in {
                        "schema_version", "authority_id", "key_id", "recorder_principal_id",
                        "anchor_sequence", "previous_anchor_record_digest", "signature"
                    }
                } | {"transition": "ABORTED", "prepared_record_digest": op["prepared_record_digest"],
                     "abort_reason_code": reason_code})
                conn.execute(
                    "UPDATE recovery_operations SET state='ABORTED' WHERE domain_id=? AND experiment_id=? AND epoch=? AND operation_id=?",
                    (*scope, operation),
                )
                conn.execute("COMMIT")
                return aborted
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def terminal_close(self, checkpoint_value: dict, witness_value: dict, integrity: str) -> dict:
        checkpoint = SignedCheckpoint.model_validate(checkpoint_value)
        witness = SignedWitnessClose.model_validate(witness_value)
        context = Context(domain_id=checkpoint.checkpoint.domain_id,
                          experiment_id=checkpoint.checkpoint.experiment_id,
                          epoch=checkpoint.checkpoint.epoch)
        cp = checkpoint.checkpoint
        witness_payload = witness.model_dump(mode="json")
        witness_sha = hashlib.sha256(_canonical(witness_payload)).hexdigest()
        cp_sha = checkpoint_digest(cp)
        operation = terminal_operation_id(context, cp.event_count, cp.final_root, cp_sha, witness_sha, integrity)
        with closing(self._connect()) as conn:
            scope, row = self._begin(conn, context)
            try:
                old = conn.execute(
                    "SELECT record_json FROM recovery_records WHERE domain_id=? AND experiment_id=? AND epoch=? AND operation_id=? AND transition='TERMINAL_CLOSED'",
                    (*scope, operation),
                ).fetchone()
                if old:
                    conn.execute("COMMIT")
                    return json.loads(old[0])
                unresolved = conn.execute(
                    "SELECT 1 FROM recovery_operations WHERE domain_id=? AND experiment_id=? AND epoch=? AND state='PREPARED'",
                    scope,
                ).fetchone()
                if row["terminal"] or unresolved or cp.event_count != row["event_sequence"] or cp.final_root != row["event_root"]:
                    raise RecoveryAnchorError("ANCHOR_TERMINAL_COMPARE_AND_SWAP_FAILED")
                record, _ = self._append_record(conn, scope, row, {
                    "transition": "TERMINAL_CLOSED", "domain_id": context.domain_id,
                    "experiment_id": context.experiment_id, "epoch": context.epoch,
                    "operation_id": operation, "recorder_event_count": cp.event_count,
                    "final_event_root": cp.final_root, "checkpoint_digest": cp_sha,
                    "witness_close_digest": witness_sha, "final_integrity": integrity,
                })
                conn.execute(
                    "UPDATE recovery_runs SET terminal=1 WHERE domain_id=? AND experiment_id=? AND epoch=?",
                    scope,
                )
                conn.execute("COMMIT")
                return record
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def records(self, context: Context) -> list[dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = list(conn.execute(
                "SELECT record_json,record_digest FROM recovery_records WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY anchor_sequence",
                self._scope(context),
            ))
        records = []
        for row in rows:
            try:
                record = json.loads(row["record_json"])
            except Exception as exc:
                raise RecoveryAnchorError("ANCHOR_RECORD_JSON_INVALID") from exc
            if record_digest(record) != row["record_digest"]:
                raise RecoveryAnchorError("ANCHOR_RECORD_INDEX_MISMATCH")
            records.append(record)
        verify_anchor_records(
            records, context, self.private_key.public_key().public_bytes_raw(),
            self.key_id, self.authority_id,
        )
        return records
