"""Read-only identity inspection of quiescent SQLite copies; never resume authority.

The operator must first make quiescent copies without SQLite sidecars. Matching
metadata is not an independent freshness anchor, rollback detection, evidence
verification, or authorization to reuse an owner, queue, lane, or quarantine.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from arena.contracts.common import Context
from arena.contracts.crypto import verify, witness_message
from arena.contracts.evidence import WitnessStart


class Reason(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    QUIESCENT_COPY_REQUIRED = "QUIESCENT_COPY_REQUIRED"
    PUBLIC_KEY_INVALID = "PUBLIC_KEY_INVALID"
    INDEPENDENT_AUTHORITIES_REQUIRED = "INDEPENDENT_AUTHORITIES_REQUIRED"
    SNAPSHOT_MISSING = "SNAPSHOT_MISSING"
    SNAPSHOT_FILE_INVALID = "SNAPSHOT_FILE_INVALID"
    SNAPSHOT_SIDECAR_PRESENT = "SNAPSHOT_SIDECAR_PRESENT"
    SNAPSHOT_CHANGED = "SNAPSHOT_CHANGED"
    SNAPSHOT_INVALID = "SNAPSHOT_INVALID"
    AUTHORITY_MISMATCH = "AUTHORITY_MISMATCH"
    CONTEXT_NOT_REGISTERED = "CONTEXT_NOT_REGISTERED"
    MANIFEST_MISMATCH = "MANIFEST_MISMATCH"
    START_RECEIPT_INVALID = "START_RECEIPT_INVALID"
    WATERMARK_MISSING = "WATERMARK_MISSING"
    STALE_CONTEXT = "STALE_CONTEXT"
    WATERMARK_INVALID = "WATERMARK_INVALID"
    COLD_RESUME_UNSUPPORTED = "COLD_RESUME_UNSUPPORTED"


class _Refusal(Exception):
    def __init__(self, reason: Reason):
        self.reason = reason


def _result(reason: Reason, matched: bool = False) -> dict:
    return {
        "status": "REFUSED",
        "reason": reason.value,
        "trusted_resume_authorized": False,
        "snapshot_identity_matches": matched,
        "scope": "QUIESCENT_SNAPSHOT_IDENTITY_ONLY",
        "independent_freshness": "NOT_ESTABLISHED",
        "automated_cold_resume": "NOT_IMPLEMENTED",
    }


def _fingerprint(path: Path) -> tuple:
    if path.is_symlink():
        raise _Refusal(Reason.SNAPSHOT_FILE_INVALID)
    try:
        before = path.stat()
        if not path.is_file() or before.st_size > 256 * 1024 * 1024:
            raise _Refusal(Reason.SNAPSHOT_FILE_INVALID)
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = path.stat()
    except FileNotFoundError:
        raise _Refusal(Reason.SNAPSHOT_MISSING) from None
    signature = lambda value: (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if signature(before) != signature(after):
        raise _Refusal(Reason.SNAPSHOT_CHANGED)
    return (*signature(after), digest)


def _no_sidecars(paths: tuple[Path, Path]) -> None:
    for path in paths:
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = path.with_name(path.name + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                raise _Refusal(Reason.SNAPSHOT_SIDECAR_PRESENT)


def _open(path: Path, tables: tuple[str, ...]) -> sqlite3.Connection:
    # No constructor for recorder/witness is used: those can initialize stores.
    connection = sqlite3.connect(
        path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True, timeout=0,
    )
    try:
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1_000_000)
        if connection.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
            raise _Refusal(Reason.SNAPSHOT_INVALID)
        for table in tables:
            row = connection.execute(
                "SELECT type,sql FROM sqlite_schema WHERE name=?", (table,),
            ).fetchone()
            if not row or row[0] != "table" or not row[1].upper().startswith("CREATE TABLE"):
                raise _Refusal(Reason.SNAPSHOT_INVALID)
        return connection
    except BaseException:
        connection.close()
        raise


def _inspect(recorder, witness, context, manifest, recorder_key, recorder_id,
             witness_key, witness_id) -> None:
    identities = recorder.execute("SELECT key,value FROM recorder_identity").fetchmany(3)
    authorities = witness.execute(
        "SELECT identity,value FROM authority_metadata",
    ).fetchmany(5)
    if len(identities) != 2 or len(authorities) != 4:
        raise _Refusal(Reason.AUTHORITY_MISMATCH)
    identity, authority = dict(identities), dict(authorities)
    if identity != {"key_id": recorder_id, "public_key": recorder_key.hex()} or authority != {
        "witness_key_id": witness_id, "public_key": witness_key.hex(),
        "recorder_key": recorder_key.hex(), "recorder_key_id": recorder_id,
    }:
        raise _Refusal(Reason.AUTHORITY_MISMATCH)
    binding = (context.domain_id, context.experiment_id, context.epoch)
    run = recorder.execute(
        "SELECT manifest_digest FROM runs WHERE domain_id=? AND experiment_id=? AND epoch=?",
        binding,
    ).fetchone()
    start = witness.execute(
        "SELECT manifest_digest,receipt_json,signature FROM start_receipts "
        "WHERE domain_id=? AND experiment_id=? AND epoch=?", binding,
    ).fetchone()
    if run is None or start is None:
        raise _Refusal(Reason.CONTEXT_NOT_REGISTERED)
    if run[0] != manifest or start[0] != manifest:
        raise _Refusal(Reason.MANIFEST_MISMATCH)
    try:
        receipt = WitnessStart.model_validate_json(start[1])
        if (
            any(getattr(receipt, name) != value for name, value in context.model_dump().items())
            or receipt.public_manifest_digest != manifest
            or receipt.witness_key_id != witness_id
            or not verify(witness_message(receipt), start[2], witness_key)
        ):
            raise _Refusal(Reason.START_RECEIPT_INVALID)
    except (ValidationError, ValueError, TypeError):
        raise _Refusal(Reason.START_RECEIPT_INVALID) from None
    domain = witness.execute(
        "SELECT highest_reserved,experiment_id,epoch FROM domain_reservations WHERE domain_id=?",
        (context.domain_id,),
    ).fetchone()
    watermark = witness.execute(
        "SELECT highest_committed_epoch,current_active_epoch FROM epoch_watermarks "
        "WHERE domain_id=? AND experiment_id=?", binding[:2],
    ).fetchone()
    if domain is None or watermark is None:
        raise _Refusal(Reason.WATERMARK_MISSING)
    if (
        type(domain[0]) is not int or type(domain[2]) is not int
        or type(watermark[0]) is not int or watermark[0] < 0
        or (watermark[1] is not None and type(watermark[1]) is not int)
    ):
        raise _Refusal(Reason.WATERMARK_INVALID)
    if domain != (context.epoch, context.experiment_id, context.epoch):
        raise _Refusal(Reason.STALE_CONTEXT)
    active = watermark[1]
    if watermark[0] > context.epoch or (active is not None and active != context.epoch):
        raise _Refusal(Reason.STALE_CONTEXT)
    if not (
        (0 <= watermark[0] < context.epoch and active == context.epoch)
        or (watermark[0] == context.epoch and active is None)
    ):
        raise _Refusal(Reason.WATERMARK_INVALID)


def inspect_snapshot(
    recorder_db: Path, witness_db: Path, expected_context: Context,
    expected_manifest: str, recorder_public_key: bytes, recorder_key_id: str,
    witness_public_key: bytes, witness_key_id: str, *, quiescent_copy: bool = False,
) -> dict:
    """Return local refusal metadata. Identity consistency never authorizes resume."""
    paths = (Path(recorder_db), Path(witness_db))
    before = None
    result = _result(Reason.SNAPSHOT_INVALID)
    try:
        if not quiescent_copy:
            raise _Refusal(Reason.QUIESCENT_COPY_REQUIRED)
        if (
            not isinstance(expected_context, Context)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_manifest)
            or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", key_id)
                   for key_id in (recorder_key_id, witness_key_id))
        ):
            raise _Refusal(Reason.INVALID_INPUT)
        if any(type(key) is not bytes or len(key) != 32
               for key in (recorder_public_key, witness_public_key)):
            raise _Refusal(Reason.PUBLIC_KEY_INVALID)
        if recorder_key_id == witness_key_id or recorder_public_key == witness_public_key:
            raise _Refusal(Reason.INDEPENDENT_AUTHORITIES_REQUIRED)
        _no_sidecars(paths)
        before = tuple(_fingerprint(path) for path in paths)
        if before[0][:2] == before[1][:2]:
            raise _Refusal(Reason.INDEPENDENT_AUTHORITIES_REQUIRED)
        with closing(_open(paths[0], ("recorder_identity", "runs"))) as recorder:
            with closing(_open(paths[1], (
                "authority_metadata", "start_receipts", "domain_reservations", "epoch_watermarks",
            ))) as witness:
                _inspect(recorder, witness, expected_context, expected_manifest,
                         recorder_public_key, recorder_key_id, witness_public_key, witness_key_id)
        result = _result(Reason.COLD_RESUME_UNSUPPORTED, matched=True)
    except _Refusal as error:
        result = _result(error.reason)
    except (OSError, sqlite3.Error, ValueError, TypeError):
        result = _result(Reason.SNAPSHOT_INVALID)
    finally:
        if before is not None:
            try:
                _no_sidecars(paths)
                if tuple(_fingerprint(path) for path in paths) != before:
                    raise _Refusal(Reason.SNAPSHOT_CHANGED)
            except (_Refusal, OSError):
                result = _result(Reason.SNAPSHOT_CHANGED)
    return result


def _public_key(path: Path) -> bytes:
    # Only public PEM input: no ambiguous raw 32-byte private seeds or private PEM.
    try:
        if path.is_symlink() or path.stat().st_size > 4096:
            raise ValueError
        before = _fingerprint(path)
        key = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(key, Ed25519PublicKey) or _fingerprint(path) != before:
            raise ValueError
        return key.public_bytes_raw()
    except (OSError, ValueError, _Refusal):
        raise _Refusal(Reason.PUBLIC_KEY_INVALID) from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _Refusal(Reason.INVALID_INPUT)


def main(argv=None) -> int:
    parser = _Parser(description=__doc__, add_help=False)
    parser.add_argument("--help", action="store_true")
    parser.add_argument("--quiescent-copy", action="store_true")
    for name in ("recorder-db", "witness-db", "recorder-public-key", "witness-public-key"):
        parser.add_argument("--" + name, type=Path)
    for name in ("domain-id", "experiment-id", "epoch", "manifest", "recorder-key-id", "witness-key-id"):
        parser.add_argument("--" + name)
    try:
        args = parser.parse_args(argv)
        if args.help:
            result = _result(Reason.INVALID_INPUT)
            result["usage"] = parser.format_help()
        elif any(value is None for value in vars(args).values()):
            raise _Refusal(Reason.INVALID_INPUT)
        else:
            context = Context(domain_id=args.domain_id, experiment_id=args.experiment_id,
                              epoch=int(args.epoch))
            result = inspect_snapshot(
                args.recorder_db, args.witness_db, context, args.manifest,
                _public_key(args.recorder_public_key), args.recorder_key_id,
                _public_key(args.witness_public_key), args.witness_key_id,
                quiescent_copy=args.quiescent_copy,
            )
    except _Refusal as error:
        result = _result(error.reason)
    except (ValidationError, ValueError, TypeError):
        result = _result(Reason.INVALID_INPUT)
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
