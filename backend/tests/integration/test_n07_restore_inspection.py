"""Actual administrative subprocess inspection: identity never authorizes resume."""

import asyncio
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.common import Context
from arena.contracts.crypto import event_digest
from arena.contracts.evidence import EventProposal, WitnessStart
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority


def file_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def snapshot_case(tmp_path):
    recorder_key, witness_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    recorder_public = recorder_key.public_key().public_bytes_raw()
    context = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    manifest = "a" * 64
    live_recorder, live_witness = tmp_path / "live-recorder.db", tmp_path / "live-witness.db"
    recorder = DurableRecorder(live_recorder, recorder_key.private_bytes_raw(), "recorder")
    recorder.register_run(context, manifest, actor_id="broker")
    event = asyncio.run(recorder.append_once(EventProposal(
        **context.model_dump(), session_id=None, turn_id=None, turn_index=None,
        event_type="START_RESERVED", outcome_code="OK", artifact_ciphertext_refs=(), duration_us=0,
    ), "broker", str(uuid4())))
    start = WitnessStart(
        **context.model_dump(), schema_version="arena.v2", receipt_type="START",
        public_manifest_digest=manifest, reservation_id=str(uuid4()),
        event_count=event.sequence, prefix_root=event_digest(event), witness_key_id="witness",
    )
    witness = SQLiteWitnessAuthority(
        live_witness, witness_key.private_bytes_raw(), "witness", initialize_if_missing=True,
        recorder_public_key=recorder_public, recorder_key_id="recorder",
    )
    asyncio.run(witness.reserve_start_authenticated(start, recorder.authorize_start(start, "broker")))
    snapshots = [tmp_path / "recorder-copy.db", tmp_path / "witness-copy.db"]
    for source, target in zip((live_recorder, live_witness), snapshots):
        with closing(sqlite3.connect(source)) as src, closing(sqlite3.connect(target)) as dst:
            src.backup(dst)
    public_files = [tmp_path / "recorder-public.pem", tmp_path / "witness-public.pem"]
    for path, key in zip(public_files, (recorder_key, witness_key)):
        path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    command = [sys.executable, "-m", "arena.integration.recovery", "--quiescent-copy",
               "--recorder-db", str(snapshots[0]), "--witness-db", str(snapshots[1]),
               "--recorder-public-key", str(public_files[0]), "--witness-public-key", str(public_files[1]),
               "--recorder-key-id", "recorder", "--witness-key-id", "witness",
               "--domain-id", context.domain_id, "--experiment-id", context.experiment_id,
               "--epoch", "1", "--manifest", manifest]
    return tmp_path, command, snapshots, public_files


def invoke_unchanged(case, command=None):
    root, base, _, _ = case
    before = file_hashes(root)
    ran = subprocess.run(command or base, capture_output=True, timeout=15)
    assert ran.returncode == 2 and ran.stderr == b""
    value = json.loads(ran.stdout)
    assert value["status"] == "REFUSED" and value["trusted_resume_authorized"] is False
    assert value["independent_freshness"] == "NOT_ESTABLISHED"
    assert value["automated_cold_resume"] == "NOT_IMPLEMENTED"
    assert file_hashes(root) == before
    assert all(str(root).encode() not in stream for stream in (ran.stdout, ran.stderr))
    return value


def replace_argument(command, name, value):
    result = list(command)
    result[result.index(name) + 1] = str(value)
    return result


def test_matching_authenticated_snapshots_are_read_only_and_never_resume(snapshot_case):
    value = invoke_unchanged(snapshot_case)
    assert value["snapshot_identity_matches"] is True
    assert value["reason"] == "COLD_RESUME_UNSUPPORTED"


@pytest.mark.parametrize("which", [0, 1])
def test_missing_snapshot_is_not_created(snapshot_case, which):
    snapshot_case[2][which].unlink()
    value = invoke_unchanged(snapshot_case)
    assert value["reason"] == "SNAPSHOT_MISSING"
    assert not snapshot_case[2][which].exists()


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_live_sidecars_are_refused_without_opening_or_removing_them(snapshot_case, suffix):
    path = snapshot_case[2][0]
    path.with_name(path.name + suffix).write_bytes(b"not a quiescent copy")
    assert invoke_unchanged(snapshot_case)["reason"] == "SNAPSHOT_SIDECAR_PRESENT"


@pytest.mark.parametrize("which", [0, 1])
def test_corrupt_snapshots_cannot_be_initialized_or_repaired(snapshot_case, which):
    snapshot_case[2][which].write_bytes(b"invalid sqlite snapshot")
    assert invoke_unchanged(snapshot_case)["reason"] == "SNAPSHOT_INVALID"


@pytest.mark.parametrize("name,value,reason", [
    ("--recorder-key-id", "other", "AUTHORITY_MISMATCH"),
    ("--witness-key-id", "other", "AUTHORITY_MISMATCH"),
    ("--domain-id", "00000000-0000-0000-0000-000000000001", "CONTEXT_NOT_REGISTERED"),
    ("--manifest", "b" * 64, "MANIFEST_MISMATCH"),
])
def test_wrong_external_expectations_do_not_authorize_or_mutate(snapshot_case, name, value, reason):
    command = replace_argument(snapshot_case[1], name, value)
    assert invoke_unchanged(snapshot_case, command)["reason"] == reason


def test_wrong_public_key_and_private_key_material_are_refused(snapshot_case):
    public_file = snapshot_case[3][0]
    key = Ed25519PrivateKey.generate()
    public_file.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    assert invoke_unchanged(snapshot_case)["reason"] == "AUTHORITY_MISMATCH"
    public_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    assert invoke_unchanged(snapshot_case)["reason"] == "PUBLIC_KEY_INVALID"


def test_newer_domain_watermark_refuses_old_context(snapshot_case):
    with closing(sqlite3.connect(snapshot_case[2][1])) as conn:
        conn.execute("UPDATE domain_reservations SET highest_reserved=2,epoch=2")
        conn.commit()
    assert invoke_unchanged(snapshot_case)["reason"] == "STALE_CONTEXT"


def test_signed_start_substitution_is_not_metadata_match(snapshot_case):
    with closing(sqlite3.connect(snapshot_case[2][1])) as conn:
        conn.execute("UPDATE start_receipts SET signature=?", ("0" * 128,))
        conn.commit()
    assert invoke_unchanged(snapshot_case)["reason"] == "START_RECEIPT_INVALID"


def test_explicit_quiescent_copy_declaration_is_required(snapshot_case):
    command = [item for item in snapshot_case[1] if item != "--quiescent-copy"]
    assert invoke_unchanged(snapshot_case, command)["reason"] == "QUIESCENT_COPY_REQUIRED"
