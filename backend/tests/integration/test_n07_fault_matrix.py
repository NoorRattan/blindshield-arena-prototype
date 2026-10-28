"""Real SQLite subprocess crash and fault durability matrix for N07 (BAR-3, T-008, P-015).

Real subprocess cases cover recorder/witness commit and lost-ACK boundaries;
separate in-process artifact mutations and synthetic model exception cases cover
their narrower failure paths. Raw SQLite rollback is distinct from crashing the
actual recorder append implementation. These are bounded component observations.
"""

import asyncio
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.common import Context
from arena.contracts.crypto import (
    checkpoint_digest,
    checkpoint_message,
    event_digest,
    sign,
    witness_message,
)
from arena.contracts.evidence import (
    ArtifactRef,
    Checkpoint,
    EventProposal,
    SignedCheckpoint,
    TurnReceipt,
    WitnessClose,
    WitnessStart,
)
from arena.ports import DependencyUnavailable
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority
from test_n04 import environment, payload, turn, verify_export


# ---------------------------------------------------------------------------
# Fault Window 1: Before durable append commit
# ---------------------------------------------------------------------------

CHILD_FAULT_1 = """
import os, pathlib, sys, sqlite3
db_path = pathlib.Path(sys.argv[1])
sync_file = pathlib.Path(sys.argv[2])
domain_id = sys.argv[3]
exp_id = sys.argv[4]
epoch = int(sys.argv[5])
commit_mode = sys.argv[6] if len(sys.argv) > 6 else "rollback"

conn = sqlite3.connect(str(db_path))
conn.execute("PRAGMA journal_mode = WAL;")
conn.execute("BEGIN IMMEDIATE;")
conn.execute(
    "INSERT INTO events (domain_id, experiment_id, epoch, sequence, operation_id, canonical_json, digest, previous_digest) "
    "VALUES (?, ?, ?, 2, 'uncommitted_op_seq_2', '{}', '1' * 64, '0' * 64);",
    (domain_id, exp_id, epoch),
)
if commit_mode == "commit":
    conn.commit()

sync_file.write_text("inserted")
# Abruptly exit before commit in normal rollback mode
os._exit(42)
"""


def test_fault_window_1_crash_before_append_commit_rolls_back_cleanly(tmp_path):
    """Raw SQLite rollback control; this case does not invoke the recorder in the child."""
    db_path = tmp_path / "recorder_f1.sqlite3"
    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    recorder = DurableRecorder(db_path, rec_priv, "rec-f1")
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    manifest = "a" * 64
    recorder.register_run(ctx, manifest, actor_id="broker")

    # 1. Establish known committed prefix at sequence 1
    prefix_prop = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="START_RESERVED",
        outcome_code="OK",
        artifact_ciphertext_refs=(),
        duration_us=100,
    )
    ev1 = asyncio.run(recorder.append_once(prefix_prop, "broker", str(uuid4())))
    assert ev1.sequence == 1
    assert len(recorder.get_events(ctx)) == 1

    # Assert database contents before crash: exactly 1 committed row
    with closing(sqlite3.connect(str(db_path))) as conn:
        before_count = conn.execute(
            "SELECT count(*) FROM events WHERE domain_id=? AND experiment_id=? AND epoch=?",
            (ctx.domain_id, ctx.experiment_id, ctx.epoch),
        ).fetchone()[0]
        assert before_count == 1

    # 2. Run child process that inserts an uncommitted row at sequence 2 under the actual tested context
    sync_file = tmp_path / "f1_sync.txt"
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            CHILD_FAULT_1,
            str(db_path),
            str(sync_file),
            ctx.domain_id,
            ctx.experiment_id,
            str(ctx.epoch),
            "rollback",
        ],
        capture_output=True,
        timeout=15,
    )
    assert proc.returncode == 42
    assert sync_file.read_text() == "inserted"

    # Assert database contents AFTER crash, BEFORE retrying:
    # uncommitted row rolled back, database still has exactly 1 event
    with closing(sqlite3.connect(str(db_path))) as conn:
        after_count = conn.execute(
            "SELECT count(*) FROM events WHERE domain_id=? AND experiment_id=? AND epoch=?",
            (ctx.domain_id, ctx.experiment_id, ctx.epoch),
        ).fetchone()[0]
        assert after_count == 1
        uncommitted_check = conn.execute(
            "SELECT count(*) FROM events WHERE operation_id='uncommitted_op_seq_2'"
        ).fetchone()[0]
        assert uncommitted_check == 0

    events = recorder.get_events(ctx)
    assert len(events) == 1
    assert events[0].sequence == 1

    # 3. Subsequent legitimate append receives sequence 2 without sequence gap or fabricated row
    prop2 = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="INTEGRITY_VIOLATION",
        outcome_code="INVALID",
        artifact_ciphertext_refs=(),
        duration_us=0,
    )
    ev2 = asyncio.run(recorder.append_once(prop2, "broker", str(uuid4())))
    assert ev2.sequence == 2
    assert ev2.previous_digest == event_digest(ev1)
    assert len(recorder.get_events(ctx)) == 2


def test_fault_window_1_negative_control_committed_row_fails_rollback(tmp_path):
    """Negative control: an intentionally committed row violates the rollback check."""
    db_path = tmp_path / "recorder_f1_neg.sqlite3"
    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    recorder = DurableRecorder(db_path, rec_priv, "rec-f1-neg")
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    recorder.register_run(ctx, "a" * 64, actor_id="broker")

    prefix_prop = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="START_RESERVED",
        outcome_code="OK",
        artifact_ciphertext_refs=(),
        duration_us=100,
    )
    asyncio.run(recorder.append_once(prefix_prop, "broker", str(uuid4())))

    sync_file = tmp_path / "f1_neg_sync.txt"
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            CHILD_FAULT_1,
            str(db_path),
            str(sync_file),
            ctx.domain_id,
            ctx.experiment_id,
            str(ctx.epoch),
            "commit",  # Intentionally commits unexpected row
        ],
        capture_output=True,
        timeout=15,
    )
    assert proc.returncode == 42

    with closing(sqlite3.connect(str(db_path))) as conn:
        count = conn.execute(
            "SELECT count(*) FROM events WHERE domain_id=? AND experiment_id=?",
            (ctx.domain_id, ctx.experiment_id),
        ).fetchone()[0]
        # Proves that committed row increases count to 2, failing any rollback assertion expecting 1
        assert count == 2


# ---------------------------------------------------------------------------
# Real recorder append immediately before COMMIT, using a child-only connection.
# ---------------------------------------------------------------------------

CHILD_APPEND_BEFORE_COMMIT = """
import asyncio, json, os, pathlib, sqlite3, sys
from arena.contracts.evidence import EventProposal
from arena.recorder.recorder import DurableRecorder
root = pathlib.Path(sys.argv[1])
config = json.loads((root / 'append-before-commit.json').read_bytes())
connect = sqlite3.connect
class CrashBeforeCommit(sqlite3.Connection):
    inserted_event = False
    def execute(self, sql, parameters=()):
        normalized = ' '.join(sql.upper().split()).rstrip(';')
        if normalized == 'COMMIT' and self.inserted_event:
            row = super().execute(
                'SELECT sequence,operation_id,canonical_json FROM events WHERE operation_id=?',
                (config['operation'],)).fetchone()
            assert self.in_transaction and row is not None
            marker = dict(sequence=row[0], operation_id=row[1], event=json.loads(row[2]))
            (root / 'append-before-commit-reached.json').write_text(json.dumps(marker))
            os._exit(43)
        result = super().execute(sql, parameters)
        if normalized.startswith('INSERT INTO EVENTS '):
            self.inserted_event = True
        return result
def intercepted_connect(*args, **kwargs):
    return connect(*args, **(kwargs | {'factory': CrashBeforeCommit}))
sqlite3.connect = intercepted_connect
recorder = DurableRecorder(root / 'real-append.sqlite3', (root / 'real-append.key').read_bytes(), 'real-append')
asyncio.run(recorder.append_once(EventProposal.model_validate(config['proposal']), 'broker', config['operation']))
raise SystemExit('CRASH_WINDOW_NOT_REACHED')
"""


def test_actual_recorder_append_crash_immediately_before_commit_preserves_prefix(tmp_path):
    key = Ed25519PrivateKey.generate().private_bytes_raw()
    (tmp_path / 'real-append.key').write_bytes(key)
    recorder = DurableRecorder(tmp_path / 'real-append.sqlite3', key, 'real-append')
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    recorder.register_run(ctx, 'a' * 64, actor_id='broker')
    proposal = EventProposal(**ctx.model_dump(), session_id=None, turn_id=None,
        turn_index=None, event_type='START_RESERVED', outcome_code='OK',
        artifact_ciphertext_refs=(), duration_us=0)
    prefix = asyncio.run(recorder.append_once(proposal, 'broker', str(uuid4())))
    next_proposal = proposal.model_copy(update={'event_type':'INTEGRITY_VIOLATION', 'outcome_code':'INVALID'})
    operation = str(uuid4())
    (tmp_path / 'append-before-commit.json').write_text(json.dumps(
        {'proposal':next_proposal.model_dump(), 'operation':operation}))
    child = subprocess.run([sys.executable, '-c', CHILD_APPEND_BEFORE_COMMIT, str(tmp_path)],
        capture_output=True, timeout=15)
    assert child.returncode == 43, child.stderr.decode()
    assert child.stdout == b''
    reached = json.loads((tmp_path / 'append-before-commit-reached.json').read_bytes())
    assert reached['sequence'] == 2 and reached['operation_id'] == operation
    assert reached['event']['event_type'] == 'INTEGRITY_VIOLATION'
    assert reached['event']['previous_digest'] == event_digest(prefix)
    restarted = DurableRecorder(tmp_path / 'real-append.sqlite3', key, 'real-append')
    assert restarted.get_events(ctx) == [prefix]
    with closing(sqlite3.connect(tmp_path / 'real-append.sqlite3')) as conn:
        assert conn.execute('SELECT count(*) FROM events WHERE operation_id=?', (operation,)).fetchone()[0] == 0
    acknowledged = asyncio.run(restarted.append_once(next_proposal, 'broker', operation))
    assert acknowledged.sequence == 2 and acknowledged.previous_digest == event_digest(prefix)
    assert asyncio.run(restarted.append_once(next_proposal, 'broker', operation)) == acknowledged
    assert restarted.get_events(ctx) == [prefix, acknowledged]


# Fault Window 2: After append commit, before ACK
CHILD_FAULT_2 = """
import asyncio, json, os, pathlib, sys
from arena.contracts.evidence import EventProposal
from arena.recorder.recorder import DurableRecorder

root = pathlib.Path(sys.argv[1])
config = json.loads((root / "f2_fixture.json").read_bytes())
mode = sys.argv[2]

recorder = DurableRecorder(root / "recorder_f2.sqlite3", (root / "f2.key").read_bytes(), "rec-f2")
prop = EventProposal.model_validate(config["proposal"])
actor = config["actor"]
op_id = config["operation"]

result = asyncio.run(recorder.append_once(prop, actor, op_id))
if mode == "crash_after_commit":
    # Durably committed in SQLite WAL, exit before caller receives return ACK
    os._exit(0)
print(result.model_dump_json())
"""


def test_fault_window_2_crash_after_commit_lost_ack_retry_and_conflict_rejection(tmp_path):
    """Crash after append commit: retry returns original event, one sequence increment; conflicts reject."""
    db_path = tmp_path / "recorder_f2.sqlite3"
    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    (tmp_path / "f2.key").write_bytes(rec_priv)

    recorder = DurableRecorder(db_path, rec_priv, "rec-f2")
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    manifest = "a" * 64
    recorder.register_run(ctx, manifest, actor_id="broker")

    prop = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=str(uuid4()),
        turn_id=str(uuid4()),
        turn_index=0,
        event_type="DISPATCH_INTENT",
        outcome_code="OK",
        artifact_ciphertext_refs=(),
        duration_us=1200,
    )
    op_id = str(uuid4())

    (tmp_path / "f2_fixture.json").write_text(
        json.dumps({"proposal": prop.model_dump(), "actor": "broker", "operation": op_id})
    )

    # 1. Child crashes after commit, before ACK
    lost = subprocess.run(
        [sys.executable, "-c", CHILD_FAULT_2, str(tmp_path), "crash_after_commit"],
        capture_output=True,
        timeout=15,
    )
    assert lost.returncode == 0
    assert lost.stdout == b""

    # Inspect persisted authority in SQLite directly BEFORE parent retries
    with closing(sqlite3.connect(str(db_path))) as conn:
        persisted_row = conn.execute(
            "SELECT sequence, operation_id, digest, canonical_json FROM events WHERE operation_id=?",
            (op_id,),
        ).fetchone()
        assert persisted_row is not None
        assert persisted_row[0] == 1
        assert persisted_row[1] == op_id
        ev_payload = json.loads(persisted_row[3])
        assert ev_payload["actor_id"] == "broker"

        total_before_retry = conn.execute(
            "SELECT count(*) FROM events WHERE domain_id=? AND experiment_id=?",
            (ctx.domain_id, ctx.experiment_id),
        ).fetchone()[0]
        assert total_before_retry == 1

    # 2. Identical retry returns original event without creating an extra record
    retried = asyncio.run(recorder.append_once(prop, "broker", op_id))
    assert retried.sequence == 1
    assert retried.turn_id == prop.turn_id
    assert event_digest(retried) == persisted_row[2]

    # Database count remains exactly 1 (no duplicate row created)
    with closing(sqlite3.connect(str(db_path))) as conn:
        total_after_retry = conn.execute(
            "SELECT count(*) FROM events WHERE domain_id=? AND experiment_id=?",
            (ctx.domain_id, ctx.experiment_id),
        ).fetchone()[0]
        assert total_after_retry == 1

    # 3. Conflicting body under same operation_id raises EVENT_OPERATION_CONFLICT
    conflicting_prop = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=prop.session_id,
        turn_id=str(uuid4()),  # Changed turn_id (conflicting body)
        turn_index=1,
        event_type="DISPATCH_INTENT",
        outcome_code="OK",
        artifact_ciphertext_refs=(),
        duration_us=9999,
    )
    with pytest.raises(DependencyUnavailable, match="EVENT_OPERATION_CONFLICT"):
        asyncio.run(recorder.append_once(conflicting_prop, "broker", op_id))

    # 4. Conflicting actor under same operation_id raises RECORDER_CALLER_DENIED
    with pytest.raises(DependencyUnavailable, match="RECORDER_CALLER_DENIED"):
        asyncio.run(recorder.append_once(prop, "unauthorized_actor", op_id))


# ---------------------------------------------------------------------------
# Fault Window 3: Required ciphertext absent, truncated or substituted
# ---------------------------------------------------------------------------

def test_fault_window_3_ciphertext_absent_truncated_substituted_and_context_mismatch(tmp_path):
    """Artifact ciphertext mutations: missing, truncated, substituted, cross-context fail closed."""
    db_path = tmp_path / "recorder_f3.sqlite3"
    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    recorder = DurableRecorder(db_path, rec_priv, "rec-f3")
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    manifest = "a" * 64
    recorder.register_run(ctx, manifest, actor_id="broker")

    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    art_id = str(uuid4())
    art_file = artifacts_dir / f"{art_id}.bin"
    legit_bytes = b"cipher-dummy-valid-payload-content"
    art_file.write_bytes(legit_bytes)
    legit_sha = hashlib.sha256(legit_bytes).hexdigest()

    # Register legitimate artifact bound to context
    recorder.register_artifact(art_id, legit_sha, str(art_file), context=ctx)
    art_ref = ArtifactRef(artifact_id=art_id, ciphertext_sha256=legit_sha)

    prop = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=str(uuid4()),
        turn_id=str(uuid4()),
        turn_index=0,
        event_type="DISPATCH_INTENT",
        outcome_code="OK",
        artifact_ciphertext_refs=(art_ref,),
        duration_us=500,
    )

    # Case A: Truncated artifact ciphertext fails verification during append_once
    art_file.write_bytes(legit_bytes[:5])
    with pytest.raises(DependencyUnavailable, match="ARTIFACT_BYTES_LOST_OR_CHANGED"):
        asyncio.run(recorder.append_once(prop, "broker", str(uuid4())))

    # Case B: Substituted artifact ciphertext fails verification during append_once
    art_file.write_bytes(b"tampered-bytes-wrong-checksum-123456")
    with pytest.raises(DependencyUnavailable, match="ARTIFACT_BYTES_LOST_OR_CHANGED"):
        asyncio.run(recorder.append_once(prop, "broker", str(uuid4())))

    # Case C: Absent / deleted ciphertext fails during append_once
    art_file.unlink()
    with pytest.raises(DependencyUnavailable, match="ARTIFACT_BYTES_LOST_OR_CHANGED"):
        asyncio.run(recorder.append_once(prop, "broker", str(uuid4())))

    # Restore legitimate artifact for proposal verification
    art_file.write_bytes(legit_bytes)
    ev = asyncio.run(recorder.append_once(prop, "broker", str(uuid4())))
    assert ev.sequence == 1

    # Case D: Missing / unregistered artifact ciphertext ref fails
    unregistered_art_id = str(uuid4())
    bad_ref = ArtifactRef(artifact_id=unregistered_art_id, ciphertext_sha256="0" * 64)
    prop_unregistered = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=str(uuid4()),
        turn_id=str(uuid4()),
        turn_index=1,
        event_type="DISPATCH_INTENT",
        outcome_code="OK",
        artifact_ciphertext_refs=(bad_ref,),
        duration_us=500,
    )
    with pytest.raises(DependencyUnavailable, match="MISSING_ARTIFACT_CIPHERTEXT"):
        asyncio.run(recorder.append_once(prop_unregistered, "broker", str(uuid4())))

    # Case E: Cross-context artifact reference failure
    other_ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    recorder.register_run(other_ctx, manifest, actor_id="broker")

    prop_cross = EventProposal(
        domain_id=other_ctx.domain_id,
        experiment_id=other_ctx.experiment_id,
        epoch=1,
        session_id=str(uuid4()),
        turn_id=str(uuid4()),
        turn_index=0,
        event_type="DISPATCH_INTENT",
        outcome_code="OK",
        artifact_ciphertext_refs=(art_ref,),
        duration_us=500,
    )
    with pytest.raises(DependencyUnavailable, match="ARTIFACT_CONTEXT_MISMATCH"):
        asyncio.run(recorder.append_once(prop_cross, "broker", str(uuid4())))


# ---------------------------------------------------------------------------
# Fault Window 4: Bound-turn authorization interrupted
# ---------------------------------------------------------------------------

CHILD_FAULT_4 = """
import asyncio, json, os, pathlib, sys
from arena.contracts.evidence import ArtifactRef, TurnReceipt
from arena.recorder.recorder import DurableRecorder

root = pathlib.Path(sys.argv[1])
config = json.loads((root / "f4_fixture.json").read_bytes())
receipt = TurnReceipt.model_validate(config["receipt"])
in_ref = ArtifactRef.model_validate(config["input_ref"])
resp_ref = ArtifactRef.model_validate(config["response_ref"])

recorder = DurableRecorder(root / "recorder_f4.sqlite3", (root / "f4.key").read_bytes(), "rec-f4")
signed = asyncio.run(recorder.authorize_bound_turn(receipt, config["actor"], in_ref, resp_ref))
# Committed turn authorization to SQLite, exit before ACK
os._exit(0)
"""


def test_fault_window_4_bound_turn_authorization_crash_retry_and_prefix_mismatch(tmp_path):
    """Bound turn authorization lost ACK: retry returns signed receipt without duplicate record."""
    db_path = tmp_path / "recorder_f4.sqlite3"
    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    (tmp_path / "f4.key").write_bytes(rec_priv)

    recorder = DurableRecorder(db_path, rec_priv, "rec-f4")
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    manifest = "a" * 64
    recorder.register_run(ctx, manifest, actor_id="broker")

    artifacts_dir = tmp_path / "artifacts_f4"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    in_art_id = str(uuid4())
    in_bytes = b"input-artifact-ciphertext"
    (artifacts_dir / f"{in_art_id}.bin").write_bytes(in_bytes)
    in_sha = hashlib.sha256(in_bytes).hexdigest()
    recorder.register_artifact(in_art_id, in_sha, str(artifacts_dir / f"{in_art_id}.bin"), context=ctx)
    in_ref = ArtifactRef(artifact_id=in_art_id, ciphertext_sha256=in_sha)

    resp_art_id = str(uuid4())
    resp_bytes = b"response-artifact-ciphertext"
    (artifacts_dir / f"{resp_art_id}.bin").write_bytes(resp_bytes)
    resp_sha = hashlib.sha256(resp_bytes).hexdigest()
    recorder.register_artifact(resp_art_id, resp_sha, str(artifacts_dir / f"{resp_art_id}.bin"), context=ctx)
    resp_ref = ArtifactRef(artifact_id=resp_art_id, ciphertext_sha256=resp_sha)

    sess_id = str(uuid4())
    t_id = str(uuid4())

    # Append FEEDBACK_AUTHORIZED event to establish actual prefix root
    feedback_prop = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=sess_id,
        turn_id=t_id,
        turn_index=0,
        event_type="FEEDBACK_AUTHORIZED",
        outcome_code="OK",
        artifact_ciphertext_refs=(in_ref, resp_ref),
        duration_us=2000,
    )
    feedback_ev = asyncio.run(recorder.append_once(feedback_prop, "broker", str(uuid4())))

    receipt = TurnReceipt(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=sess_id,
        turn_id=t_id,
        turn_index=0,
        schema_version="arena.v2",
        input_commitment="b" * 64,
        event_count=feedback_ev.sequence,
        prefix_root=event_digest(feedback_ev),
        public_response_commitment="c" * 64,
        signer_key_id="rec-f4",
    )

    (tmp_path / "f4_fixture.json").write_text(
        json.dumps({
            "receipt": receipt.model_dump(),
            "actor": "broker",
            "input_ref": in_ref.model_dump(),
            "response_ref": resp_ref.model_dump(),
        })
    )

    # 1. Child crashes after committing turn authorization
    lost = subprocess.run(
        [sys.executable, "-c", CHILD_FAULT_4, str(tmp_path)],
        capture_output=True,
        timeout=15,
    )
    assert lost.returncode == 0

    # Inspect persisted authority in SQLite directly BEFORE parent retries
    with closing(sqlite3.connect(str(db_path))) as conn:
        persisted_auth = conn.execute(
            "SELECT turn_id, signature FROM turn_authorizations WHERE turn_id=?",
            (t_id,),
        ).fetchone()
        assert persisted_auth is not None
        assert persisted_auth[0] == t_id
        auth_count_before = conn.execute("SELECT count(*) FROM turn_authorizations").fetchone()[0]
        assert auth_count_before == 1

    # 2. Identical retry returns existing signed turn receipt without creating another record
    signed_ack = asyncio.run(recorder.authorize_bound_turn(receipt, "broker", in_ref, resp_ref))
    assert signed_ack.receipt == receipt
    assert signed_ack.signature == persisted_auth[1]

    with closing(sqlite3.connect(str(db_path))) as conn:
        auth_count_after = conn.execute("SELECT count(*) FROM turn_authorizations").fetchone()[0]
        assert auth_count_after == 1

    # 3. Conflicting receipt retry (different public response commitment) raises TURN_AUTHORIZATION_CONFLICT
    conflicting_receipt = TurnReceipt(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=sess_id,
        turn_id=t_id,
        turn_index=0,
        schema_version="arena.v2",
        input_commitment="b" * 64,
        event_count=feedback_ev.sequence,
        prefix_root=event_digest(feedback_ev),
        public_response_commitment="d" * 64,  # conflicting
        signer_key_id="rec-f4",
    )
    with pytest.raises(DependencyUnavailable, match="TURN_AUTHORIZATION_CONFLICT"):
        asyncio.run(recorder.authorize_bound_turn(conflicting_receipt, "broker", in_ref, resp_ref))

    # 4. Mismatched prefix root cannot mint authorization
    fake_receipt = TurnReceipt(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=sess_id,
        turn_id=str(uuid4()),
        turn_index=1,
        schema_version="arena.v2",
        input_commitment="b" * 64,
        event_count=feedback_ev.sequence,
        prefix_root="e" * 64,
        public_response_commitment="c" * 64,
        signer_key_id="rec-f4",
    )
    with pytest.raises(DependencyUnavailable, match="TURN_PREFIX_MISMATCH"):
        asyncio.run(recorder.authorize_bound_turn(fake_receipt, "broker", in_ref, resp_ref))


# ---------------------------------------------------------------------------
# Fault Window 5: Witness START commits before ACK is lost
# ---------------------------------------------------------------------------

CHILD_FAULT_5 = """
import asyncio, json, os, pathlib, sys
from arena.contracts.evidence import WitnessStart
from arena.witness.authority import SQLiteWitnessAuthority

root = pathlib.Path(sys.argv[1])
config = json.loads((root / "f5_fixture.json").read_bytes())
receipt = WitnessStart.model_validate(config["receipt"])
rec_sig = config["recorder_signature"]
rec_pub = bytes.fromhex(config["recorder_pub_hex"])

witness = SQLiteWitnessAuthority(
    root / "witness_f5.sqlite3",
    (root / "f5_wit.key").read_bytes(),
    "wit-f5",
    initialize_if_missing=False,
    recorder_public_key=rec_pub,
    recorder_key_id=config["recorder_key_id"],
)

result = asyncio.run(witness.reserve_start_authenticated(receipt, rec_sig))
# Durably committed to start_receipts and epoch_watermarks, crash before ACK
os._exit(0)
"""


def test_fault_window_5_witness_start_lost_ack_retry_conflict_and_anti_regression(tmp_path):
    """Witness START lost ACK: identical retry returns reservation; conflict/regression rejected."""
    db_path = tmp_path / "witness_f5.sqlite3"
    wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    wit_pub = Ed25519PrivateKey.from_private_bytes(wit_priv).public_key().public_bytes_raw()
    (tmp_path / "f5_wit.key").write_bytes(wit_priv)

    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    rec_pub = Ed25519PrivateKey.from_private_bytes(rec_priv).public_key().public_bytes_raw()
    rec_key_id = "rec-key-f5"

    # Initialize witness store with pinned recorder key
    witness = SQLiteWitnessAuthority(
        db_path,
        wit_priv,
        "wit-f5",
        initialize_if_missing=True,
        recorder_public_key=rec_pub,
        recorder_key_id=rec_key_id,
    )

    domain_id = str(uuid4())
    exp_id = str(uuid4())
    res_id = str(uuid4())
    manifest = "a" * 64

    start_receipt = WitnessStart(
        domain_id=domain_id,
        experiment_id=exp_id,
        epoch=1,
        schema_version="arena.v2",
        receipt_type="START",
        public_manifest_digest=manifest,
        reservation_id=res_id,
        event_count=1,
        prefix_root="0" * 64,
        witness_key_id="wit-f5",
    )

    # Calling unauthenticated reserve_start is component-only and refused when recorder key is pinned
    with pytest.raises(DependencyUnavailable, match="AUTHENTICATED_RECORDER_START_REQUIRED"):
        asyncio.run(witness.reserve_start(start_receipt))

    # Authenticated start requires recorder signature
    recorder_sig = sign(witness_message(start_receipt), rec_priv)

    # Wrong recorder signature fails closed
    with pytest.raises(DependencyUnavailable, match="RECORDER_START_SIGNATURE_INVALID"):
        asyncio.run(witness.reserve_start_authenticated(start_receipt, "0" * 128))

    (tmp_path / "f5_fixture.json").write_text(
        json.dumps({
            "receipt": start_receipt.model_dump(),
            "recorder_signature": recorder_sig,
            "recorder_pub_hex": rec_pub.hex(),
            "recorder_key_id": rec_key_id,
        })
    )

    # 1. Child crashes after committing start reservation via reserve_start_authenticated
    lost = subprocess.run(
        [sys.executable, "-c", CHILD_FAULT_5, str(tmp_path)],
        capture_output=True,
        timeout=15,
    )
    assert lost.returncode == 0

    # Inspect persisted authority in SQLite directly BEFORE parent retries
    with closing(sqlite3.connect(str(db_path))) as conn:
        persisted_start = conn.execute(
            "SELECT reservation_id, signature FROM start_receipts WHERE domain_id=? AND experiment_id=? AND epoch=?",
            (domain_id, exp_id, 1),
        ).fetchone()
        assert persisted_start is not None
        assert persisted_start[0] == res_id

        wm = conn.execute(
            "SELECT highest_committed_epoch, current_active_epoch FROM epoch_watermarks WHERE domain_id=? AND experiment_id=?",
            (domain_id, exp_id),
        ).fetchone()
        assert wm == (0, 1)

        start_count_before = conn.execute(
            "SELECT count(*) FROM start_receipts WHERE domain_id=? AND experiment_id=?",
            (domain_id, exp_id),
        ).fetchone()[0]
        assert start_count_before == 1

    # 2. Identical authenticated retry returns original signed reservation without duplicate record
    retried_start = asyncio.run(witness.reserve_start_authenticated(start_receipt, recorder_sig))
    assert retried_start.receipt == start_receipt
    assert retried_start.signature == persisted_start[1]

    with closing(sqlite3.connect(str(db_path))) as conn:
        start_count_after = conn.execute(
            "SELECT count(*) FROM start_receipts WHERE domain_id=? AND experiment_id=?",
            (domain_id, exp_id),
        ).fetchone()[0]
        assert start_count_after == 1

    # 3. Conflicting start reservation on same epoch (different reservation_id) is rejected
    conflicting_start = WitnessStart(
        domain_id=domain_id,
        experiment_id=exp_id,
        epoch=1,
        schema_version="arena.v2",
        receipt_type="START",
        public_manifest_digest=manifest,
        reservation_id=str(uuid4()),
        event_count=1,
        prefix_root="0" * 64,
        witness_key_id="wit-f5",
    )
    conflicting_sig = sign(witness_message(conflicting_start), rec_priv)
    with pytest.raises(DependencyUnavailable, match="CONFLICTING_START_RESERVATION"):
        asyncio.run(witness.reserve_start_authenticated(conflicting_start, conflicting_sig))

    # Advance watermark via authenticated close checkpoint
    cp = Checkpoint(
        domain_id=domain_id,
        experiment_id=exp_id,
        epoch=1,
        schema_version="arena.v2",
        public_manifest_digest=manifest,
        event_count=2,
        final_root="c" * 64,
        terminal_marker="CLOSED",
        required_artifacts=(),
        signer_key_id=rec_key_id,
    )
    signed_cp = SignedCheckpoint(checkpoint=cp, signature=sign(checkpoint_message(cp), rec_priv))
    asyncio.run(witness.close_checkpoint(signed_cp))

    # 4. Monotonic anti-regression: Attempting to reserve epoch 1 again is rejected
    with pytest.raises(DependencyUnavailable, match="EPOCH_REGRESSION_REJECTED|DOMAIN_EPOCH_REGRESSION_OR_CONFLICT"):
        asyncio.run(witness.reserve_start_authenticated(start_receipt, recorder_sig))


# ---------------------------------------------------------------------------
# Fault Window 6: Concurrent witness START/CLOSE and conflicting checkpoint
# ---------------------------------------------------------------------------

def test_witness_start_requires_actual_recorder_prefix_and_registered_actor(tmp_path):
    """Obtain witness authority through the real recorder guard, not raw key signing."""
    rec_key = Ed25519PrivateKey.generate().private_bytes_raw()
    rec_public = Ed25519PrivateKey.from_private_bytes(rec_key).public_key().public_bytes_raw()
    wit_key = Ed25519PrivateKey.generate().private_bytes_raw()
    recorder = DurableRecorder(tmp_path / 'recorder-start.sqlite3', rec_key, 'recorder-start')
    witness = SQLiteWitnessAuthority(tmp_path / 'witness-start.sqlite3', wit_key, 'witness-start',
        initialize_if_missing=True, recorder_public_key=rec_public, recorder_key_id='recorder-start')
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    recorder.register_run(ctx, 'a'*64, actor_id='broker')
    start = WitnessStart(**ctx.model_dump(), schema_version='arena.v2', receipt_type='START',
        public_manifest_digest='a'*64, reservation_id=str(uuid4()), event_count=1,
        prefix_root='0'*64, witness_key_id='witness-start')
    with pytest.raises(DependencyUnavailable, match='RECORDER_START_AUTHORITY_DENIED'):
        recorder.authorize_start(start, 'broker')
    proposal = EventProposal(**ctx.model_dump(), session_id=None, turn_id=None, turn_index=None,
        event_type='START_RESERVED', outcome_code='OK', artifact_ciphertext_refs=(), duration_us=0)
    prefix = asyncio.run(recorder.append_once(proposal, 'broker', str(uuid4())))
    start = start.model_copy(update={'event_count':prefix.sequence, 'prefix_root':event_digest(prefix)})
    with pytest.raises(DependencyUnavailable, match='RECORDER_START_AUTHORITY_DENIED'):
        recorder.authorize_start(start, 'wrong-actor')
    with pytest.raises(DependencyUnavailable, match='RECORDER_START_AUTHORITY_DENIED'):
        recorder.authorize_start(start.model_copy(update={'public_manifest_digest':'b'*64}), 'broker')
    with pytest.raises(DependencyUnavailable, match='RECORDER_START_PREFIX_MISMATCH'):
        recorder.authorize_start(start.model_copy(update={'prefix_root':'c'*64}), 'broker')
    with pytest.raises(DependencyUnavailable, match='RECORDER_START_PREFIX_MISMATCH'):
        recorder.authorize_start(start.model_copy(update={'event_count':prefix.sequence+1}), 'broker')
    with pytest.raises(DependencyUnavailable, match='RECORDER_START_SIGNATURE_INVALID'):
        asyncio.run(witness.reserve_start_authenticated(start, '0'*128))
    assert witness.watermark(ctx) == (0, None)
    signature = recorder.authorize_start(start, 'broker')
    accepted = asyncio.run(witness.reserve_start_authenticated(start, signature))
    reopened = SQLiteWitnessAuthority(tmp_path / 'witness-start.sqlite3', wit_key, 'witness-start',
        recorder_public_key=rec_public, recorder_key_id='recorder-start')
    assert asyncio.run(reopened.reserve_start_authenticated(start, signature)) == accepted
    assert reopened.watermark(ctx) == (0, ctx.epoch)
    assert recorder.get_events(ctx) == [prefix]
    with closing(sqlite3.connect(tmp_path / 'witness-start.sqlite3')) as conn:
        assert conn.execute('SELECT count(*) FROM start_receipts').fetchone()[0] == 1


CHILD_FAULT_6_START = """
import asyncio, json, os, pathlib, sys, time
from arena.contracts.evidence import WitnessStart
from arena.witness.authority import SQLiteWitnessAuthority
from arena.ports import DependencyUnavailable

root = pathlib.Path(sys.argv[1])
idx = sys.argv[2]
config = json.loads((root / "f6_fixture.json").read_bytes())
receipt_data = dict(config["receipt"])
receipt_data["reservation_id"] = str(config["res_ids"][int(idx)])
receipt = WitnessStart.model_validate(receipt_data)
rec_sig = config["rec_sigs"][int(idx)]
rec_pub = bytes.fromhex(config["recorder_pub_hex"])

witness = SQLiteWitnessAuthority(
    root / "witness_f6.sqlite3",
    (root / "f6_wit.key").read_bytes(),
    "wit-f6",
    initialize_if_missing=False,
    recorder_public_key=rec_pub,
    recorder_key_id=config["recorder_key_id"],
)

# Synchronize via barrier file
(root / f"ready_start_{idx}.txt").write_text("ready")
go_file = root / "go_start.txt"
until = time.monotonic() + (float(sys.argv[3]) if len(sys.argv) > 3 else 7.5)
while time.monotonic() < until:
    if go_file.exists():
        break
    time.sleep(0.05)
if not go_file.exists():
    raise SystemExit(74)

try:
    res = asyncio.run(witness.reserve_start_authenticated(receipt, rec_sig))
    (root / f"start_win_{idx}.txt").write_text("WON")
except DependencyUnavailable as e:
    (root / f"start_win_{idx}.txt").write_text(f"LOST:{e}")
"""

CHILD_FAULT_6_CLOSE = """
import asyncio, json, os, pathlib, sys, time
from arena.contracts.evidence import SignedCheckpoint
from arena.witness.authority import SQLiteWitnessAuthority
from arena.ports import DependencyUnavailable

root = pathlib.Path(sys.argv[1])
idx = sys.argv[2]
config = json.loads((root / "f6_close_fixture.json").read_bytes())
signed_cp = SignedCheckpoint.model_validate(config["signed_cps"][int(idx)])
rec_pub = bytes.fromhex(config["recorder_pub_hex"])

witness = SQLiteWitnessAuthority(
    root / "witness_f6.sqlite3",
    (root / "f6_wit.key").read_bytes(),
    "wit-f6",
    initialize_if_missing=False,
    recorder_public_key=rec_pub,
    recorder_key_id=config["recorder_key_id"],
)

# Synchronize via barrier file
(root / f"ready_close_{idx}.txt").write_text("ready")
go_file = root / "go_close.txt"
until = time.monotonic() + (float(sys.argv[3]) if len(sys.argv) > 3 else 7.5)
while time.monotonic() < until:
    if go_file.exists():
        break
    time.sleep(0.05)
if not go_file.exists():
    raise SystemExit(74)

try:
    res = asyncio.run(witness.close_checkpoint(signed_cp))
    (root / f"close_win_{idx}.txt").write_text("WON")
except DependencyUnavailable as e:
    (root / f"close_win_{idx}.txt").write_text(f"LOST:{e}")
"""


@pytest.mark.parametrize('operation', ['start', 'close'])
def test_witness_race_without_go_exits_before_operation(tmp_path, operation):
    """Timeout cannot silently turn the race harness into serial witness operations."""
    rec_key = Ed25519PrivateKey.generate().private_bytes_raw()
    rec_public = Ed25519PrivateKey.from_private_bytes(rec_key).public_key().public_bytes_raw()
    wit_key = Ed25519PrivateKey.generate().private_bytes_raw()
    (tmp_path / 'f6_wit.key').write_bytes(wit_key)
    witness = SQLiteWitnessAuthority(tmp_path / 'witness_f6.sqlite3', wit_key, 'wit-f6',
        initialize_if_missing=True, recorder_public_key=rec_public, recorder_key_id='rec-f6')
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    start = WitnessStart(**ctx.model_dump(), schema_version='arena.v2', receipt_type='START',
        public_manifest_digest='a'*64, reservation_id=str(uuid4()), event_count=1,
        prefix_root='b'*64, witness_key_id='wit-f6')
    trust = {'recorder_pub_hex':rec_public.hex(), 'recorder_key_id':'rec-f6'}
    if operation == 'start':
        fixture = dict(trust, receipt=start.model_dump(), res_ids=[start.reservation_id],
            rec_sigs=[sign(witness_message(start), rec_key)])
        (tmp_path / 'f6_fixture.json').write_text(json.dumps(fixture))
        script = CHILD_FAULT_6_START
    else:
        asyncio.run(witness.reserve_start_authenticated(start, sign(witness_message(start), rec_key)))
        checkpoint = Checkpoint(**ctx.model_dump(), schema_version='arena.v2', public_manifest_digest='a'*64,
            event_count=2, final_root='c'*64, terminal_marker='CLOSED', required_artifacts=(), signer_key_id='rec-f6')
        signed = SignedCheckpoint(checkpoint=checkpoint, signature=sign(checkpoint_message(checkpoint), rec_key))
        (tmp_path / 'f6_close_fixture.json').write_text(json.dumps(dict(trust, signed_cps=[signed.model_dump()])))
        script = CHILD_FAULT_6_CLOSE
    child = subprocess.run([sys.executable, '-c', script, str(tmp_path), '0', '0.1'],
        capture_output=True, timeout=15)
    assert child.returncode == 74, child.stderr.decode()
    assert (tmp_path / f'ready_{operation}_0.txt').exists()
    assert not (tmp_path / f'{operation}_win_0.txt').exists()
    with closing(sqlite3.connect(tmp_path / 'witness_f6.sqlite3')) as conn:
        assert conn.execute('SELECT count(*) FROM start_receipts').fetchone()[0] == (operation == 'close')
        assert conn.execute('SELECT count(*) FROM close_receipts').fetchone()[0] == 0
    assert witness.watermark(ctx) == ((0, 1) if operation == 'close' else (0, None))


def test_fault_window_6_concurrent_witness_start_and_close_competing_processes(tmp_path):
    """Concurrent witness operations: first accepted identity wins, conflicts reject."""
    db_path = tmp_path / "witness_f6.sqlite3"
    wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    (tmp_path / "f6_wit.key").write_bytes(wit_priv)

    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    rec_pub = Ed25519PrivateKey.from_private_bytes(rec_priv).public_key().public_bytes_raw()
    rec_key_id = "rec-key-f6"

    witness = SQLiteWitnessAuthority(
        db_path,
        wit_priv,
        "wit-f6",
        initialize_if_missing=True,
        recorder_public_key=rec_pub,
        recorder_key_id=rec_key_id,
    )

    domain_id = str(uuid4())
    exp_id = str(uuid4())
    manifest = "a" * 64

    start_base = {
        "domain_id": domain_id,
        "experiment_id": exp_id,
        "epoch": 1,
        "schema_version": "arena.v2",
        "receipt_type": "START",
        "public_manifest_digest": manifest,
        "event_count": 1,
        "prefix_root": "0" * 64,
        "witness_key_id": "wit-f6",
    }
    res_id_0 = str(uuid4())
    res_id_1 = str(uuid4())

    start_0 = WitnessStart.model_validate({**start_base, "reservation_id": res_id_0})
    start_1 = WitnessStart.model_validate({**start_base, "reservation_id": res_id_1})
    rec_sig_0 = sign(witness_message(start_0), rec_priv)
    rec_sig_1 = sign(witness_message(start_1), rec_priv)

    (tmp_path / "f6_fixture.json").write_text(
        json.dumps({
            "receipt": start_base,
            "res_ids": [res_id_0, res_id_1],
            "rec_sigs": [rec_sig_0, rec_sig_1],
            "recorder_pub_hex": rec_pub.hex(),
            "recorder_key_id": rec_key_id,
        })
    )

    # 1. Competing START processes racing with deterministic barrier
    procs_start = [
        subprocess.Popen([sys.executable, "-c", CHILD_FAULT_6_START, str(tmp_path), str(i)])
        for i in range(2)
    ]
    try:
        for i in range(2):
            ready_file = tmp_path / f"ready_start_{i}.txt"
            for _ in range(150):
                if ready_file.exists():
                    break
                time.sleep(0.05)
            assert ready_file.exists(), f"Child start process {i} did not signal ready"
        # Release barrier simultaneously
        (tmp_path / "go_start.txt").write_text("GO")
        for p in procs_start:
            p.communicate(timeout=15)
            assert p.returncode == 0
    finally:
        for p in procs_start:
            if p.poll() is None:
                p.kill()
                p.wait()

    res0 = (tmp_path / "start_win_0.txt").read_text()
    res1 = (tmp_path / "start_win_1.txt").read_text()
    # Exactly one process won and one lost with CONFLICTING_START_RESERVATION
    assert (res0 == "WON" and "LOST:" in res1 and "CONFLICTING_START_RESERVATION" in res1) or \
           (res1 == "WON" and "LOST:" in res0 and "CONFLICTING_START_RESERVATION" in res0)

    # 2. Competing CLOSE processes racing with conflicting checkpoints
    cp_a = Checkpoint(
        domain_id=domain_id,
        experiment_id=exp_id,
        epoch=1,
        schema_version="arena.v2",
        public_manifest_digest=manifest,
        event_count=2,
        final_root="c" * 64,
        terminal_marker="CLOSED",
        required_artifacts=(),
        signer_key_id=rec_key_id,
    )
    signed_cp_a = SignedCheckpoint(checkpoint=cp_a, signature=sign(checkpoint_message(cp_a), rec_priv))

    cp_b = Checkpoint(
        domain_id=domain_id,
        experiment_id=exp_id,
        epoch=1,
        schema_version="arena.v2",
        public_manifest_digest=manifest,
        event_count=2,
        final_root="d" * 64,  # Conflicting root
        terminal_marker="CLOSED",
        required_artifacts=(),
        signer_key_id=rec_key_id,
    )
    signed_cp_b = SignedCheckpoint(checkpoint=cp_b, signature=sign(checkpoint_message(cp_b), rec_priv))

    (tmp_path / "f6_close_fixture.json").write_text(
        json.dumps({
            "signed_cps": [signed_cp_a.model_dump(), signed_cp_b.model_dump()],
            "recorder_pub_hex": rec_pub.hex(),
            "recorder_key_id": rec_key_id,
        })
    )

    procs_close = [
        subprocess.Popen([sys.executable, "-c", CHILD_FAULT_6_CLOSE, str(tmp_path), str(i)])
        for i in range(2)
    ]
    try:
        for i in range(2):
            ready_file = tmp_path / f"ready_close_{i}.txt"
            for _ in range(150):
                if ready_file.exists():
                    break
                time.sleep(0.05)
            assert ready_file.exists(), f"Child close process {i} did not signal ready"
        # Release barrier simultaneously
        (tmp_path / "go_close.txt").write_text("GO")
        for p in procs_close:
            p.communicate(timeout=15)
            assert p.returncode == 0
    finally:
        for p in procs_close:
            if p.poll() is None:
                p.kill()
                p.wait()

    close_res0 = (tmp_path / "close_win_0.txt").read_text()
    close_res1 = (tmp_path / "close_win_1.txt").read_text()
    # Exactly one process committed CLOSE and the other was rejected with CONFLICTING_CLOSE_RECEIPT
    assert (close_res0 == "WON" and "LOST:" in close_res1 and "CONFLICTING_CLOSE_RECEIPT" in close_res1) or \
           (close_res1 == "WON" and "LOST:" in close_res0 and "CONFLICTING_CLOSE_RECEIPT" in close_res0)


# ---------------------------------------------------------------------------
# Fault Window 7: Recorder close or witness close interrupted
# ---------------------------------------------------------------------------

CHILD_FAULT_7_REC = """
import asyncio, json, os, pathlib, sys
from arena.contracts.common import Context
from arena.recorder.recorder import DurableRecorder

root = pathlib.Path(sys.argv[1])
config = json.loads((root / "f7_rec_fixture.json").read_bytes())
ctx = Context.model_validate(config["ctx"])
recorder = DurableRecorder(root / "recorder_f7.sqlite3", (root / "f7_rec.key").read_bytes(), "rec-f7")

result = asyncio.run(recorder.close(ctx))
# Committed checkpoint to SQLite checkpoints table, exit before ACK
os._exit(0)
"""

CHILD_FAULT_7_WIT_CLOSE = """
import asyncio, json, os, pathlib, sys
from arena.contracts.evidence import SignedCheckpoint
from arena.witness.authority import SQLiteWitnessAuthority

root = pathlib.Path(sys.argv[1])
config = json.loads((root / "f7_wit_fixture.json").read_bytes())
signed_cp = SignedCheckpoint.model_validate(config["signed_checkpoint"])
rec_pub = bytes.fromhex(config["recorder_pub_hex"])

witness = SQLiteWitnessAuthority(
    root / "witness_f7.sqlite3",
    (root / "f7_wit.key").read_bytes(),
    "wit-f7",
    initialize_if_missing=False,
    recorder_public_key=rec_pub,
    recorder_key_id=config["recorder_key_id"],
)

result = asyncio.run(witness.close_checkpoint(signed_cp))
# Committed close receipt to SQLite close_receipts table, exit before ACK
os._exit(0)
"""


def test_fault_window_7_recorder_and_witness_close_interrupted_and_missing_authority_refusal(tmp_path):
    """Recorder/witness close interrupted: retry identity preserved; missing authority refused."""
    rec_db = tmp_path / "recorder_f7.sqlite3"
    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    (tmp_path / "f7_rec.key").write_bytes(rec_priv)

    recorder = DurableRecorder(rec_db, rec_priv, "rec-f7")
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    manifest = "a" * 64
    recorder.register_run(ctx, manifest, actor_id="broker")

    closed_prop = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="CLOSED",
        outcome_code="OK",
        artifact_ciphertext_refs=(),
        duration_us=0,
    )
    asyncio.run(recorder.append_once(closed_prop, "broker", str(uuid4())))

    (tmp_path / "f7_rec_fixture.json").write_text(json.dumps({"ctx": ctx.model_dump()}))

    # 1. Child crashes after committing checkpoint in recorder.close
    lost_rec = subprocess.run(
        [sys.executable, "-c", CHILD_FAULT_7_REC, str(tmp_path)],
        capture_output=True,
        timeout=15,
    )
    assert lost_rec.returncode == 0

    # Inspect persisted authority in SQLite directly BEFORE parent retries
    with closing(sqlite3.connect(str(rec_db))) as conn:
        persisted_cp = conn.execute(
            "SELECT checkpoint_json, signature FROM checkpoints WHERE domain_id=? AND experiment_id=? AND epoch=?",
            (ctx.domain_id, ctx.experiment_id, ctx.epoch),
        ).fetchone()
        assert persisted_cp is not None
        cp_payload = json.loads(persisted_cp[0])
        assert cp_payload["event_count"] == 1
        persisted_sig = persisted_cp[1]
        cp_count_before = conn.execute("SELECT count(*) FROM checkpoints").fetchone()[0]
        assert cp_count_before == 1

    # 2. Retrying recorder close returns exact signed checkpoint without creating duplicate row
    signed_cp = asyncio.run(recorder.close(ctx))
    assert signed_cp.checkpoint.event_count == 1
    assert signed_cp.signature == persisted_sig

    with closing(sqlite3.connect(str(rec_db))) as conn:
        cp_count_after = conn.execute("SELECT count(*) FROM checkpoints").fetchone()[0]
        assert cp_count_after == 1

    # Appends after close are denied
    extra_prop = EventProposal(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="INTEGRITY_VIOLATION",
        outcome_code="INVALID",
        artifact_ciphertext_refs=(),
        duration_us=0,
    )
    with pytest.raises(DependencyUnavailable, match="APPEND_AFTER_CLOSE_DENIED|APPEND_AFTER_TERMINAL_EVENT_DENIED"):
        asyncio.run(recorder.append_once(extra_prop, "broker", str(uuid4())))

    # 3. Witness close lost ACK coverage
    wit_db = tmp_path / "witness_f7.sqlite3"
    wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    (tmp_path / "f7_wit.key").write_bytes(wit_priv)
    rec_pub = Ed25519PrivateKey.from_private_bytes(rec_priv).public_key().public_bytes_raw()
    rec_key_id = "rec-f7"

    witness = SQLiteWitnessAuthority(
        wit_db,
        wit_priv,
        "wit-f7",
        initialize_if_missing=True,
        recorder_public_key=rec_pub,
        recorder_key_id=rec_key_id,
    )

    # Reserve start first to open epoch 1
    start_receipt = WitnessStart(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        schema_version="arena.v2",
        receipt_type="START",
        public_manifest_digest=manifest,
        reservation_id=str(uuid4()),
        event_count=1,
        prefix_root="0" * 64,
        witness_key_id="wit-f7",
    )
    start_sig = sign(witness_message(start_receipt), rec_priv)
    asyncio.run(witness.reserve_start_authenticated(start_receipt, start_sig))

    (tmp_path / "f7_wit_fixture.json").write_text(
        json.dumps({
            "signed_checkpoint": signed_cp.model_dump(),
            "recorder_pub_hex": rec_pub.hex(),
            "recorder_key_id": rec_key_id,
        })
    )

    # Child crashes after committing close receipt to SQLite close_receipts table
    lost_wit = subprocess.run(
        [sys.executable, "-c", CHILD_FAULT_7_WIT_CLOSE, str(tmp_path)],
        capture_output=True,
        timeout=15,
    )
    assert lost_wit.returncode == 0

    # Inspect persisted authority in SQLite directly BEFORE parent retries
    with closing(sqlite3.connect(str(wit_db))) as conn:
        persisted_close = conn.execute(
            "SELECT receipt_json, signature FROM close_receipts WHERE domain_id=? AND experiment_id=? AND epoch=?",
            (ctx.domain_id, ctx.experiment_id, ctx.epoch),
        ).fetchone()
        assert persisted_close is not None
        wit_close_payload = json.loads(persisted_close[0])
        assert wit_close_payload["event_count"] == 1
        persisted_wit_sig = persisted_close[1]
        wm = conn.execute(
            "SELECT highest_committed_epoch, current_active_epoch FROM epoch_watermarks WHERE domain_id=? AND experiment_id=?",
            (ctx.domain_id, ctx.experiment_id),
        ).fetchone()
        assert wm == (1, None)
        close_count_before = conn.execute("SELECT count(*) FROM close_receipts").fetchone()[0]
        assert close_count_before == 1

    # Retrying witness close returns original signed receipt without creating another record
    signed_close = asyncio.run(witness.close_checkpoint(signed_cp))
    assert signed_close.receipt.event_count == 1
    assert signed_close.signature == persisted_wit_sig

    with closing(sqlite3.connect(str(wit_db))) as conn:
        close_count_after = conn.execute("SELECT count(*) FROM close_receipts").fetchone()[0]
        assert close_count_after == 1

    # 4. Missing authority state refusal
    missing_wit_db = tmp_path / "nonexistent_witness.sqlite3"
    with pytest.raises(DependencyUnavailable, match="WITNESS_STATE_INITIALIZATION_REQUIRES_EXPLICIT_PROVISIONING"):
        SQLiteWitnessAuthority(missing_wit_db, wit_priv, "wit-key", initialize_if_missing=False)

    # 5. Changed authority key on existing database fails closed
    existing_wit_db = tmp_path / "existing_witness.sqlite3"
    SQLiteWitnessAuthority(existing_wit_db, wit_priv, "wit-key", initialize_if_missing=True)
    other_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    with pytest.raises(DependencyUnavailable, match="WITNESS_AUTHORITY_STATE_MISMATCH"):
        SQLiteWitnessAuthority(existing_wit_db, other_priv, "wit-key", initialize_if_missing=False)


# ---------------------------------------------------------------------------
# Fault Window 8: Known model completion followed by evidence failure
# ---------------------------------------------------------------------------

def test_fault_window_8_model_completion_with_evidence_failure_retains_executed_and_invalid(tmp_path, monkeypatch):
    """Known model completion with subsequent evidence failure preserves EXECUTED and INVALID."""
    async def scenario():
        env = await environment(tmp_path)
        item = payload()

        original_append_once = env.recorder.append_once

        async def fail_append(proposal, authenticated_actor, operation_id):
            if proposal.event_type == "FEEDBACK_AUTHORIZED":
                raise OSError("Simulated disk I/O failure during feedback authorization append")
            return await original_append_once(proposal, authenticated_actor, operation_id)

        monkeypatch.setattr(env.recorder, "append_once", fail_append)

        with pytest.raises(OSError, match="Simulated disk I/O failure"):
            await turn(env, item)

        assert len(env.runtime.model.calls) == 1

        with closing(env.store.connect()) as conn:
            row = conn.execute("SELECT result_json FROM turns").fetchone()
            assert row is not None
            recorded_result = json.loads(row[0])

        assert recorded_result["model_execution"] == "EXECUTED"
        assert recorded_result["integrity"] == "INVALID"
        assert recorded_result["pipeline_disposition"] == "INFRASTRUCTURE_FAILED"

        await env.controller.close(env.principals["operator"])
        result = verify_export(env, tmp_path, "INPUT")
        assert result.status == "AUTHENTIC_INVALID"
        assert result.diagnostics["integrity"] == "INVALID"

    asyncio.run(scenario())
