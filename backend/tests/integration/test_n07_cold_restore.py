"""MN07-03 cold restore, stale authority refusal and safe failure matrix.

Verifies:
1. Missing witness state refuses implicit bootstrap (fail-closed).
2. Key mismatch / rotated key on existing database fails closed.
3. Stale recorder restore with newer intact witness refuses stale epoch start (anti-regression).
4. Stale domain reservation in witness rejects conflicting epoch or experiment.
5. Manifest mismatch on restore fails closed on both recorder and witness.
6. ThreeLaneModel.reset strictly refuses active and quarantined lanes.
7. Consistent SQLite backup vs corrupted state handling.
Coordinated multi-authority rollback refusal is explicitly unsupported here;
there is no production anchor/startup consumer exercised by this component file.
"""

import asyncio
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.common import Context
from arena.contracts.crypto import checkpoint_digest, sign, witness_message
from arena.contracts.evidence import (
    ArtifactRef,
    Checkpoint,
    EventProposal,
    WitnessClose,
    WitnessStart,
)
from arena.integration.lanes import ThreeLaneModel
from arena.ports import DependencyUnavailable, TargetNotDispatched
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority


# ---------------------------------------------------------------------------
# 1. Missing witness state refuses implicit bootstrap
# ---------------------------------------------------------------------------

def test_missing_witness_database_refuses_implicit_bootstrap(tmp_path):
    """An expected-existing witness database must fail closed if absent."""
    missing_db = tmp_path / "nonexistent_witness.sqlite3"
    wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()

    with pytest.raises(
        DependencyUnavailable,
        match="WITNESS_STATE_INITIALIZATION_REQUIRES_EXPLICIT_PROVISIONING",
    ):
        SQLiteWitnessAuthority(
            missing_db,
            wit_priv,
            "wit-key-1",
            initialize_if_missing=False,
        )


# ---------------------------------------------------------------------------
# 2. Key or key ID mismatch on existing database fails closed
# ---------------------------------------------------------------------------

def test_witness_and_recorder_authority_key_mismatch_fails_closed(tmp_path):
    """Reopening existing databases with mismatched or rotated key material fails closed."""
    wit_db = tmp_path / "witness.sqlite3"
    rec_db = tmp_path / "recorder.sqlite3"

    key1 = Ed25519PrivateKey.generate().private_bytes_raw()
    key2 = Ed25519PrivateKey.generate().private_bytes_raw()

    # Provision witness with key1
    SQLiteWitnessAuthority(wit_db, key1, "wit-key-1", initialize_if_missing=True)

    # Reopening witness with key2 fails
    with pytest.raises(DependencyUnavailable, match="WITNESS_AUTHORITY_STATE_MISMATCH"):
        SQLiteWitnessAuthority(wit_db, key2, "wit-key-1", initialize_if_missing=False)

    # Reopening witness with mismatched key_id fails
    with pytest.raises(DependencyUnavailable, match="WITNESS_AUTHORITY_STATE_MISMATCH"):
        SQLiteWitnessAuthority(wit_db, key1, "wrong-key-id", initialize_if_missing=False)

    # Provision recorder with key1
    DurableRecorder(rec_db, key1, "rec-key-1")

    # Reopening recorder with key2 fails
    with pytest.raises(DependencyUnavailable, match="RECORDER_AUTHORITY_STATE_MISMATCH"):
        DurableRecorder(rec_db, key2, "rec-key-1")

    # Reopening recorder with mismatched key_id fails
    with pytest.raises(DependencyUnavailable, match="RECORDER_AUTHORITY_STATE_MISMATCH"):
        DurableRecorder(rec_db, key1, "wrong-rec-id")


# ---------------------------------------------------------------------------
# 3. Stale recorder restore with newer intact witness refuses stale epoch start
# ---------------------------------------------------------------------------

def test_stale_recorder_restore_with_newer_intact_witness_refuses_stale_start(tmp_path):
    """Restoring a stale recorder backup alongside a newer intact witness refuses resume."""
    rec_db = tmp_path / "recorder.sqlite3"
    rec_backup = tmp_path / "recorder_backup_epoch1.sqlite3"
    wit_db = tmp_path / "witness.sqlite3"

    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    rec_pub = Ed25519PrivateKey.from_private_bytes(rec_priv).public_key().public_bytes_raw()

    witness = SQLiteWitnessAuthority(
        wit_db,
        wit_priv,
        "wit-key",
        initialize_if_missing=True,
        recorder_public_key=rec_pub,
        recorder_key_id="rec-key",
    )
    recorder = DurableRecorder(rec_db, rec_priv, "rec-key")

    domain_id = str(uuid4())
    exp_id = str(uuid4())
    manifest = "a" * 64

    # --- Epoch 1: Reserve, append, close ---
    ctx1 = Context(domain_id=domain_id, experiment_id=exp_id, epoch=1)
    recorder.register_run(ctx1, manifest, actor_id="broker")

    start1 = WitnessStart(
        domain_id=domain_id,
        experiment_id=exp_id,
        epoch=1,
        schema_version="arena.v2",
        receipt_type="START",
        public_manifest_digest=manifest,
        reservation_id=str(uuid4()),
        event_count=1,
        prefix_root="0" * 64,
        witness_key_id="wit-key",
    )
    sig1 = sign(witness_message(start1), rec_priv)
    asyncio.run(witness.reserve_start_authenticated(start1, sig1))

    # Append terminal event and close recorder for Epoch 1
    closed_prop1 = EventProposal(
        domain_id=domain_id,
        experiment_id=exp_id,
        epoch=1,
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="CLOSED",
        outcome_code="OK",
        artifact_ciphertext_refs=(),
        duration_us=0,
    )
    asyncio.run(recorder.append_once(closed_prop1, "broker", str(uuid4())))
    signed_cp1 = asyncio.run(recorder.close(ctx1))
    asyncio.run(witness.close_checkpoint(signed_cp1))

    # Take backup of recorder at Epoch 1
    with closing(sqlite3.connect(str(rec_db))) as src, closing(sqlite3.connect(str(rec_backup))) as dst:
        src.backup(dst)

    # --- Epoch 2: Advance witness and recorder to Epoch 2 ---
    ctx2 = Context(domain_id=domain_id, experiment_id=exp_id, epoch=2)
    recorder.register_run(ctx2, manifest, actor_id="broker")

    start2 = WitnessStart(
        domain_id=domain_id,
        experiment_id=exp_id,
        epoch=2,
        schema_version="arena.v2",
        receipt_type="START",
        public_manifest_digest=manifest,
        reservation_id=str(uuid4()),
        event_count=1,
        prefix_root="0" * 64,
        witness_key_id="wit-key",
    )
    sig2 = sign(witness_message(start2), rec_priv)
    asyncio.run(witness.reserve_start_authenticated(start2, sig2))

    closed_prop2 = EventProposal(
        domain_id=domain_id,
        experiment_id=exp_id,
        epoch=2,
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="CLOSED",
        outcome_code="OK",
        artifact_ciphertext_refs=(),
        duration_us=0,
    )
    asyncio.run(recorder.append_once(closed_prop2, "broker", str(uuid4())))
    signed_cp2 = asyncio.run(recorder.close(ctx2))
    asyncio.run(witness.close_checkpoint(signed_cp2))

    # Current witness highest committed epoch is 2
    highest, active = witness.watermark(ctx2)
    assert highest == 2
    assert active is None

    # --- SIMULATE RESTORE OF STALE RECORDER ---
    # Reopen stale recorder from Epoch 1 backup
    stale_recorder = DurableRecorder(rec_backup, rec_priv, "rec-key")
    stale_events = stale_recorder.get_events(ctx1)
    assert len(stale_events) == 1
    assert len(stale_recorder.get_events(ctx2)) == 0  # Does not know about Epoch 2!

    # Stale recorder attempts to request Epoch 1 again from the intact witness
    with pytest.raises(DependencyUnavailable, match="EPOCH_REGRESSION_REJECTED|DOMAIN_EPOCH_REGRESSION_OR_CONFLICT"):
        asyncio.run(witness.reserve_start_authenticated(start1, sig1))


# ---------------------------------------------------------------------------
# 4. Stale domain reservation in witness rejects conflicting epoch / experiment
# ---------------------------------------------------------------------------

def test_stale_domain_reservation_refuses_rollback_or_conflict(tmp_path):
    """Witness domain reservations enforce anti-rollback across experiments on the same domain."""
    wit_db = tmp_path / "witness_domain.sqlite3"
    wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    witness = SQLiteWitnessAuthority(wit_db, wit_priv, "wit-key", initialize_if_missing=True)

    domain_id = str(uuid4())
    exp1 = str(uuid4())
    exp2 = str(uuid4())
    manifest = "b" * 64

    # Reserve Epoch 2 for exp1
    start_e2 = WitnessStart(
        domain_id=domain_id,
        experiment_id=exp1,
        epoch=2,
        schema_version="arena.v2",
        receipt_type="START",
        public_manifest_digest=manifest,
        reservation_id=str(uuid4()),
        event_count=1,
        prefix_root="0" * 64,
        witness_key_id="wit-key",
    )
    asyncio.run(witness.reserve_start(start_e2))

    # Attempt to reserve Epoch 1 for exp2 on same domain: must be rejected
    start_conflict = WitnessStart(
        domain_id=domain_id,
        experiment_id=exp2,
        epoch=1,
        schema_version="arena.v2",
        receipt_type="START",
        public_manifest_digest=manifest,
        reservation_id=str(uuid4()),
        event_count=1,
        prefix_root="0" * 64,
        witness_key_id="wit-key",
    )
    with pytest.raises(DependencyUnavailable, match="DOMAIN_EPOCH_REGRESSION_OR_CONFLICT"):
        asyncio.run(witness.reserve_start(start_conflict))


# ---------------------------------------------------------------------------
# 5. Manifest mismatch on restore fails closed on both recorder and witness
# ---------------------------------------------------------------------------

def test_manifest_mismatch_fails_closed_on_recorder_and_witness(tmp_path):
    """Attempting to resume or re-register an existing run with a conflicting manifest fails closed."""
    rec_db = tmp_path / "recorder_manifest.sqlite3"
    wit_db = tmp_path / "witness_manifest.sqlite3"
    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()

    recorder = DurableRecorder(rec_db, rec_priv, "rec-key")
    witness = SQLiteWitnessAuthority(wit_db, wit_priv, "wit-key", initialize_if_missing=True)

    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    manifest_a = "a" * 64
    manifest_b = "b" * 64

    # Register run in recorder with manifest_a
    recorder.register_run(ctx, manifest_a, actor_id="broker")

    # Re-registering with manifest_b raises RUN_MANIFEST_MISMATCH
    with pytest.raises(DependencyUnavailable, match="RUN_MANIFEST_MISMATCH"):
        recorder.register_run(ctx, manifest_b, actor_id="broker")

    # Reserve start in witness with manifest_a
    start_a = WitnessStart(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        schema_version="arena.v2",
        receipt_type="START",
        public_manifest_digest=manifest_a,
        reservation_id=str(uuid4()),
        event_count=1,
        prefix_root="0" * 64,
        witness_key_id="wit-key",
    )
    asyncio.run(witness.reserve_start(start_a))

    # Closing witness with manifest_b raises CLOSE_MANIFEST_MISMATCH
    close_b = WitnessClose(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=1,
        schema_version="arena.v2",
        receipt_type="CLOSE",
        public_manifest_digest=manifest_b,
        checkpoint_digest="c" * 64,
        event_count=2,
        final_root="d" * 64,
        witness_key_id="wit-key",
    )
    with pytest.raises(DependencyUnavailable, match="CLOSE_MANIFEST_MISMATCH"):
        asyncio.run(witness.close(close_b))


# ---------------------------------------------------------------------------
# 6. ThreeLaneModel.reset strictly refuses active and quarantined lanes
# ---------------------------------------------------------------------------

def test_three_lane_model_reset_refuses_active_and_quarantined_lanes():
    """ThreeLaneModel.reset raises LANE_NOT_SAFE_TO_RESET on active or quarantined lanes."""
    class DummyCell:
        def __init__(self, name):
            self.container = name
            self.model = SimpleNamespace(
                infer=self._infer,
                reset=self._reset,
            )

        async def _infer(self, req):
            if req.text == "fail":
                raise RuntimeError("simulated_model_crash")
            return SimpleNamespace(
                domain_id=req.domain_id,
                experiment_id=req.experiment_id,
                epoch=req.epoch,
                attempt_id=req.attempt_id,
                session_id=req.session_id,
                turn_index=req.turn_index,
                text="ok",
            )

        async def _reset(self, session_id):
            pass

    cells = [DummyCell(f"cell_{i}") for i in range(3)]
    recreated = []

    def recreate(lane):
        recreated.append(lane)
        return DummyCell(f"cell_{lane}_recreated")

    pool = ThreeLaneModel(cells, recreate)
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)

    sess0 = str(uuid4())
    pool.bind_session(sess0, 0, ctx)

    # 1. Quarantine lane 0 via exception during infer
    req_fail = SimpleNamespace(
        domain_id=ctx.domain_id,
        experiment_id=ctx.experiment_id,
        epoch=ctx.epoch,
        attempt_id=str(uuid4()),
        session_id=sess0,
        turn_index=0,
        text="fail",
    )
    with pytest.raises(RuntimeError, match="simulated_model_crash"):
        asyncio.run(pool.infer(req_fail))

    assert 0 in pool.quarantined

    # 2. Reset on quarantined lane is strictly refused
    with pytest.raises(DependencyUnavailable, match="LANE_NOT_SAFE_TO_RESET"):
        asyncio.run(pool.reset(sess0))

    # 3. Active lane refusal
    sess1 = str(uuid4())
    pool.bind_session(sess1, 1, ctx)
    pool.active.add(1)  # Simulate in-flight inference

    with pytest.raises(DependencyUnavailable, match="LANE_NOT_SAFE_TO_RESET"):
        asyncio.run(pool.reset(sess1))
    pool.active.remove(1)


# ---------------------------------------------------------------------------
# 7. Consistent SQLite backup vs corrupted state handling
# ---------------------------------------------------------------------------

def test_consistent_backup_vs_corrupted_state(tmp_path):
    """Backup preserves actual prefix/registration/identity; corrupt recorder open rejects."""
    rec_db = tmp_path / "rec_original.sqlite3"
    rec_backup = tmp_path / "rec_consistent.sqlite3"
    rec_corrupt = tmp_path / "rec_corrupt.sqlite3"
    key = Ed25519PrivateKey.generate().private_bytes_raw()

    recorder = DurableRecorder(rec_db, key, "rec-key")
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    recorder.register_run(ctx, "a" * 64, actor_id="broker")
    proposal = EventProposal(**ctx.model_dump(), session_id=None, turn_id=None, turn_index=None,
        event_type='START_RESERVED', outcome_code='OK', artifact_ciphertext_refs=(), duration_us=0)
    prefix = asyncio.run(recorder.append_once(proposal, 'broker', str(uuid4())))
    tables = ('recorder_identity', 'runs', 'run_actors', 'events')
    with closing(sqlite3.connect(str(rec_db))) as conn:
        expected = {table:conn.execute(f'SELECT * FROM {table} ORDER BY 1,2').fetchall() for table in tables}

    # Consistent backup via SQLite online backup API
    with closing(sqlite3.connect(str(rec_db))) as src, closing(sqlite3.connect(str(rec_backup))) as dst:
        src.backup(dst)

    # Advance the source after the backup; restored authority remains its exact older prefix.
    later = proposal.model_copy(update={'event_type':'INTEGRITY_VIOLATION', 'outcome_code':'INVALID'})
    asyncio.run(recorder.append_once(later, 'broker', str(uuid4())))
    reopened = DurableRecorder(rec_backup, key, "rec-key")
    assert reopened.get_events(ctx) == [prefix]
    assert len(recorder.get_events(ctx)) == 2
    with closing(sqlite3.connect(str(rec_backup))) as conn:
        actual = {table:conn.execute(f'SELECT * FROM {table} ORDER BY 1,2').fetchall() for table in tables}
        assert conn.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
    assert actual == expected
    assert actual['runs'][0][3:5] == ('a'*64, 'OPEN')
    assert actual['run_actors'][0][-1] == 'broker'
    with pytest.raises(DependencyUnavailable, match='RECORDER_AUTHORITY_STATE_MISMATCH'):
        DurableRecorder(rec_backup, Ed25519PrivateKey.generate().private_bytes_raw(), 'rec-key')

    # Corrupt database: truncated header / garbage bytes
    rec_corrupt.write_bytes(b"SQLite format 3\x00GARBAGE_HEADER_CORRUPTED_BYTES" + b"\x00" * 100)
    with pytest.raises(sqlite3.DatabaseError):
        DurableRecorder(rec_corrupt, key, 'rec-key')


# ---------------------------------------------------------------------------
# 8. Unsupported boundary: no production coordinated-rollback resume guard here
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason='No production independent-anchor/startup consumer: coordinated rollback remains unsupported')
def test_coordinated_rollback_runtime_refusal_is_unsupported():
    """A test-local integer comparison cannot establish production restore refusal.

    Replace this explicit gap only with a test of an actual bounded administrative
    refusal entry point and independently trusted authority. It must restore real
    stores and prove no initialization, dispatch or trusted resume on failure.
    """
