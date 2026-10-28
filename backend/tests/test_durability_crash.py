"""Standalone SQLite crash recovery and watermark regression test suite (T-008, P-015)."""

import asyncio
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from uuid import uuid4

from arena.contracts.common import Context
from arena.contracts.crypto import checkpoint_digest
from arena.contracts.evidence import (
    ArtifactRef,
    Checkpoint,
    EventProposal,
    WitnessClose,
    WitnessStart,
)
from arena.ports import DependencyUnavailable
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TestDurabilityAndCrashRecovery(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
        self.wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
        self.rec_key_id = "rec-key-1"
        self.wit_key_id = "wit-key-1"

        self.domain_id = str(uuid4())
        self.experiment_id = str(uuid4())
        self.manifest_digest = hashlib.sha256(b"manifest-test").hexdigest()

    async def test_t008_uncommitted_transaction_rollback(self):
        """Simulate crash during uncommitted write; verify clean rollback and sequence preservation."""
        tmp_dir = tempfile.mkdtemp()
        try:
            db_path = Path(tmp_dir) / "recorder_crash.db"
            recorder = DurableRecorder(db_path, self.rec_priv, self.rec_key_id)
            ctx = Context(domain_id=self.domain_id, experiment_id=self.experiment_id, epoch=1)
            recorder.register_run(ctx, self.manifest_digest)

            # 1. Commit first valid event
            prop1 = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                session_id=None,
                turn_id=None,
                turn_index=None,
                event_type="START_RESERVED",
                outcome_code="OK",
                artifact_ciphertext_refs=[],
                duration_us=1000,
            )
            ev1 = await recorder.append(prop1, authenticated_actor="broker")
            self.assertEqual(ev1.sequence, 1)

            # 2. Simulate crash during uncommitted SQLite transaction
            conn = sqlite3.connect(str(db_path))
            conn.execute("BEGIN TRANSACTION;")
            # Insert a bogus raw row that never gets committed
            conn.execute(
                """
                INSERT INTO events (domain_id, experiment_id, epoch, sequence, operation_id, canonical_json, digest, previous_digest)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self.domain_id, self.experiment_id, 1, 999, "bogus_op", "{}", "bad", "bad"),
            )
            # Sudden disconnect / crash (no commit)
            conn.close()

            # 3. Re-open database with new recorder instance and confirm rollback
            restarted = DurableRecorder(db_path, self.rec_priv, self.rec_key_id)
            events = restarted.get_events(ctx)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].sequence, 1)

            # 4. Subsequent legitimate append proceeds normally at sequence 2
            prop2 = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                session_id=str(uuid4()),
                turn_id=str(uuid4()),
                turn_index=0,
                event_type="DISPATCH_INTENT",
                outcome_code="OK",
                artifact_ciphertext_refs=[],
                duration_us=1500,
            )
            ev2 = await restarted.append(prop2, authenticated_actor="broker")
            self.assertEqual(ev2.sequence, 2)
            from arena.contracts.crypto import event_digest
            expected_prev = event_digest(ev1)
            self.assertEqual(ev2.previous_digest, expected_prev)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def test_p015_witness_watermark_anti_regression(self):
        """Verify SQLite witness strictly enforces ascending epoch watermark and rejects rollback."""
        tmp_dir = tempfile.mkdtemp()
        try:
            db_path = Path(tmp_dir) / "witness_watermark.db"
            witness = SQLiteWitnessAuthority(db_path, self.wit_priv, self.wit_key_id, initialize_if_missing=True)

            # Epoch 1: Reserve and Close
            start_e1 = WitnessStart(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                schema_version="arena.v2",
                receipt_type="START",
                public_manifest_digest=self.manifest_digest,
                reservation_id=str(uuid4()),
                event_count=1,
                prefix_root="0" * 64,
                witness_key_id=self.wit_key_id,
            )
            await witness.reserve_start(start_e1)

            close_e1 = WitnessClose(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                schema_version="arena.v2",
                receipt_type="CLOSE",
                public_manifest_digest=self.manifest_digest,
                checkpoint_digest="1" * 64,
                event_count=2,
                final_root="a" * 64,
                witness_key_id=self.wit_key_id,
            )
            await witness.close(close_e1)

            # Verify in db directly
            conn = sqlite3.connect(str(db_path))
            row = conn.execute("SELECT highest_committed_epoch FROM epoch_watermarks WHERE domain_id=? AND experiment_id=?;", (self.domain_id, self.experiment_id)).fetchone()
            conn.close()
            self.assertEqual(row[0], 1)

            # Epoch 2: Reserve and Close
            start_e2 = WitnessStart(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=2,
                schema_version="arena.v2",
                receipt_type="START",
                public_manifest_digest=self.manifest_digest,
                reservation_id=str(uuid4()),
                event_count=1,
                prefix_root="0" * 64,
                witness_key_id=self.wit_key_id,
            )
            await witness.reserve_start(start_e2)

            close_e2 = WitnessClose(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=2,
                schema_version="arena.v2",
                receipt_type="CLOSE",
                public_manifest_digest=self.manifest_digest,
                checkpoint_digest="2" * 64,
                event_count=3,
                final_root="b" * 64,
                witness_key_id=self.wit_key_id,
            )
            await witness.close(close_e2)

            # Regression attempt: Try to re-reserve Epoch 1 -> Must raise DependencyUnavailable
            replayed_e1 = WitnessStart(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                schema_version="arena.v2",
                receipt_type="START",
                public_manifest_digest=self.manifest_digest,
                reservation_id=str(uuid4()),
                event_count=1,
                prefix_root="0" * 64,
                witness_key_id=self.wit_key_id,
            )
            with self.assertRaises(DependencyUnavailable) as ctx:
                await witness.reserve_start(replayed_e1)
            self.assertTrue("EPOCH_REGRESSION" in str(ctx.exception))
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def test_lost_ack_retry_is_not_deduplicated_without_an_operation_identity(self):
        """A retry is a separate append until the shared port defines stable identity."""
        tmp_dir = tempfile.mkdtemp()
        try:
            db_path = Path(tmp_dir) / "recorder_idempotency.db"
            recorder = DurableRecorder(db_path, self.rec_priv, self.rec_key_id)
            ctx = Context(domain_id=self.domain_id, experiment_id=self.experiment_id, epoch=1)
            recorder.register_run(ctx, self.manifest_digest)

            prop = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                session_id=str(uuid4()),
                turn_id=str(uuid4()),
                turn_index=0,
                event_type="DISPATCH_INTENT",
                outcome_code="OK",
                artifact_ciphertext_refs=[],
                duration_us=1200,
            )

            # 1. Append proposal
            ev1 = await recorder.append(prop, authenticated_actor="broker")
            self.assertEqual(ev1.sequence, 1)

            # 2. Simulate process crash / new recorder instance
            restarted = DurableRecorder(db_path, self.rec_priv, self.rec_key_id)

            # 3. Client re-sends exact same proposal (lost-ACK retry)
            ev2 = await restarted.append(prop, authenticated_actor="broker")

            # 4. The port has no operation ID, so it cannot safely infer a retry.
            self.assertEqual(ev2.sequence, 2)
            events = restarted.get_events(ctx)
            self.assertEqual(len(events), 2)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def test_witness_active_epoch_concurrency_lock(self):
        """Verify witness rejects new epoch reservation while an epoch is still active and unclosed."""
        tmp_dir = tempfile.mkdtemp()
        try:
            db_path = Path(tmp_dir) / "witness_lock.db"
            witness = SQLiteWitnessAuthority(db_path, self.wit_priv, self.wit_key_id, initialize_if_missing=True)

            start_e1 = WitnessStart(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                schema_version="arena.v2",
                receipt_type="START",
                public_manifest_digest=self.manifest_digest,
                reservation_id=str(uuid4()),
                event_count=1,
                prefix_root="0" * 64,
                witness_key_id=self.wit_key_id,
            )
            await witness.reserve_start(start_e1)

            # While epoch 1 is active, attempt to start epoch 2 without closing epoch 1
            start_e2 = WitnessStart(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=2,
                schema_version="arena.v2",
                receipt_type="START",
                public_manifest_digest=self.manifest_digest,
                reservation_id=str(uuid4()),
                event_count=1,
                prefix_root="0" * 64,
                witness_key_id=self.wit_key_id,
            )
            with self.assertRaises(DependencyUnavailable) as ctx:
                await witness.reserve_start(start_e2)
            self.assertTrue("ACTIVE_EPOCH_IN_FLIGHT" in str(ctx.exception))
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
