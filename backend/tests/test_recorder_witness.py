"""Durable recorder and witness authority integration and negative tests (BAR-3)."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from arena.contracts.common import Context
from arena.contracts.crypto import (
    validate_chain,
    verify,
    verify_checkpoint,
    verify_witness_close,
    witness_message,
)
from arena.contracts.evidence import (
    ArtifactRef,
    Checkpoint,
    EventProposal,
    WitnessClose,
    WitnessStart,
)
from arena.ports import DependencyUnavailable
from arena.recorder import DurableRecorder, verify_event_chain
from arena.witness import SQLiteWitnessAuthority
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TestDurableRecorderAndWitness(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Generate distinct Ed25519 keys for recorder and witness
        self.rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
        self.rec_pub = (
            Ed25519PrivateKey.from_private_bytes(self.rec_priv)
            .public_key()
            .public_bytes_raw()
        )
        self.rec_key_id = "recorder-key-1"

        self.wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
        self.wit_pub = (
            Ed25519PrivateKey.from_private_bytes(self.wit_priv)
            .public_key()
            .public_bytes_raw()
        )
        self.wit_key_id = "witness-key-1"

        self.domain_id = str(uuid4())
        self.experiment_id = str(uuid4())
        self.epoch = 1
        self.context = Context(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
        )
        self.manifest_digest = "b" * 64

    async def test_recorder_lifecycle_hash_chain_and_durability(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "recorder.db"
            recorder = DurableRecorder(db_path, self.rec_priv, self.rec_key_id)

            # Register run
            recorder.register_run(self.context, self.manifest_digest)

            # Register artifact
            art_id = str(uuid4())
            artifact_path = Path(tmpdir) / "ciphertext.bin"
            artifact_path.write_bytes(b"synthetic encrypted artifact fixture")
            art_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            recorder.register_artifact(art_id, art_hash, str(artifact_path))

            session_id = str(uuid4())
            turn_id = str(uuid4())

            # Append attempt event 1
            prop1 = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                session_id=session_id,
                turn_id=turn_id,
                turn_index=0,
                event_type="DISPATCH_INTENT",
                outcome_code="OK",
                artifact_ciphertext_refs=(
                    (ArtifactRef(artifact_id=art_id, ciphertext_sha256=art_hash)),
                ),
                duration_us=1000,
            )
            ev1 = await recorder.append(prop1, authenticated_actor="broker_core")
            self.assertEqual(ev1.sequence, 1)
            self.assertEqual(ev1.previous_digest, "0" * 64)
            self.assertEqual(ev1.actor_id, "broker_core")

            # Append attempt event 2
            prop2 = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                session_id=session_id,
                turn_id=turn_id,
                turn_index=0,
                event_type="MODEL_RESULT",
                outcome_code="OK",
                artifact_ciphertext_refs=(),
                duration_us=15000,
            )
            ev2 = await recorder.append(prop2, authenticated_actor="broker_core")
            self.assertEqual(ev2.sequence, 2)
            self.assertNotEqual(ev2.previous_digest, "0" * 64)

            # Close requires the broker to persist the truthful terminal event first.
            terminal = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                session_id=None,
                turn_id=None,
                turn_index=None,
                event_type="CLOSED",
                outcome_code="OK",
                artifact_ciphertext_refs=(),
                duration_us=0,
            )
            await recorder.append(terminal, authenticated_actor="broker_core")
            signed_cp = await recorder.close(self.context)
            self.assertEqual(signed_cp.checkpoint.event_count, 3)  # ev1, ev2, CLOSED
            self.assertTrue(
                verify_checkpoint(
                    signed_cp,
                    self.rec_pub,
                    self.context,
                    self.manifest_digest,
                    self.rec_key_id,
                )
            )

            # Retrieve all events and validate chain structurally and cryptographically
            events = recorder.get_events(self.context)
            self.assertEqual(len(events), 3)
            self.assertEqual(events[-1].event_type, "CLOSED")
            valid, final_root = verify_event_chain(events)
            self.assertTrue(valid)
            self.assertEqual(signed_cp.checkpoint.final_root, final_root)

            # Canonical arena.v2 validate_chain check
            validate_chain(tuple(events), signed_cp.checkpoint)

            # Simulate restart: open same db file with new recorder instance
            restarted_recorder = DurableRecorder(
                db_path, self.rec_priv, self.rec_key_id
            )
            restarted_events = restarted_recorder.get_events(self.context)
            self.assertEqual(len(restarted_events), 3)
            valid2, _ = verify_event_chain(restarted_events)
            self.assertTrue(valid2)

            # Appending after close must fail
            prop3 = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                session_id=session_id,
                turn_id=turn_id,
                turn_index=0,
                event_type="FEEDBACK_AUTHORIZED",
                outcome_code="OK",
                artifact_ciphertext_refs=(),
                duration_us=500,
            )
            with self.assertRaises(DependencyUnavailable) as ctx:
                await restarted_recorder.append(
                    prop3, authenticated_actor="broker_core"
                )
            self.assertEqual(str(ctx.exception), "APPEND_AFTER_CLOSE_DENIED")

    async def test_recorder_does_not_guess_retry_identity_and_checks_missing_artifact(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "recorder.db"
            recorder = DurableRecorder(db_path, self.rec_priv, self.rec_key_id)
            recorder.register_run(self.context, self.manifest_digest)

            # 1. Missing artifact failure
            missing_art_id = str(uuid4())
            prop_missing = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                session_id=str(uuid4()),
                turn_id=str(uuid4()),
                turn_index=0,
                event_type="DISPATCH_INTENT",
                outcome_code="OK",
                artifact_ciphertext_refs=(
                    (
                        ArtifactRef(
                            artifact_id=missing_art_id, ciphertext_sha256="d" * 64
                        )
                    ),
                ),
                duration_us=1000,
            )
            with self.assertRaises(DependencyUnavailable) as ctx:
                await recorder.append(prop_missing, authenticated_actor="broker")
            self.assertTrue("MISSING_ARTIFACT_CIPHERTEXT" in str(ctx.exception))

            # 2. The current port has no stable operation ID, so the recorder must
            # not collapse distinct appends using a guessed turn/type key.
            session_id = str(uuid4())
            turn_id = str(uuid4())
            prop_ok = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                session_id=session_id,
                turn_id=turn_id,
                turn_index=0,
                event_type="DISPATCH_INTENT",
                outcome_code="OK",
                artifact_ciphertext_refs=(),
                duration_us=1000,
            )
            ev_first = await recorder.append(prop_ok, authenticated_actor="broker")
            # Identical proposal is a distinct append; ambiguous caller retries are
            # an OPEN shared decision and must not be silently treated as idempotent.
            ev_retry = await recorder.append(prop_ok, authenticated_actor="broker")
            self.assertNotEqual(ev_first.sequence, ev_retry.sequence)
            self.assertEqual(ev_retry.sequence, ev_first.sequence + 1)

            # Same session/index/type with another turn ID is also a separate append.
            prop_conflict = EventProposal(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                session_id=session_id,
                turn_id=str(uuid4()),  # different turn_id
                turn_index=0,
                event_type="DISPATCH_INTENT",
                outcome_code="OK",
                artifact_ciphertext_refs=(),
                duration_us=1000,
            )
            ev_other_turn = await recorder.append(
                prop_conflict, authenticated_actor="broker"
            )
            self.assertEqual(ev_other_turn.sequence, ev_retry.sequence + 1)

    async def test_close_fails_without_terminal_event_and_turn_signing_fails_closed(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = DurableRecorder(
                Path(tmpdir) / "recorder.db", self.rec_priv, self.rec_key_id
            )
            recorder.register_run(self.context, self.manifest_digest)
            with self.assertRaises(DependencyUnavailable) as close_error:
                await recorder.close(self.context)
            self.assertEqual(
                str(close_error.exception), "CLOSE_PENDING_MISSING_TERMINAL_EVENT"
            )

            from arena.contracts.evidence import TurnReceipt

            receipt = TurnReceipt(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                session_id=str(uuid4()),
                turn_id=str(uuid4()),
                turn_index=0,
                schema_version="arena.v2",
                input_commitment="a" * 64,
                event_count=1,
                prefix_root="0" * 64,
                public_response_commitment="b" * 64,
                signer_key_id=self.rec_key_id,
            )
            with self.assertRaises(DependencyUnavailable) as turn_error:
                await recorder.authorize_turn(receipt)
            self.assertEqual(
                str(turn_error.exception), "TURN_COMMITMENT_COVERAGE_UNRESOLVED"
            )

    async def test_witness_authority_anti_regression_and_consensus(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "witness.db"
            with self.assertRaises(DependencyUnavailable) as init_error:
                SQLiteWitnessAuthority(db_path, self.wit_priv, self.wit_key_id)
            self.assertEqual(
                str(init_error.exception),
                "WITNESS_STATE_INITIALIZATION_REQUIRES_EXPLICIT_PROVISIONING",
            )
            witness = SQLiteWitnessAuthority(
                db_path, self.wit_priv, self.wit_key_id, initialize_if_missing=True
            )

            res_id_1 = str(uuid4())
            start_req = WitnessStart(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                schema_version="arena.v2",
                receipt_type="START",
                public_manifest_digest=self.manifest_digest,
                reservation_id=res_id_1,
                event_count=1,
                prefix_root="0" * 64,
                witness_key_id=self.wit_key_id,
            )

            # Reserve start epoch 1
            bad_key_start = start_req.model_copy(update={"witness_key_id": "wrong-key"})
            with self.assertRaises(DependencyUnavailable) as key_error:
                await witness.reserve_start(bad_key_start)
            self.assertEqual(str(key_error.exception), "WITNESS_KEY_ID_MISMATCH")
            signed_start = await witness.reserve_start(start_req)
            self.assertTrue(
                verify(
                    witness_message(signed_start.receipt),
                    signed_start.signature,
                    self.wit_pub,
                )
            )

            # Idempotent retry of identical reservation
            signed_start_retry = await witness.reserve_start(start_req)
            self.assertEqual(signed_start.signature, signed_start_retry.signature)

            # Conflicting start reservation (different reservation_id on same active epoch)
            conflicting_start = WitnessStart(
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
                await witness.reserve_start(conflicting_start)
            self.assertEqual(str(ctx.exception), "CONFLICTING_START_RESERVATION")

            # Starting another epoch while epoch 1 is active
            epoch2_premature = WitnessStart(
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
            with self.assertRaises(DependencyUnavailable) as ctx_premature:
                await witness.reserve_start(epoch2_premature)
            self.assertTrue("ACTIVE_EPOCH_IN_FLIGHT" in str(ctx_premature.exception))

            # Construct matching checkpoint for close verification
            cp = Checkpoint(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                schema_version="arena.v2",
                public_manifest_digest=self.manifest_digest,
                event_count=5,
                final_root="f" * 64,
                terminal_marker="CLOSED",
                required_artifacts=(),
                signer_key_id=self.rec_key_id,
            )
            from arena.contracts.crypto import checkpoint_digest

            cp_digest = checkpoint_digest(cp)

            # Close epoch 1
            close_req = WitnessClose(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                schema_version="arena.v2",
                receipt_type="CLOSE",
                public_manifest_digest=self.manifest_digest,
                checkpoint_digest=cp_digest,
                event_count=5,
                final_root="f" * 64,
                witness_key_id=self.wit_key_id,
            )
            signed_close = await witness.close(close_req)
            self.assertTrue(
                verify_witness_close(
                    signed_close, self.wit_pub, cp, self.context, self.wit_key_id
                )
            )

            # Idempotent retry of close
            signed_close_retry = await witness.close(close_req)
            self.assertEqual(signed_close.signature, signed_close_retry.signature)

            # Conflicting close retry
            conflicting_close = WitnessClose(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                schema_version="arena.v2",
                receipt_type="CLOSE",
                public_manifest_digest=self.manifest_digest,
                checkpoint_digest="9" * 64,  # different checkpoint
                event_count=5,
                final_root="f" * 64,
                witness_key_id=self.wit_key_id,
            )
            with self.assertRaises(DependencyUnavailable) as ctx_close:
                await witness.close(conflicting_close)
            self.assertEqual(str(ctx_close.exception), "CONFLICTING_CLOSE_RECEIPT")

            # Epoch regression rejection: attempt to start epoch 1 again
            with self.assertRaises(DependencyUnavailable) as ctx_regr:
                await witness.reserve_start(start_req)
            self.assertTrue("EPOCH_REGRESSION_REJECTED" in str(ctx_regr.exception))

            # Restart witness instance and verify watermark persistence: epoch 1 still rejected
            restarted_witness = SQLiteWitnessAuthority(
                db_path, self.wit_priv, self.wit_key_id, initialize_if_missing=True
            )
            with self.assertRaises(DependencyUnavailable) as ctx_regr2:
                await restarted_witness.reserve_start(start_req)
            self.assertTrue("EPOCH_REGRESSION_REJECTED" in str(ctx_regr2.exception))


if __name__ == "__main__":
    unittest.main()
