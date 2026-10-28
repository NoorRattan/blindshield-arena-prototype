import asyncio
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from arena.contracts.crypto import event_digest
from arena.ports import DependencyUnavailable
from arena.recovery.anchor import RecoveryAnchor, RecoveryAnchorError, operation_id, verify_anchor_records
from arena.recovery.feedback import (
    FeedbackRecoveryRequest,
    FeedbackReconciliationUnsigned,
    FeedbackReplay,
    FeedbackReplayUnsigned,
    sign_reconciliation,
    sign_replay,
    verify_reconciliation,
    verify_replay,
)
from test_n06_execution import environment, submit


def _unsigned_values():
    return {
        "schema_version": "arena.feedback-reconciliation.v1",
        "domain_id": "11111111-1111-4111-8111-111111111111",
        "experiment_id": "22222222-2222-4222-8222-222222222222",
        "epoch": 1,
        "session_id": "33333333-3333-4333-8333-333333333333",
        "turn_id": "44444444-4444-4444-8444-444444444444",
        "turn_index": 0,
        "feedback_event_sequence": 7,
        "feedback_event_digest": "a" * 64,
        "prefix_root": "a" * 64,
        "anchor_record_digest": "b" * 64,
        "input_artifact": {
            "artifact_id": "55555555-5555-4555-8555-555555555555",
            "ciphertext_sha256": "c" * 64,
        },
        "response_artifact": {
            "artifact_id": "66666666-6666-4666-8666-666666666666",
            "ciphertext_sha256": "d" * 64,
        },
        "input_commitment": "e" * 64,
        "response_commitment": "f" * 64,
        "reservation_id": "44444444-4444-4444-8444-444444444444",
        "model_result_digest": "1" * 64,
        "score_result_digest": "2" * 64,
        "queue_job_id": "44444444-4444-4444-8444-444444444444",
        "recovery_operation_id": "77777777-7777-4777-8777-777777777777",
        "recovery_authority_id": "test-recovery-authority",
        "recovery_key_id": "test-recovery-key",
    }


def test_reconciliation_and_replay_are_separately_domain_signed():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes_raw()
    public = key.public_key().public_bytes_raw()
    proof_unsigned = FeedbackReconciliationUnsigned.model_validate(_unsigned_values())
    proof = sign_reconciliation(proof_unsigned, private)
    assert verify_reconciliation(proof, public, "test-recovery-authority", "test-recovery-key")
    assert not verify_reconciliation(proof, public, "other-authority", "test-recovery-key")

    replay_unsigned = FeedbackReplayUnsigned(
        schema_version="arena.feedback-replay.v1",
        domain_id=proof.domain_id,
        experiment_id=proof.experiment_id,
        epoch=proof.epoch,
        session_id=proof.session_id,
        turn_id=proof.turn_id,
        turn_index=proof.turn_index,
        public_reply_base64="SGVsbG8=",
        public_status="COMPLETED",
        response_commitment=proof.response_commitment,
        feedback_reconciliation=proof,
        recovery_authority_id="test-recovery-authority",
        recovery_key_id="test-recovery-key",
    )
    replay = sign_replay(replay_unsigned, private)
    assert verify_replay(replay, public, "test-recovery-authority", "test-recovery-key")
    assert not verify_replay(replay.model_copy(update={"public_reply_base64": "V29ybGQ="}), public,
                             "test-recovery-authority", "test-recovery-key")

    # A valid outer signature must not make an internally inconsistent replay
    # acceptable. Both inner and outer objects are signed independently.
    altered_proof = sign_reconciliation(
        proof_unsigned.model_copy(update={"response_commitment": "9" * 64}), private
    )
    inconsistent = sign_replay(
        replay_unsigned.model_copy(update={"feedback_reconciliation": altered_proof}), private
    )
    assert not verify_replay(inconsistent, public, "test-recovery-authority", "test-recovery-key")


def test_recovery_wire_models_reject_unknown_fields_and_wrong_versions():
    values = _unsigned_values()
    with pytest.raises(ValidationError):
        FeedbackReconciliationUnsigned.model_validate(values | {"private_prompt": "secret"})
    with pytest.raises(ValidationError):
        FeedbackReconciliationUnsigned.model_validate(values | {"schema_version": "arena.v2"})


class _DirectAnchor:
    """Synthetic test adapter around the same signed append-only journal."""

    def __init__(self, journal, key):
        self.journal = journal
        self.public_key = key.public_key().public_bytes_raw()
        self.authority_id = "test-anchor-authority"
        self.key_id = "test-anchor-key"

    def prepare(self, event):
        return self.journal.prepare(event.model_dump(mode="json"))

    def commit(self, event):
        return self.journal.commit(event.model_dump(mode="json"))

    def abort(self, event, reason_code):
        return self.journal.abort(event.model_dump(mode="json"), reason_code)

    def records(self, context):
        return self.journal.records(context)

    def verify_events(self, context, events):
        state = verify_anchor_records(
            self.records(context), context, self.public_key, self.key_id, self.authority_id
        )
        if state["pending"] or state["event_sequence"] != len(events):
            raise ValueError("anchor/event count mismatch")
        for event in events:
            op = operation_id(context, event.sequence, event_digest(event))
            if op not in state["committed"]:
                raise ValueError("event is not independently committed")
        return state

    def terminal_close(self, checkpoint, witness, integrity):
        return self.journal.terminal_close(
            checkpoint.model_dump(mode="json"), witness.model_dump(mode="json"), integrity)

    def verify_terminal(self, context, checkpoint, witness, integrity):
        state = verify_anchor_records(self.records(context), context, self.public_key,
                                      self.key_id, self.authority_id)
        terminal = state["terminal"]
        assert terminal and terminal["final_integrity"] == integrity
        assert terminal["recorder_event_count"] == checkpoint.checkpoint.event_count
        assert terminal["final_event_root"] == checkpoint.checkpoint.final_root
        return terminal


@pytest.mark.parametrize(
    "recovery_case", [
        "success", "source_mismatch", "missing_reservation", "unknown_execution",
        "execution_disagreement", "authority_unavailable", "transient_timeout",
        "settlement_ack_loss", "concurrent_instances", "release_tamper",
        "original_receipt_recorder", "original_receipt_broker",
    ]
)
def test_synthetic_orphan_recovery_persists_stable_separately_signed_replay(tmp_path, recovery_case):
    async def scenario():
        anchor_key = Ed25519PrivateKey.generate()
        recovery_key = Ed25519PrivateKey.generate()
        authority = {
            "authority_id": "test-feedback-recovery",
            "key_id": "test-feedback-recovery-key",
            "public_key_bytes": recovery_key.public_key().public_bytes_raw(),
        }
        journal = RecoveryAnchor(
            tmp_path / "anchor.sqlite3", anchor_key,
            "test-anchor-authority", "test-anchor-key",
        )
        anchor = _DirectAnchor(journal, anchor_key)
        env = await environment(
            tmp_path / "service",
            sealed_transport=True,
            anchor=anchor,
            recovery_authority=authority,
            recovery_private_key=recovery_key.private_bytes_raw(),
        )
        async def resolve(payload_ref):
            assert payload_ref == env.source.payload_ref
            return env.source
        env.controller.corpus.resolve = resolve
        turn = submit(env, key="original-turn-key")
        assert await env.worker.run_once()
        original_signed = env.recorder.get_turn_authorization(env.ctx, turn["turn_id"])

        # Assemble a synthetic pre-receipt state from a completed component
        # fixture while preserving its event and private openings. This exercises
        # the reconstruction checks; it does not simulate process death. Delete
        # all later receipt/body copies so none secretly remains available.
        with env.store.transaction() as conn:
            body = conn.execute(
                "SELECT body_ref FROM n06_jobs WHERE turn_id=?", (turn["turn_id"],)
            ).fetchone()[0]
            if body is not None:
                conn.execute(
                    "UPDATE n06_jobs SET body_ref=NULL WHERE turn_id=?", (turn["turn_id"],)
                )
                conn.execute(
                    "DELETE FROM payloads WHERE artifact_id=? AND kind='n06-feedback'", (body,)
                )
            assert conn.execute(
                "SELECT 1 FROM payloads WHERE kind='n06-feedback' LIMIT 1"
            ).fetchone() is None
        # Recreate the durable-store boundary after FEEDBACK_AUTHORIZED but before
        # its bound receipt/body were copied to the broker projection.
        with env.recorder._get_connection() as conn:
            if recovery_case != "original_receipt_recorder":
                conn.execute(
                "DELETE FROM turn_authorizations WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                (env.ctx.domain_id, env.ctx.experiment_id, env.ctx.epoch, turn["turn_id"]),
                )
        with env.store.transaction() as conn:
            conn.execute(
                "UPDATE n06_jobs SET state='CLAIMED',body_ref=NULL,published=0,known_execution=? WHERE turn_id=?",
                ("NOT_EVALUATED" if recovery_case == "success" else "EXECUTED", turn["turn_id"]),
            )
            conn.execute(
                "UPDATE turns SET state='DISPATCHED',result_json=NULL WHERE id=?",
                (turn["turn_id"],),
            )
            conn.execute(
                "UPDATE n04_turns SET state='DISPATCHED',known_execution='EXECUTED',result_json=NULL,feedback_ref=NULL,receipt_json=? WHERE turn_id=?",
                (original_signed.model_dump_json() if recovery_case == "original_receipt_broker" else None,
                 turn["turn_id"]),
            )
        request = FeedbackRecoveryRequest(
            turn_id=turn["turn_id"], idempotency_key="original-turn-key"
        )
        event_bytes = env.recorder.get_event_bytes(env.ctx)
        if recovery_case in {"original_receipt_recorder", "original_receipt_broker"}:
            from arena.contracts.evidence import TurnFeedback
            body = await env.controller.recover_feedback(env.p["red"], request)
            copied = TurnFeedback.model_validate_json(body)
            assert copied.feedback_receipt == original_signed
            assert env.recorder.get_turn_authorization(env.ctx, turn["turn_id"]) == original_signed
            assert await env.controller.recover_feedback(env.p["red"], request) == body
            if recovery_case == "original_receipt_recorder":
                # Retry through the existing broker-copy path after losing only
                # the recorder projection; recovery must restore the exact
                # signature from authenticated broker bytes without re-signing.
                with env.recorder._get_connection() as conn:
                    conn.execute(
                        "DELETE FROM turn_authorizations WHERE domain_id=? AND experiment_id=? "
                        "AND epoch=? AND turn_id=?",
                        (env.ctx.domain_id, env.ctx.experiment_id, env.ctx.epoch, turn["turn_id"]),
                    )
                assert env.recorder.get_turn_authorization(env.ctx, turn["turn_id"]) is None
                restored = await env.controller.recover_feedback(env.p["red"], request)
                assert restored == body
                assert env.recorder.get_turn_authorization(env.ctx, turn["turn_id"]) == original_signed
                assert env.recorder.get_event_bytes(env.ctx) == event_bytes
            assert env.recorder.get_event_bytes(env.ctx) == event_bytes
            with env.store.connect() as conn:
                stored = conn.execute("SELECT receipt_json,state FROM n04_turns WHERE turn_id=?",
                                      (turn["turn_id"],)).fetchone()
                assert stored[0] == original_signed.model_dump_json() and stored[1] == "DONE"
                assert conn.execute("SELECT 1 FROM n04_recoveries WHERE turn_id=?",
                                    (turn["turn_id"],)).fetchone() is None
            assert len(env.runtime.model.calls) == 1
            if recovery_case == "original_receipt_broker":
                await env.controller._event("INTEGRITY_VIOLATION", "FAILED", turn={
                    **env.ctx.model_dump(), "session_id": env.session,
                    "turn_id": turn["turn_id"], "turn_index": turn["turn_index"],
                })
                env.controller._invalidate()
                with pytest.raises(DependencyUnavailable, match="FEEDBACK_RECOVERY_ORIGINAL_RECEIPT_INVALID"):
                    await env.controller.recover_feedback(env.p["red"], request)
                with env.store.connect() as conn:
                    stored = conn.execute("SELECT receipt_json FROM n04_turns WHERE turn_id=?",
                                          (turn["turn_id"],)).fetchone()[0]
                    failure = conn.execute("SELECT original_body_ref FROM n04_recovery_failures WHERE turn_id=?",
                                           (turn["turn_id"],)).fetchone()
                    assert stored == original_signed.model_dump_json()
                    assert failure and conn.execute("SELECT 1 FROM payloads WHERE artifact_id=?",
                                                    (failure[0],)).fetchone()
                await env.controller.close(env.p["operator"])
                export_key = Ed25519PrivateKey.generate()
                export_authority = {"key_id": "invalid-copy", "public_key_bytes": export_key.public_key().public_bytes_raw()}
                invalid_path = tmp_path / "invalid-copy.zip"
                env.controller.export_invalid_evidence(env.p["auditor"], invalid_path, export_authority, export_key)
                from arena.verifier.invalid_bundle import verify_invalid_evidence_bundle
                verified = verify_invalid_evidence_bundle(
                    invalid_path, recorder_key=env.controller.recorder_public_key,
                    witness_key=env.controller.witness_public_key, export_key=export_authority["public_key_bytes"],
                    expected_context=env.ctx,
                    expected_manifest_digest=env.controller._row(env.p["auditor"])["public_commitment"],
                    recorder_key_id=env.recorder.signer_key_id,
                    witness_key_id=env.controller.witness.witness_key_id, export_key_id="invalid-copy")
                assert verified["status"] == "AUTHENTIC_INVALID_INCOMPLETE"
                return
            await env.controller.close(env.p["operator"])
            env.controller.export(env.p["auditor"], tmp_path / "original-copy-valid.zip")
            return
        if recovery_case == "source_mismatch":
            tampered_source = env.source.model_copy(
                update={"text": env.source.text + " altered after execution"}
            )

            async def resolve_tampered(_payload_ref):
                return tampered_source

            env.controller.corpus.resolve = resolve_tampered
            with pytest.raises(DependencyUnavailable, match="FEEDBACK_RECOVERY_SOURCE_MISMATCH"):
                await env.controller.recover_feedback(env.p["red"], request)
            with env.store.connect() as conn:
                job = conn.execute(
                    "SELECT state,known_execution,body_ref,published FROM n06_jobs WHERE turn_id=?",
                    (turn["turn_id"],),
                ).fetchone()
                projection = conn.execute(
                    "SELECT t.state,n.state,n.known_execution,n.receipt_json,s.quarantined,e.phase,e.integrity "
                    "FROM turns t JOIN n04_turns n ON n.turn_id=t.id JOIN sessions s ON s.id=t.session_id "
                    "JOIN experiments e ON e.id=t.experiment_id WHERE t.id=?",
                    (turn["turn_id"],),
                ).fetchone()
            assert tuple(job) == ("FAILED", "EXECUTED", None, 0)
            assert tuple(projection) == (
                "FAILED", "RECOVERY_INVALID", "EXECUTED", None, 1, "INVALID", "INVALID"
            )
            assert len([event for event in env.recorder.get_events(env.ctx)
                        if event.event_type == "INTEGRITY_VIOLATION"]) == 1
            await env.controller.close(env.p["operator"])
            with env.store.connect() as conn:
                closed = conn.execute(
                    "SELECT phase,integrity FROM experiments WHERE id=?",
                    (env.ctx.experiment_id,),
                ).fetchone()
            assert tuple(closed) == ("CLOSED", "INVALID")
            return
        if recovery_case in {"missing_reservation", "unknown_execution", "execution_disagreement"}:
            with env.store.transaction() as conn:
                if recovery_case == "missing_reservation":
                    conn.execute(
                        "DELETE FROM idempotency WHERE subject_id=? AND domain_id=? AND experiment_id=? "
                        "AND epoch=? AND action='turns' AND client_key=?",
                        (env.p["red"].subject_id, env.ctx.domain_id, env.ctx.experiment_id,
                         env.ctx.epoch, "original-turn-key"),
                    )
                elif recovery_case == "unknown_execution":
                    conn.execute(
                        "UPDATE n04_turns SET known_execution='UNKNOWN' WHERE turn_id=?",
                        (turn["turn_id"],),
                    )
                    conn.execute(
                        "UPDATE n06_jobs SET known_execution='UNKNOWN' WHERE turn_id=?",
                        (turn["turn_id"],),
                    )
                else:
                    conn.execute(
                        "UPDATE n06_jobs SET known_execution='UNKNOWN' WHERE turn_id=?",
                        (turn["turn_id"],),
                    )
            expected_error = (
                "FEEDBACK_RESERVATION_MISSING"
                if recovery_case == "missing_reservation"
                else "FEEDBACK_RECOVERY_EXECUTION_UNKNOWN"
                if recovery_case in {"unknown_execution", "execution_disagreement"}
                else "FEEDBACK_RECOVERY_EXECUTION_NOT_ESTABLISHED"
            )
            with pytest.raises(DependencyUnavailable, match=expected_error):
                await env.controller.recover_feedback(env.p["red"], request)
            with env.store.connect() as conn:
                job = conn.execute(
                    "SELECT state,known_execution,body_ref,published FROM n06_jobs WHERE turn_id=?",
                    (turn["turn_id"],),
                ).fetchone()
                projection = conn.execute(
                    "SELECT t.state,n.state,n.known_execution,n.receipt_json,s.quarantined,e.phase,e.integrity "
                    "FROM turns t JOIN n04_turns n ON n.turn_id=t.id JOIN sessions s ON s.id=t.session_id "
                    "JOIN experiments e ON e.id=t.experiment_id WHERE t.id=?",
                    (turn["turn_id"],),
                ).fetchone()
            expected_execution = "UNKNOWN" if recovery_case == "unknown_execution" else "EXECUTED"
            if recovery_case == "execution_disagreement":
                expected_execution = "UNKNOWN"
            assert tuple(job) == ("FAILED", expected_execution, None, 0)
            assert tuple(projection) == (
                "UNKNOWN" if expected_execution == "UNKNOWN" else "FAILED",
                "RECOVERY_INVALID", expected_execution, None, 1, "INVALID", "INVALID"
            )
            assert len([event for event in env.recorder.get_events(env.ctx)
                        if event.event_type == "INTEGRITY_VIOLATION"]) == 1
            with env.store.connect() as conn:
                assert conn.execute(
                    "SELECT 1 FROM n04_recoveries WHERE turn_id=?", (turn["turn_id"],)
                ).fetchone() is None
                turn_result = conn.execute(
                    "SELECT result_json FROM turns WHERE id=?", (turn["turn_id"],)
                ).fetchone()[0]
            assert json.loads(turn_result)["model_execution"] == expected_execution
            await env.controller.close(env.p["operator"])
            return
        if recovery_case == "authority_unavailable":
            original_authority = env.controller.recovery_authority
            env.controller.recovery_authority = None
            with pytest.raises(DependencyUnavailable, match="FEEDBACK_RECOVERY_AUTHORITY_UNAVAILABLE"):
                await env.controller.recover_feedback(env.p["red"], request)
            with env.store.connect() as conn:
                run = conn.execute(
                    "SELECT phase,integrity FROM experiments WHERE id=?",
                    (env.ctx.experiment_id,),
                ).fetchone()
                job = conn.execute(
                    "SELECT state,known_execution,body_ref,published FROM n06_jobs WHERE turn_id=?",
                    (turn["turn_id"],),
                ).fetchone()
            assert tuple(run) == ("RUNNING", "PENDING")
            assert tuple(job) == ("CLAIMED", "EXECUTED", None, 0)
            assert env.controller.recovery_admission_blocked is True
            assert not any(event.event_type == "INTEGRITY_VIOLATION"
                           for event in env.recorder.get_events(env.ctx))
            env.controller.recovery_authority = original_authority
        if recovery_case == "transient_timeout":
            async def unavailable_once(_payload_ref):
                raise TimeoutError("temporary source read timeout")

            env.controller.corpus.resolve = unavailable_once
            with pytest.raises(TimeoutError, match="temporary source read timeout"):
                await env.controller.recover_feedback(env.p["red"], request)
            with env.store.connect() as conn:
                run = conn.execute(
                    "SELECT phase,integrity FROM experiments WHERE id=?",
                    (env.ctx.experiment_id,),
                ).fetchone()
                job = conn.execute(
                    "SELECT state,body_ref,published FROM n06_jobs WHERE turn_id=?",
                    (turn["turn_id"],),
                ).fetchone()
            assert tuple(run) == ("RUNNING", "PENDING")
            assert tuple(job) == ("CLAIMED", None, 0)
            assert env.controller.recovery_admission_blocked is True
            assert not any(event.event_type == "INTEGRITY_VIOLATION"
                           for event in env.recorder.get_events(env.ctx))
            env.controller.corpus.resolve = resolve
        if recovery_case == "settlement_ack_loss":
            original_settle = env.controller._settle_recovered_feedback
            lost_ack = {"raised": False}

            async def settle_then_lose_ack(replay):
                result = await original_settle(replay)
                if not lost_ack["raised"]:
                    lost_ack["raised"] = True
                    raise RecoveryAnchorError("ANCHOR_UNAVAILABLE")
                return result

            env.controller._settle_recovered_feedback = settle_then_lose_ack
            with pytest.raises(RecoveryAnchorError, match="ANCHOR_UNAVAILABLE"):
                await env.controller.recover_feedback(env.p["red"], request)
            with env.store.connect() as conn:
                proof = conn.execute(
                    "SELECT replay_ref FROM n04_recoveries WHERE turn_id=?",
                    (turn["turn_id"],),
                ).fetchone()
                turn_state = conn.execute(
                    "SELECT state FROM turns WHERE id=?", (turn["turn_id"],)
                ).fetchone()[0]
                job_state = conn.execute(
                    "SELECT state FROM n06_jobs WHERE turn_id=?", (turn["turn_id"],)
                ).fetchone()[0]
            assert proof and turn_state == "COMPLETED" and job_state == "FAILED"
            assert len([event for event in env.recorder.get_events(env.ctx)
                        if event.event_type == "INTEGRITY_VIOLATION"]) == 0
            assert env.controller.recovery_admission_blocked is True
            env.controller._settle_recovered_feedback = original_settle

        if recovery_case == "concurrent_instances":
            second = type(env.controller)(
                env.broker, env.recorder, env.controller.witness, env.controller.vault,
                env.runtime, env.controller.corpus,
                recorder_public_key=env.controller.recorder_public_key,
                witness_public_key=env.controller.witness_public_key,
                transport_admission=env.admission, recovery_authority=authority,
                recovery_private_key=recovery_key.private_bytes_raw(),
            )
            arrived, barrier = {"count": 0}, asyncio.Event()
            async def resolve_together(payload_ref):
                assert payload_ref == env.source.payload_ref
                arrived["count"] += 1
                if arrived["count"] == 2:
                    barrier.set()
                await barrier.wait()
                return env.source
            env.controller.corpus.resolve = resolve_together
            outcomes = await asyncio.gather(
                env.controller.recover_feedback(env.p["red"], request),
                second.recover_feedback(env.p["red"], request), return_exceptions=True,
            )
            assert sum(isinstance(value, bytes) for value in outcomes) == 1
            loser = next(value for value in outcomes if not isinstance(value, bytes))
            assert isinstance(loser, DependencyUnavailable) and str(loser) == "FEEDBACK_RECOVERY_STATE_CHANGED"
            assert await second.recover_feedback(env.p["red"], request) == next(
                value for value in outcomes if isinstance(value, bytes))
        replay_bytes = await env.controller.recover_feedback(env.p["red"], request)
        replay = FeedbackReplay.model_validate_json(replay_bytes)
        assert replay_bytes.endswith(b"\n")  # Wire framing newline; signature bytes exclude it.
        assert verify_replay(replay, authority["public_key_bytes"], authority["authority_id"], authority["key_id"])
        assert verify_reconciliation(replay.feedback_reconciliation, authority["public_key_bytes"],
                                     authority["authority_id"], authority["key_id"])
        assert replay.turn_id == turn["turn_id"]
        assert replay.feedback_reconciliation.reservation_id == turn["turn_id"]
        assert replay.feedback_reconciliation.queue_job_id == turn["turn_id"]
        assert replay.feedback_reconciliation.feedback_event_digest == replay.feedback_reconciliation.prefix_root
        assert await env.controller.recover_feedback(env.p["red"], request) == replay_bytes
        recovered_event_bytes = env.recorder.get_event_bytes(env.ctx)
        before_lines = event_bytes.splitlines()
        recovered_lines = recovered_event_bytes.splitlines()
        assert recovered_lines == before_lines
        assert len([event for event in env.recorder.get_events(env.ctx)
                    if event.event_type == "INTEGRITY_VIOLATION"]) == 0
        with env.store.connect() as conn:
            job = conn.execute("SELECT state,body_ref,published FROM n06_jobs WHERE turn_id=?", (turn["turn_id"],)).fetchone()
            recovered = conn.execute("SELECT proof_json,replay_ref FROM n04_recoveries WHERE turn_id=?", (turn["turn_id"],)).fetchone()
            admitted = conn.execute("SELECT admitted FROM budgets WHERE experiment_id=? AND subject_id='red'", (env.ctx.experiment_id,)).fetchone()[0]
            projection = conn.execute(
                "SELECT t.state,t.result_json,n.state,n.known_execution,n.receipt_json,s.quarantined,e.phase,e.integrity "
                "FROM turns t JOIN n04_turns n ON n.turn_id=t.id JOIN sessions s ON s.id=t.session_id "
                "JOIN experiments e ON e.id=t.experiment_id WHERE t.id=?", (turn["turn_id"],)
            ).fetchone()
        assert tuple(job) == ("FAILED", None, 0)
        assert projection[0] == "COMPLETED" and json.loads(projection[1])["model_execution"] == "EXECUTED"
        assert projection[2:6] == ("RECOVERED", "EXECUTED", None, 1)
        assert projection[6:] == ("RUNNING", "PENDING")
        assert recovered and env.controller._read_recovery_payload(
            recovered["replay_ref"], "n04-feedback-replay") == replay_bytes
        assert admitted == 1
        for database_file in env.root.glob("broker.sqlite3*"):
            raw = database_file.read_bytes()
            assert replay.public_reply_base64.encode() not in raw
            assert replay_bytes not in raw

        closed_checkpoint = await env.controller.close(env.p["operator"])
        with env.store.connect() as conn:
            closed = conn.execute("SELECT phase,integrity FROM experiments WHERE id=?", (env.ctx.experiment_id,)).fetchone()
        assert tuple(closed) == ("CLOSED", "VALID_WITHIN_PROFILE")

        export_key = Ed25519PrivateKey.generate()
        export_authority = {
            "authority_id": "test-invalid-export",
            "key_id": "test-invalid-export-key",
            "public_key_bytes": export_key.public_key().public_bytes_raw(),
        }
        invalid_path = tmp_path / "recovered-invalid.zip"
        with pytest.raises(DependencyUnavailable, match="CLOSED_INVALID_RUN"):
            env.controller.export_invalid_evidence(
                env.p["auditor"], invalid_path, export_authority, export_key)
        assert not invalid_path.exists()
        valid_path = tmp_path / "reconciled-valid.zip"
        env.controller.export(env.p["auditor"], valid_path)
        from arena.verifier.reconciled_bundle import verify_reconciled_evidence_bundle
        from arena.contracts.crypto import canonical_bytes
        keys = env.controller.vault.private_replay_keys(
            closed_checkpoint.checkpoint.required_artifacts)
        result = verify_reconciled_evidence_bundle(
            valid_path,
            anchor_records_bytes=b"".join(canonical_bytes(record) + b"\n" for record in anchor.records(env.ctx)),
            recorder_key=env.controller.recorder_public_key,
            witness_key=env.controller.witness_public_key,
            anchor_key=anchor.public_key,
            recovery_key=authority["public_key_bytes"],
            expected_context=env.ctx,
            expected_manifest_digest=env.controller._row(env.p["auditor"])["public_commitment"],
            recorder_key_id=env.recorder.signer_key_id,
            witness_key_id=env.controller.witness.witness_key_id,
            anchor_authority_id=anchor.authority_id,
            anchor_key_id=anchor.key_id,
            recovery_authority_id=authority["authority_id"],
            recovery_key_id=authority["key_id"],
            artifact_keys={identifier: bytes.fromhex(value["key"]) for identifier, value in keys.items()},
            artifact_classifications={identifier: value["classification"] for identifier, value in keys.items()},
            expected_defense_mode="INPUT", expected_broker_actor="n04-trusted-broker",
            transport_trust=env.admission.trust, require_transport_profile=True,
        )
        assert result["status"] == "PASS_RECONCILED_EVIDENCE"
        if recovery_case == "success":
            import subprocess
            import sys
            anchor_path, keys_path = tmp_path / "anchor-records.jsonl", tmp_path / "replay-keys.json"
            anchor_path.write_bytes(b"".join(canonical_bytes(record) + b"\n"
                                           for record in anchor.records(env.ctx)))
            keys_path.write_text(json.dumps(keys), encoding="utf-8")
            trust = env.admission.trust
            command = [
                sys.executable, "-m", "arena.verifier.cli", "--bundle", str(valid_path),
                "--recorder-key", env.controller.recorder_public_key.hex(),
                "--recorder-key-id", env.recorder.signer_key_id,
                "--witness-key", env.controller.witness_public_key.hex(),
                "--witness-key-id", env.controller.witness.witness_key_id,
                "--domain-id", env.ctx.domain_id, "--experiment-id", env.ctx.experiment_id,
                "--epoch", str(env.ctx.epoch), "--manifest-digest",
                env.controller._row(env.p["auditor"])["public_commitment"],
                "--anchor-records", str(anchor_path), "--anchor-key", anchor.public_key.hex(),
                "--anchor-key-id", anchor.key_id, "--anchor-authority-id", anchor.authority_id,
                "--recovery-key", authority["public_key_bytes"].hex(),
                "--recovery-key-id", authority["key_id"],
                "--recovery-authority-id", authority["authority_id"],
                "--keys-json", str(keys_path), "--defense-mode", "INPUT",
                "--broker-actor", "n04-trusted-broker", "--require-transport-profile",
                "--transport-profile-key", trust.transport_public_key.hex(),
                "--transport-profile-key-id", trust.transport_key_id,
                "--feedback-policy-key", trust.feedback_public_key.hex(),
                "--feedback-policy-key-id", trust.feedback_key_id,
            ]
            verified = subprocess.run(command, capture_output=True, text=True, timeout=30)
            assert verified.returncode == 0, verified.stderr
            assert json.loads(verified.stdout)["status"] == "PASS_RECONCILED_EVIDENCE"
        if recovery_case == "release_tamper":
            with env.store.transaction() as conn:
                proof = json.loads(conn.execute(
                    "SELECT proof_json FROM n04_recoveries WHERE turn_id=?", (turn["turn_id"],)
                ).fetchone()[0])
                proof["signature"] = "0" * 128
                conn.execute("UPDATE n04_recoveries SET proof_json=? WHERE turn_id=?",
                             (json.dumps(proof), turn["turn_id"]))
            with pytest.raises(DependencyUnavailable, match="RELEASE_RECOVERY_EVIDENCE_INVALID"):
                env.controller.release(env.p["operator"])
            with env.store.connect() as conn:
                assert conn.execute("SELECT phase FROM experiments WHERE id=?",
                                    (env.ctx.experiment_id,)).fetchone()[0] == "CLOSED"
                assert conn.execute("SELECT release_id FROM n04_runs WHERE experiment_id=?",
                                    (env.ctx.experiment_id,)).fetchone()[0] is None
            return
        assert env.controller.release(env.p["operator"])
        assert await env.controller.recover_feedback(env.p["red"], request) == replay_bytes

    asyncio.run(scenario())
