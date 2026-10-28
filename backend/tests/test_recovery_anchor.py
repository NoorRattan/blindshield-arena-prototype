"""Signed anchor sequence, event CAS, retries and tamper refusals."""
import asyncio
import sqlite3
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.common import Context
from arena.contracts.crypto import event_digest
from arena.contracts.evidence import Event
from arena.contracts.evidence import EventProposal
from arena.ports import DependencyUnavailable
from arena.recorder.recorder import DurableRecorder
from arena.recovery.anchor import RecoveryAnchor, RecoveryAnchorError, verify_anchor_records


def event(context, sequence, previous, kind, utc="2026-10-26T12:00:00Z"):
    return Event(
        **context.model_dump(), session_id=None, turn_id=None, turn_index=None,
        event_type=kind, outcome_code="OK", artifact_ciphertext_refs=(), duration_us=0,
        schema_version="arena.v2", sequence=sequence, previous_digest=previous,
        actor_id="test-recorder", public_manifest_digest="a" * 64, utc_time=utc,
    )


def test_prepared_commit_abort_consumes_anchor_sequence_not_event_position(tmp_path):
    key = Ed25519PrivateKey.generate()
    anchor = RecoveryAnchor(tmp_path / "anchor.sqlite3", key, "test-anchor", "test-key")
    context = Context(domain_id="10000000-0000-4000-8000-000000000001",
                      experiment_id="20000000-0000-4000-8000-000000000002", epoch=1)
    first = event(context, 1, "0" * 64, "MANIFEST_SEALED")
    prepared = anchor.prepare(first.model_dump(mode="json"))
    assert prepared["transition"] == "PREPARED" and prepared["anchor_sequence"] == 1
    committed = anchor.commit(first.model_dump(mode="json"))
    assert committed["transition"] == "COMMITTED" and committed["anchor_sequence"] == 2
    assert anchor.commit(first.model_dump(mode="json")) == committed

    next_digest = event_digest(first)
    rejected = event(context, 2, next_digest, "PREFLIGHT_PASSED")
    pending = anchor.prepare(rejected.model_dump(mode="json"))
    aborted = anchor.abort(rejected.model_dump(mode="json"), "RECORDER_APPEND_NOT_COMMITTED")
    assert pending["anchor_sequence"] == 3
    assert aborted["transition"] == "ABORTED" and aborted["anchor_sequence"] == 4
    assert anchor.abort(rejected.model_dump(mode="json"), "RECORDER_APPEND_NOT_COMMITTED") == aborted
    with pytest.raises(RecoveryAnchorError, match="ANCHOR_OPERATION_ABORTED"):
        anchor.commit(rejected.model_dump(mode="json"))

    replacement = event(context, 2, next_digest, "START_RESERVED", "2026-10-26T12:00:01Z")
    prepared_replacement = anchor.prepare(replacement.model_dump(mode="json"))
    assert prepared_replacement["anchor_sequence"] == 5
    records = anchor.records(context)
    with pytest.raises(RecoveryAnchorError, match="ANCHOR_TRUST_BINDING_INVALID"):
        verify_anchor_records(
            records, context, key.public_key().public_bytes_raw(), "test-key", "wrong-authority"
        )
    state = verify_anchor_records(records, context, key.public_key().public_bytes_raw(), "test-key")
    assert state["anchor_sequence"] == 5
    assert state["event_sequence"] == 1 and state["event_root"] == next_digest
    assert len(state["committed"]) == 1
    # The mapping retains the complete PREPARED history, including records
    # subsequently committed or aborted; live pending state is in the ledger.
    assert len(state["prepared"]) == 3


def test_unresolved_prepare_and_equivocation_block_later_records(tmp_path):
    key = Ed25519PrivateKey.generate()
    anchor = RecoveryAnchor(tmp_path / "anchor.sqlite3", key, "test-anchor", "test-key")
    context = Context(domain_id="10000000-0000-4000-8000-000000000001",
                      experiment_id="20000000-0000-4000-8000-000000000002", epoch=1)
    first = event(context, 1, "0" * 64, "MANIFEST_SEALED")
    anchor.prepare(first.model_dump(mode="json"))
    with pytest.raises(RecoveryAnchorError, match="ANCHOR_PREPARE_UNRESOLVED"):
        anchor.prepare(event(context, 1, "0" * 64, "START_RESERVED").model_dump(mode="json"))


def test_signature_context_and_database_tampering_fail_closed(tmp_path):
    key = Ed25519PrivateKey.generate()
    anchor_path = tmp_path / "anchor.sqlite3"
    anchor = RecoveryAnchor(anchor_path, key, "test-anchor", "test-key")
    context = Context(domain_id="10000000-0000-4000-8000-000000000001",
                      experiment_id="20000000-0000-4000-8000-000000000002", epoch=1)
    first = event(context, 1, "0" * 64, "MANIFEST_SEALED")
    anchor.prepare(first.model_dump(mode="json"))
    records = anchor.records(context)
    with pytest.raises(RecoveryAnchorError, match="ANCHOR_BAD_SIGNATURE"):
        verify_anchor_records(records, context, Ed25519PrivateKey.generate().public_key().public_bytes_raw(), "test-key")
    wrong_context = context.model_copy(update={"epoch": 2})
    with pytest.raises(RecoveryAnchorError, match="ANCHOR_CONTEXT_MISMATCH"):
        verify_anchor_records(records, wrong_context, key.public_key().public_bytes_raw(), "test-key")

    with sqlite3.connect(anchor_path) as conn:
        conn.execute("UPDATE recovery_records SET record_json='{}'")
    with pytest.raises(RecoveryAnchorError, match="ANCHOR_RECORD_INDEX_MISMATCH"):
        anchor.prepare(first.model_copy(update={"utc_time": "2026-10-26T12:00:01Z"}).model_dump(mode="json"))


def test_corrupt_anchor_ledger_is_not_reinitialized(tmp_path):
    key = Ed25519PrivateKey.generate()
    database = tmp_path / "anchor.sqlite3"
    database.write_bytes(b"")
    with pytest.raises(RecoveryAnchorError, match="ANCHOR_LEDGER_CORRUPT_OR_INCOMPLETE"):
        RecoveryAnchor(database, key, "test-anchor", "test-key")


def test_recorder_anchor_prepare_commit_and_early_append_refusal(tmp_path):
    context = Context(domain_id="10000000-0000-4000-8000-000000000001",
                      experiment_id="20000000-0000-4000-8000-000000000002", epoch=1)
    proposal = EventProposal(
        **context.model_dump(), session_id=None, turn_id=None, turn_index=None,
        event_type="MANIFEST_SEALED", outcome_code="OK",
        artifact_ciphertext_refs=(), duration_us=0,
    )
    recorder_key = Ed25519PrivateKey.generate()
    anchor_key = Ed25519PrivateKey.generate()
    anchor = RecoveryAnchor(tmp_path / "anchor.sqlite3", anchor_key, "test-anchor", "test-anchor-key")
    recorder = DurableRecorder(
        tmp_path / "recorder.sqlite3", recorder_key.private_bytes_raw(), "test-recorder",
        anchor=anchor,
    )

    async def run():
        with pytest.raises(DependencyUnavailable, match="UNREGISTERED_RUN_CONTEXT"):
            await recorder.append_once(proposal, "test-actor", str(uuid4()))
        recorder.register_run(context, "a" * 64, actor_id="test-actor")
        operation = str(uuid4())
        event_value = await recorder.append_once(proposal, "test-actor", operation)
        assert event_value.sequence == 1
        assert (await recorder.append_once(proposal, "test-actor", operation)) == event_value
        records = anchor.records(context)
        state = verify_anchor_records(
            records, context, anchor_key.public_key().public_bytes_raw(),
            "test-anchor-key", "test-anchor",
        )
        assert [record["transition"] for record in records] == ["PREPARED", "COMMITTED"]
        assert state["event_sequence"] == 1
        assert recorder.get_events(context) == [event_value]

    asyncio.run(run())
