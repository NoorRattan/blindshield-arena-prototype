"""Valid reconciled bundles bind all four authorities and private openings."""

import base64
import hashlib
import json
from pathlib import Path
import uuid
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.api import AttemptResult, PayloadProvenance, TargetResponse
from arena.contracts.common import Context
from arena.contracts.crypto import (
    canonical_bytes,
    checkpoint_digest,
    commitment,
    event_digest,
    sha256,
    sign,
    turn_message,
    witness_message,
)
from arena.contracts.transport_profile import (
    FeedbackPolicy,
    LabProfile,
    SealedTransportPlan,
    SignedLabProfile,
    SignedPolicy,
    TransportTrust,
    disclosure_id,
    lab_message,
    policy_message,
)
from arena.contracts.evidence import (
    ArtifactAAD,
    ArtifactRef,
    Event,
    SignedTurnReceipt,
    SignedWitnessClose,
    SignedWitnessStart,
    TurnReceipt,
    WitnessClose,
    WitnessStart,
)
from arena.evaluation.rubric import evaluate_refusal_rubric
from arena.integration.types import ScoreObservation
from arena.recovery.anchor import RecoveryAnchor, operation_id, record_digest
from arena.recovery.feedback import FeedbackReconciliationUnsigned, sign_reconciliation
from arena.ports import DependencyUnavailable
from arena.recorder.checkpoint import build_and_sign_checkpoint
from arena.contracts.crypto import encrypt_artifact
from arena.verifier.reconciled_bundle import (
    ReconciledVerificationInputs,
    export_reconciled_evidence_bundle,
    serialize_anchor_records,
    verify_reconciled_evidence_bundle,
)
from arena.verifier.rules import VerificationError


DOMAIN = "11111111-1111-4111-8111-111111111111"
EXPERIMENT = "22222222-2222-4222-8222-222222222222"
SESSION = "33333333-3333-4333-8333-333333333333"
TURN = "44444444-4444-4444-8444-444444444444"
MANIFEST = "55555555-5555-4555-8555-555555555555"
ORIGINAL = "66666666-6666-4666-8666-666666666666"
MODEL = "77777777-7777-4777-8777-777777777777"
SCORE = "88888888-8888-4888-8888-888888888888"
INPUT = "99999999-9999-4999-8999-999999999999"
RESPONSE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ACTOR = "test-broker-actor"
MODE = "POST_HOC"


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _fixture(tmp_path: Path, *, receipt=False, invalid=False, sealed_transport=True):
    context = Context(domain_id=DOMAIN, experiment_id=EXPERIMENT, epoch=1)
    recorder = Ed25519PrivateKey.generate()
    witness_key = Ed25519PrivateKey.generate()
    anchor_key = Ed25519PrivateKey.generate()
    recovery_key = Ed25519PrivateKey.generate()
    recorder_id, witness_id = "test-recorder-key", "test-witness-key"
    anchor_id, anchor_authority = "test-anchor-key", "test-anchor-authority"
    recovery_id, recovery_authority = "test-recovery-key", "test-recovery-authority"
    artifacts = {}
    keys = {}
    classes = {}
    refs = {}

    def add_artifact(artifact_id, value, classification):
        aad = ArtifactAAD(
            **context.model_dump(), schema_version="arena.v2",
            artifact_id=artifact_id, classification=classification,
        )
        key, blob = encrypt_artifact(_json(value), aad)
        ref = ArtifactRef(artifact_id=artifact_id, ciphertext_sha256=hashlib.sha256(blob).hexdigest())
        artifacts[f"artifacts/{artifact_id}.bin"] = blob
        refs[artifact_id] = ref
        keys[artifact_id] = key
        classes[artifact_id] = classification
        return ref

    lock = {"lock_schema": "test-lock-v1", "python": "3.12"}
    lock_bytes = canonical_bytes(lock)
    execution_lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    transport_trust = None
    transport_plan = None
    if sealed_transport:
        feedback_signer = Ed25519PrivateKey.generate()
        transport_signer = Ed25519PrivateKey.generate()
        policy = FeedbackPolicy(
            policy_id="test-feedback-policy",
            run_label="SYNTHETIC_MOCK",
            execution_deadline_ms=5000,
            release_floor_ms=6000,
            body_bytes=4096,
        )
        signed_policy = SignedPolicy(
            policy=policy,
            signer_key_id="test-feedback-key",
            signature=feedback_signer.sign(policy_message(policy, "test-feedback-key")).hex(),
        )
        lab = LabProfile(
            **context.model_dump(),
            execution_lock_sha256=execution_lock_sha256,
            feedback_policy_sha256=sha256(policy.model_dump_json().encode()),
            admission_window_ms=100,
        )
        signed_lab = SignedLabProfile(
            profile=lab,
            signer_key_id="test-transport-key",
            signature=transport_signer.sign(lab_message(lab, "test-transport-key")).hex(),
        )
        transport_plan = SealedTransportPlan(feedback=signed_policy, transport=signed_lab)
        transport_trust = TransportTrust(
            feedback_public_key=feedback_signer.public_key().public_bytes_raw(),
            feedback_key_id="test-feedback-key",
            transport_public_key=transport_signer.public_key().public_bytes_raw(),
            transport_key_id="test-transport-key",
        )
    private_manifest = {
        "context": context.model_dump(mode="json"),
        "profile": {
            "request": {
                "defense_mode": MODE,
                **({"disclosure_profile_id": disclosure_id(transport_plan.feedback)} if transport_plan else {}),
            },
            "execution_lock_sha256": execution_lock_sha256,
            **({"run_label": "SYNTHETIC_MOCK"} if transport_plan else {}),
        }
    }
    if transport_plan is not None:
        private_manifest["n06_transport"] = transport_plan.model_dump(mode="json")
    manifest_nonce = b"m" * 32
    manifest_digest = commitment(canonical_bytes(private_manifest), manifest_nonce)
    manifest_ref = add_artifact(MANIFEST, {
        "sealed": {"manifest": private_manifest, "commitment_nonce": manifest_nonce.hex()},
        "execution_lock_bytes_base64": _b64(lock_bytes),
        "execution_lock": lock,
    }, "PRIVATE_MANIFEST")

    turn = {
        "domain_id": DOMAIN,
        "experiment_id": EXPERIMENT,
        "epoch": 1,
        "session_id": SESSION,
        "turn_id": TURN,
        "turn_index": 0,
    }
    provenance = PayloadProvenance(
        source_id="test-source", immutable_revision="rev-1", source_sha256="a" * 64,
        record_id="record-1", license_id="test-license", run_label="SYNTHETIC_MOCK",
    ).model_dump(mode="json")
    original_text = "recoverable input"
    original_b64 = _b64(original_text.encode())
    original_ref = add_artifact(ORIGINAL, {
        **turn, "original_utf8_base64": original_b64, "provenance": provenance,
    }, "PRIVATE_PAYLOAD")
    model = TargetResponse(
        **context.model_dump(), attempt_id=TURN, session_id=SESSION, turn_index=0,
        text="cached answer", input_tokens=3, output_tokens=2, duration_us=10,
    )
    model_ref = add_artifact(MODEL, model.model_dump(mode="json"), "PRIVATE_MODEL_OUTPUT")
    score_observation = ScoreObservation(
        model_output=model_ref,
        refusal_marker_present=bool(evaluate_refusal_rubric(model.text)["is_refusal"]),
    )
    score_ref = add_artifact(SCORE, {**turn, "observation": score_observation.model_dump(mode="json")},
                             "PRIVATE_MODEL_OUTPUT")

    input_nonce, response_nonce = b"i" * 32, b"r" * 32
    input_value = {
        "schema_version": "arena-n04-input.v1",
        **turn,
        "original_utf8_base64": original_b64,
        "effective_utf8_base64": original_b64,
        "provenance": provenance,
    }
    input_content = canonical_bytes(input_value)
    input_ref = add_artifact(INPUT, {
        "kind": "INPUT_OPENING",
        "content_base64": _b64(input_content),
        "nonce_hex": input_nonce.hex(),
    }, "PRIVATE_PAYLOAD")
    response_result = AttemptResult(
        defense_mode=MODE, pipeline_disposition="ALLOWED", model_execution="EXECUTED",
        scoring="UNCERTAIN", integrity="VALID_WITHIN_PROFILE",
    )
    response_value = {
        "schema_version": "arena-n04-public-response.v1",
        **turn,
        "public_reply_utf8_base64": _b64(model.text.encode()),
        "public_status": "COMPLETED",
    }
    response_content = canonical_bytes(response_value)
    response_ref = add_artifact(RESPONSE, {
        "kind": "PUBLIC_RESPONSE_OPENING",
        "content_base64": _b64(response_content),
        "nonce_hex": response_nonce.hex(),
        "public_reply_utf8_base64": response_value["public_reply_utf8_base64"],
        "result": response_result.model_dump(mode="json"),
    }, "PRIVATE_MODEL_OUTPUT")

    events = []
    previous = "0" * 64

    def append(event_type, *, outcome="OK", turn_context=False, artifact_refs=()):
        nonlocal previous
        value = Event(
            **context.model_dump(),
            session_id=SESSION if turn_context else None,
            turn_id=TURN if turn_context else None,
            turn_index=0 if turn_context else None,
            event_type=event_type,
            outcome_code=outcome,
            artifact_ciphertext_refs=tuple(artifact_refs),
            duration_us=0,
            schema_version="arena.v2",
            sequence=len(events) + 1,
            previous_digest=previous,
            actor_id=ACTOR,
            public_manifest_digest=manifest_digest,
            utc_time="2026-10-26T12:00:00Z",
        )
        events.append(value)
        previous = event_digest(value)
        return value

    append("MANIFEST_SEALED", artifact_refs=(manifest_ref,))
    append("PREFLIGHT_PASSED")
    append("START_RESERVED")
    append("TURN_COMMITTED", turn_context=True, artifact_refs=(original_ref,))
    append("DISPATCH_INTENT", turn_context=True)
    model_event = append("MODEL_RESULT", turn_context=True, artifact_refs=(model_ref,))
    score_event = append("SCORE_RESULT", turn_context=True, artifact_refs=(score_ref,))
    feedback_event = append("FEEDBACK_AUTHORIZED", turn_context=True,
                            artifact_refs=(input_ref, response_ref))
    append("CLOSE_REQUESTED", outcome="INVALID" if invalid else "OK")
    append("CLOSED", outcome="INVALID" if invalid else "OK")

    start_receipt = WitnessStart(
        **context.model_dump(), schema_version="arena.v2", receipt_type="START",
        public_manifest_digest=manifest_digest,
        reservation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        event_count=3, prefix_root=event_digest(events[2]), witness_key_id=witness_id,
    )
    signed_start = SignedWitnessStart(
        receipt=start_receipt,
        signature=sign(witness_message(start_receipt), witness_key.private_bytes_raw()),
    )
    checkpoint = build_and_sign_checkpoint(
        context, manifest_digest, len(events), event_digest(events[-1]),
        tuple(refs.values()), recorder_id, recorder.private_bytes_raw(),
    )
    close_receipt = WitnessClose(
        **context.model_dump(), schema_version="arena.v2", receipt_type="CLOSE",
        public_manifest_digest=manifest_digest,
        checkpoint_digest=checkpoint_digest(checkpoint.checkpoint),
        event_count=len(events), final_root=event_digest(events[-1]), witness_key_id=witness_id,
    )
    signed_close = SignedWitnessClose(
        receipt=close_receipt,
        signature=sign(witness_message(close_receipt), witness_key.private_bytes_raw()),
    )
    anchor_path = tmp_path / ("anchor-invalid.sqlite3" if invalid else "anchor-valid.sqlite3")
    anchor = RecoveryAnchor(anchor_path, anchor_key, anchor_authority, anchor_id)
    for event in events:
        anchor.prepare(event.model_dump(mode="json"))
        anchor.commit(event.model_dump(mode="json"))
    anchor.terminal_close(
        checkpoint.model_dump(mode="json"), signed_close.model_dump(mode="json"),
        "INVALID" if invalid else "VALID_WITHIN_PROFILE",
    )
    anchor_bytes = serialize_anchor_records(anchor.records(context))
    state = anchor.records(context)
    anchor_committed = next(
        record for record in state
        if record["transition"] == "COMMITTED"
        and record["event_sequence"] == feedback_event.sequence
    )
    proof = sign_reconciliation(FeedbackReconciliationUnsigned(
        **turn,
        schema_version="arena.feedback-reconciliation.v1",
        feedback_event_sequence=feedback_event.sequence,
        feedback_event_digest=event_digest(feedback_event),
        prefix_root=event_digest(feedback_event),
        anchor_record_digest=record_digest(anchor_committed),
        input_artifact=input_ref,
        response_artifact=response_ref,
        input_commitment=commitment(input_content, input_nonce),
        response_commitment=commitment(response_content, response_nonce),
        reservation_id=TURN,
        model_result_digest=event_digest(model_event),
        score_result_digest=event_digest(score_event),
        queue_job_id=TURN,
        recovery_operation_id=str(uuid.uuid5(
            uuid.UUID(TURN), "arena.feedback-reconciliation.v1:" + event_digest(feedback_event)
        )),
        recovery_authority_id=recovery_authority,
        recovery_key_id=recovery_id,
    ), recovery_key.private_bytes_raw())

    payload = {
        "checkpoint.json": canonical_bytes(checkpoint),
        "witness_start.json": canonical_bytes(signed_start),
        "witness_close.json": canonical_bytes(signed_close),
        "events.jsonl": b"".join(canonical_bytes(event) + b"\n" for event in events),
        **artifacts,
    }
    if receipt:
        signed_receipt = SignedTurnReceipt(receipt=TurnReceipt(
            **turn,
            schema_version="arena.v2",
            input_commitment=commitment(input_content, input_nonce),
            event_count=feedback_event.sequence,
            prefix_root=event_digest(feedback_event),
            public_response_commitment=commitment(response_content, response_nonce),
            signer_key_id=recorder_id,
        ), signature=sign(turn_message(TurnReceipt(
            **turn,
            schema_version="arena.v2",
            input_commitment=commitment(input_content, input_nonce),
            event_count=feedback_event.sequence,
            prefix_root=event_digest(feedback_event),
            public_response_commitment=commitment(response_content, response_nonce),
            signer_key_id=recorder_id,
        )), recorder.private_bytes_raw()))
        payload["turn_receipts.jsonl"] = canonical_bytes(signed_receipt) + b"\n"
    else:
        payload["reconciliation_receipts.jsonl"] = canonical_bytes(proof) + b"\n"
    verification = ReconciledVerificationInputs(
        expected_context=context,
        expected_manifest_digest=manifest_digest,
        recorder_key=recorder.public_key().public_bytes_raw(),
        recorder_key_id=recorder_id,
        witness_key=witness_key.public_key().public_bytes_raw(),
        witness_key_id=witness_id,
        anchor_key=anchor_key.public_key().public_bytes_raw(),
        anchor_authority_id=anchor_authority,
        anchor_key_id=anchor_id,
        recovery_key=recovery_key.public_key().public_bytes_raw(),
        recovery_authority_id=recovery_authority,
        recovery_key_id=recovery_id,
        artifact_keys=keys,
        artifact_classifications=classes,
        expected_defense_mode=MODE,
        expected_broker_actor=ACTOR,
        transport_trust=transport_trust,
        require_transport_profile=sealed_transport,
    )
    return payload, anchor_bytes, verification


@pytest.mark.parametrize("receipt", [False, True])
def test_reconciled_bundle_verifies_exact_anchor_and_feedback_coverage(tmp_path, receipt):
    payload, anchor_bytes, verification = _fixture(tmp_path, receipt=receipt)
    path = tmp_path / f"reconciled-{receipt}.zip"
    export_reconciled_evidence_bundle(
        path, payload, anchor_records_bytes=anchor_bytes, verification=verification
    )
    result = verify_reconciled_evidence_bundle(
        path, anchor_records_bytes=anchor_bytes, **verification.verifier_kwargs()
    )
    assert result["status"] == "PASS_RECONCILED_EVIDENCE"
    assert result["integrity_status"] == "VALID_WITHIN_PROFILE"
    assert result["anchor_signature_verified"] is True
    assert result["terminal_anchor_verified"] is True
    assert result["anchor_records_sha256"] == hashlib.sha256(anchor_bytes).hexdigest()
    assert result["private_opening_count"] == 1
    assert result["participant_release_authorized"] is False
    assert result["transport_profile_verified"] is True
    if receipt:
        assert result["original_receipt_count"] == 1
        assert result["reconciliation_proof_count"] == 0
    else:
        assert result["original_receipt_count"] == 0
        assert result["reconciliation_proof_count"] == 1


def test_reconciled_bundle_requires_independent_transport_trust_for_sealed_profile(tmp_path):
    payload, anchor_bytes, verification = _fixture(tmp_path, sealed_transport=True)
    path = tmp_path / "transport.zip"
    export_reconciled_evidence_bundle(
        path, payload, anchor_records_bytes=anchor_bytes, verification=verification
    )
    untrusted = verification.verifier_kwargs() | {
        "transport_trust": None,
        "require_transport_profile": False,
    }
    with pytest.raises(VerificationError, match="independently pinned trust"):
        verify_reconciled_evidence_bundle(
            path, anchor_records_bytes=anchor_bytes, **untrusted
        )


def test_reconciled_bundle_rejects_wrong_anchor_proof_member_or_private_key(tmp_path):
    payload, anchor_bytes, verification = _fixture(tmp_path)
    path = tmp_path / "valid.zip"
    export_reconciled_evidence_bundle(
        path, payload, anchor_records_bytes=anchor_bytes, verification=verification
    )
    tampered_anchor = anchor_bytes.replace(b'"transition":"PREPARED"', b'"transition":"COMMITTED"', 1)
    with pytest.raises(VerificationError):
        verify_reconciled_evidence_bundle(
            path, anchor_records_bytes=tampered_anchor, **verification.verifier_kwargs()
        )
    wrong_recovery = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(VerificationError):
        verify_reconciled_evidence_bundle(
            path, anchor_records_bytes=anchor_bytes,
            **(verification.verifier_kwargs() | {"recovery_key": wrong_recovery}),
        )
    wrong_keys = dict(verification.artifact_keys)
    wrong_keys[MANIFEST] = b"z" * 32
    with pytest.raises(VerificationError):
        verify_reconciled_evidence_bundle(
            path, anchor_records_bytes=anchor_bytes,
            **(verification.verifier_kwargs() | {"artifact_keys": wrong_keys}),
        )


def test_reconciled_export_rejects_invalid_close_without_creating_archive(tmp_path):
    payload, anchor_bytes, verification = _fixture(tmp_path, invalid=True)
    destination = tmp_path / "must-not-exist.zip"
    with pytest.raises(DependencyUnavailable, match="RECONCILED_EXPORT_PREFLIGHT_FAILED"):
        export_reconciled_evidence_bundle(
            destination, payload, anchor_records_bytes=anchor_bytes, verification=verification
        )
    assert not destination.exists()


def test_reconciled_archive_does_not_smuggle_anchor_records_as_a_zip_member(tmp_path):
    payload, anchor_bytes, verification = _fixture(tmp_path)
    path = tmp_path / "valid.zip"
    export_reconciled_evidence_bundle(
        path, payload, anchor_records_bytes=anchor_bytes, verification=verification
    )
    with zipfile.ZipFile(path) as archive:
        assert "anchor_records.jsonl" not in archive.namelist()
