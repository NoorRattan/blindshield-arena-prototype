"""Separate INVALID envelope is signed, bounded and never classified as PASS."""
import hashlib
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.common import Context
from arena.contracts.crypto import checkpoint_digest, event_digest, sign, witness_message
from arena.contracts.evidence import ArtifactRef, Event, SignedWitnessClose, SignedWitnessStart, WitnessClose, WitnessStart
from arena.recorder.checkpoint import build_and_sign_checkpoint
from arena.ports import DependencyUnavailable
from arena.verifier.invalid_bundle import export_invalid_evidence_bundle, verify_invalid_evidence_bundle
from arena.verifier.rules import VerificationError


def create(tmp_path, *, missing_artifact=False, declared_artifact_id=None):
    context = Context(domain_id="10000000-0000-4000-8000-000000000001",
                      experiment_id="20000000-0000-4000-8000-000000000002", epoch=1)
    recorder = Ed25519PrivateKey.generate()
    witness_key = Ed25519PrivateKey.generate()
    anchor_key = Ed25519PrivateKey.generate()
    recovery_key = Ed25519PrivateKey.generate()
    export_key = Ed25519PrivateKey.generate()
    refs = ()
    if missing_artifact:
        refs = (ArtifactRef(
            artifact_id="40000000-0000-4000-8000-000000000004",
            ciphertext_sha256="b" * 64,
        ),)
    event = Event(**context.model_dump(), session_id=None, turn_id=None, turn_index=None,
        event_type="CLOSED", outcome_code="INVALID", artifact_ciphertext_refs=refs, duration_us=0,
        schema_version="arena.v2", sequence=1, previous_digest="0" * 64,
        actor_id="test-recorder", public_manifest_digest="a" * 64, utc_time="2026-10-26T12:00:00Z")
    cp = build_and_sign_checkpoint(context, "a" * 64, 1, event_digest(event), refs,
                                   "test-recorder", recorder.private_bytes_raw())
    start_receipt = WitnessStart(**context.model_dump(), schema_version="arena.v2", receipt_type="START",
        public_manifest_digest="a" * 64, reservation_id="30000000-0000-4000-8000-000000000003",
        event_count=1, prefix_root=event_digest(event), witness_key_id="test-witness")
    start = SignedWitnessStart(receipt=start_receipt,
        signature=sign(witness_message(start_receipt), witness_key.private_bytes_raw()))
    close_receipt = WitnessClose(**context.model_dump(), schema_version="arena.v2", receipt_type="CLOSE",
        public_manifest_digest="a" * 64, checkpoint_digest=checkpoint_digest(cp.checkpoint),
        event_count=1, final_root=event_digest(event), witness_key_id="test-witness")
    close = SignedWitnessClose(receipt=close_receipt,
        signature=sign(witness_message(close_receipt), witness_key.private_bytes_raw()))
    members = {
        "checkpoint.json": cp.model_dump_json().encode(),
        "witness_start.json": start.model_dump_json().encode(),
        "witness_close.json": close.model_dump_json().encode(),
        "events.jsonl": (event.model_dump_json() + "\n").encode(),
        "turn_receipts.jsonl": b"",
    }
    path = tmp_path / "invalid.zip"
    gap = {"gap_code": "PRIOR_INVALIDITY", "related_members": ["events.jsonl"],
           "known_execution_status": "NOT_ESTABLISHED", "event_sequence": 1,
           "event_digest": event_digest(event)}
    anchor_gap = {"gap_code": "ANCHOR_RECORDS_OMITTED", "related_members": ["events.jsonl"],
                  "known_execution_status": "NOT_ESTABLISHED", "event_sequence": 1,
                  "event_digest": event_digest(event)}
    gap_list = [gap, anchor_gap]
    if missing_artifact:
        artifact_id = declared_artifact_id or refs[0].artifact_id
        gap_list.append({
            "gap_code": "ARTIFACT_OPENING_FAILED",
            "related_members": sorted(["events.jsonl", f"artifacts/{artifact_id}.bin"]),
            "known_execution_status": "NOT_ESTABLISHED",
            "event_sequence": 1,
            "event_digest": event_digest(event),
        })
    export_invalid_evidence_bundle(path, members, gap_list, context=context,
        public_manifest_digest="a" * 64, signed_checkpoint=cp, signed_witness_start=start,
        signed_witness_close=close, last_verified_anchor_record_digest=None,
        key=export_key, key_id="test-export")
    trust = {"recorder_key": recorder.public_key().public_bytes_raw(),
        "witness_key": witness_key.public_key().public_bytes_raw(),
        "anchor_key": anchor_key.public_key().public_bytes_raw(),
        "recovery_key": recovery_key.public_key().public_bytes_raw(),
        "export_key": export_key.public_key().public_bytes_raw(),
        "expected_context": context, "expected_manifest_digest": "a" * 64,
        "recorder_key_id": "test-recorder", "witness_key_id": "test-witness",
        "anchor_key_id": "test-anchor", "recovery_key_id": "test-recovery",
        "export_key_id": "test-export"}
    return path, trust


def test_invalid_bundle_verifies_as_incomplete_not_pass(tmp_path):
    path, trust = create(tmp_path)
    result = verify_invalid_evidence_bundle(path, **trust)
    assert result["status"] == "AUTHENTIC_INVALID_INCOMPLETE"
    assert result["exit_code"] != 0
    assert result["participant_release_authorized"] is False
    assert result["safety_finding"] is False
    assert result["anchor_signature_verified"] is False
    assert result["recovery_signature_verified"] is False
    assert all(item["status"] == "GAP_BINDING_CHECKED" for item in result["gap_verification"])


def test_missing_artifact_gap_is_bound_to_the_exact_checkpoint_reference(tmp_path):
    path, trust = create(tmp_path, missing_artifact=True)
    result = verify_invalid_evidence_bundle(path, **trust)
    artifact_gap = next(item for item in result["gap_verification"]
                        if item["gap_code"] == "ARTIFACT_OPENING_FAILED")
    assert artifact_gap["status"] == "CIPHERTEXT_CUSTODY_ONLY_PRIVATE_OPENING_NOT_CHECKED"

    wrong_root = tmp_path / "wrong"
    wrong_root.mkdir()
    wrong_path, wrong_trust = create(
        wrong_root, missing_artifact=True,
        declared_artifact_id="50000000-0000-4000-8000-000000000005",
    )
    with pytest.raises(VerificationError, match="missing-artifact gap binding"):
        verify_invalid_evidence_bundle(wrong_path, **wrong_trust)


def test_invalid_bundle_refuses_corruption_and_destination_conflict(tmp_path):
    path, trust = create(tmp_path)
    original = path.read_bytes()
    with pytest.raises(DependencyUnavailable, match="DESTINATION_CONFLICT"):
        export_invalid_evidence_bundle(path, {}, [], context=trust["expected_context"],
            public_manifest_digest="a" * 64, signed_checkpoint=None, signed_witness_start=None,
            signed_witness_close=None, last_verified_anchor_record_digest=None,
            key=Ed25519PrivateKey.generate(), key_id="conflict")
    assert path.read_bytes() == original

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(tampered, "w") as target:
        for info in source.infolist():
            raw = source.read(info.filename)
            if info.filename == "events.jsonl":
                raw += b"{}\n"
            target.writestr(info, raw)
    with pytest.raises(VerificationError):
        verify_invalid_evidence_bundle(tampered, **trust)
