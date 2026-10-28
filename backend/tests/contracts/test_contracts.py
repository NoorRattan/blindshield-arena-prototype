"""Executable N02 invariants; no Docker, frontend, hosted model or real corpus."""

import asyncio
import copy
import itertools
import json
from pathlib import Path
import subprocess
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
import pytest

from arena.contracts.api import (AttemptResult, AttackBatch, DEFENSE_REQUEST,
                                DefenseDecision, EmbargoedView, EpochRequest,
                                IdempotencyScope, TargetRequest, TargetResponse, TurnSubmission)
from arena.contracts.common import Context
from arena.contracts.crypto import (canonical_bytes, checkpoint_digest, checkpoint_message,
                                   commitment, decrypt_artifact, encrypt_artifact, event_digest,
                                   request_digest, sign, validate_chain, verify, verify_checkpoint,
                                   verify_witness_close, witness_message)
from arena.contracts.evidence import (ArtifactAAD, Checkpoint, CloseResponse, Event, EventProposal, ReleaseResponse,
                                     SignedCheckpoint, SignedWitnessClose, WitnessClose)
from arena.contracts.jsonwire import ContractError, load_wire, strict_json
from arena.contracts.lifecycle import GateFacts, validate_transition
from arena.contracts.registry import SCHEMAS, schema_bundle
from arena.ports import DependencyUnavailable, UnavailableModel, validate_target_binding


ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "fixtures/arena-v2/vectors.json").read_text(encoding="utf-8"))
TARGET = json.loads((ROOT / "fixtures/arena-v2/target-request.json").read_text(encoding="utf-8"))
CONTEXT = {key: TARGET[key] for key in ("domain_id", "experiment_id", "epoch")}
CALL = TARGET["attempt_id"]


def wire(schema, value):
    return load_wire(schema, json.dumps(value, ensure_ascii=False).encode("utf-8"))


@pytest.mark.parametrize("epoch", [True, False, 0, -1, 1.0, "1", None, 2_147_483_648])
def test_epoch_never_coerces(epoch):
    with pytest.raises(ContractError):
        wire(EpochRequest, {"epoch": epoch})


@pytest.mark.parametrize("body", [b'{"epoch":1,"epoch":2}', b'{"epoch":NaN}', b'{"epoch":Infinity}', b'{"epoch":1e999}', b'{"epoch":1,"extra":{"x":1,"x":2}}', b'[]', b'null', b'{"epoch":1}\xff'])
def test_raw_json_rejects_ambiguity_and_nonfinite_values(body):
    with pytest.raises(ContractError):
        load_wire(EpochRequest, body)


def test_body_and_depth_caps_fail_before_model_use():
    with pytest.raises(ContractError, match="BODY_TOO_LARGE"):
        load_wire(EpochRequest, b" " * 70_001)
    with pytest.raises(ContractError):
        strict_json(("{\"x\":" * 18 + "0" + "}" * 18).encode())


def test_validation_errors_do_not_echo_payload():
    secret = "UNIQUE_PRIVATE_CANARY_DO_NOT_LOG"
    with pytest.raises(ContractError) as error:
        wire(TargetRequest, TARGET | {"text": secret, "epoch": True})
    assert secret not in str(error.value)


@pytest.mark.parametrize("field,value", [("model", "arbitrary"), ("messages", []), ("cache_salt", "shared"), ("tools", []), ("url", "https://example.invalid"), ("slot_id", 3)])
def test_target_is_closed_schema(field, value):
    with pytest.raises(ContractError):
        wire(TargetRequest, TARGET | {field: value})


@pytest.mark.parametrize("field", ["domain_id", "experiment_id", "attempt_id", "session_id"])
def test_noncanonical_identity_is_rejected(field):
    with pytest.raises(ContractError):
        wire(TargetRequest, TARGET | {field: "not-a-uuid"})


def test_utf8_byte_bounds_and_exact_unicode_are_preserved():
    value = wire(TurnSubmission, {"epoch": 1, "turn_index": 0, "text": "é\r\n"})
    assert value.text.encode() == b"\xc3\xa9\r\n"
    wire(TurnSubmission, {"epoch": 1, "turn_index": 0, "text": "é" * 32768})
    # Escaping the same content expands the raw JSON body beyond its independent cap.
    with pytest.raises(ContractError, match="BODY_TOO_LARGE"):
        load_wire(TurnSubmission, json.dumps({"epoch": 1, "turn_index": 0, "text": "é" * 32768}).encode())
    with pytest.raises(ContractError):
        wire(TurnSubmission, {"epoch": 1, "turn_index": 0, "text": "é" * 32769})
    with pytest.raises(ContractError):
        load_wire(TurnSubmission, br'{"epoch":1,"turn_index":0,"text":"\ud800"}')


@pytest.mark.parametrize("fields", [{}, {"text": None}, {"text": "x", "payload_ref": CALL}, {"text": None, "payload_ref": CALL}])
def test_turn_has_exactly_one_nonnull_source(fields):
    with pytest.raises(ContractError):
        wire(TurnSubmission, {"epoch": 1, "turn_index": 0, **fields})


def test_batch_identity_and_frozen_nested_collections():
    item = {"item_id": "i1", "text": "hello"}
    with pytest.raises(ContractError):
        wire(AttackBatch, {"epoch": 1, "items": [item, item]})
    batch = wire(AttackBatch, {"epoch": 1, "items": [item]})
    assert isinstance(batch.items, tuple)
    with pytest.raises(ValidationError):
        batch.items[0].text = "changed"


def test_exactly_nine_defense_symbols_and_no_free_text():
    accepted = []
    for verdict, reason, transform in itertools.product(
        ["ALLOW", "BLOCK", "SANITIZE"],
        ["NONE", "INJECTION_PATTERN", "TOXICITY_PATTERN", "SCHEMA_POLICY", "UNSUPPORTED", "BUDGET_POLICY"],
        [None, "REDACT_REGISTERED_MATCHES_V1"],
    ):
        body = {"call_token": CALL, "verdict": verdict, "reason_code": reason, "transform_id": transform}
        try:
            wire(DefenseDecision, body)
            accepted.append(body)
        except ContractError:
            pass
    assert len(accepted) == 9
    with pytest.raises(ContractError):
        wire(DefenseDecision, accepted[0] | {"explanation": "private reason"})


@pytest.mark.parametrize("mode,content", [("INPUT", {"prompt": "x"}), ("FEATURES", {"length_bucket": "SHORT", "control_marker_present": False}), ("OUTPUT", {"response": "x"}), ("POST_HOC", {"prompt": "x", "response": "y"})])
def test_anonymous_blue_modes_cannot_accept_red_identity(mode, content):
    wire(DEFENSE_REQUEST, {"call_token": CALL, "mode": mode, "content": content})
    with pytest.raises(ContractError):
        wire(DEFENSE_REQUEST, {"call_token": CALL, "mode": mode, "content": content, "session_id": CALL})
    with pytest.raises(ContractError):
        wire(DEFENSE_REQUEST, {"call_token": CALL, "mode": mode, "content": content | {"red_id": "red"}})


@pytest.mark.parametrize("mode,execution", [("INPUT", "NOT_EVALUATED"), ("FEATURES", "NOT_EVALUATED"), ("OUTPUT", "EXECUTED"), ("POST_HOC", "EXECUTED")])
def test_blocks_retain_mode_correct_execution(mode, execution):
    body = {"defense_mode": mode, "pipeline_disposition": "BLOCKED_BY_DEFENSE", "model_execution": execution, "scoring": "NOT_EVALUATED", "integrity": "VALID_WITHIN_PROFILE"}
    assert wire(AttemptResult, body).model_execution == execution
    with pytest.raises(ContractError):
        wire(AttemptResult, body | {"model_execution": "EXECUTED" if execution == "NOT_EVALUATED" else "NOT_EVALUATED"})


def test_invalid_does_not_erase_known_execution_and_unknown_never_valid():
    body = {"defense_mode": "OUTPUT", "pipeline_disposition": "INFRASTRUCTURE_FAILED", "model_execution": "EXECUTED", "scoring": "FAILED", "integrity": "INVALID"}
    assert wire(AttemptResult, body).model_execution == "EXECUTED"
    with pytest.raises(ContractError):
        wire(AttemptResult, body | {"model_execution": "UNKNOWN", "integrity": "VALID_WITHIN_PROFILE"})
    with pytest.raises(ContractError):
        wire(AttemptResult, body | {"model_execution": "BLOCKED_BY_DEFENSE"})


def test_idempotency_identity_excludes_request_digest_but_binds_subject():
    scope = IdempotencyScope(**CONTEXT, subject_id="red-a", action="turn", client_key="same-key")
    assert "request_digest" not in IdempotencyScope.model_fields
    assert scope.uniqueness_key() != IdempotencyScope(**CONTEXT, subject_id="red-b", action="turn", client_key="same-key").uniqueness_key()
    a = TurnSubmission(epoch=1, turn_index=0, text="é\n")
    b = TurnSubmission(epoch=1, turn_index=0, text="e\u0301\n")
    assert request_digest(a) == request_digest(a)
    assert request_digest(a) != request_digest(b)


def test_blue_active_view_cannot_carry_delayed_telemetry():
    wire(EmbargoedView, {"status": "EMBARGOED"})
    for field in ["phase", "heartbeat", "latency_ms", "attempts_count", "sequence"]:
        with pytest.raises(ContractError):
            wire(EmbargoedView, {"status": "EMBARGOED", field: 1})


def test_lifecycle_has_no_readiness_or_release_shortcut():
    with pytest.raises(ContractError):
        validate_transition("SEALED", "RUNNING", GateFacts())
    with pytest.raises(ContractError):
        validate_transition("READY", "RUNNING", GateFacts(runtime_profile_verified=True))
    with pytest.raises(ContractError):
        validate_transition("INVALID", "CLOSED", GateFacts())
    validate_transition("INVALID", "CLOSED", GateFacts(terminal_evidence_durable=True))
    with pytest.raises(ContractError):
        validate_transition("CLOSED", "RELEASED", GateFacts(terminal_evidence_durable=True))
    validate_transition("CLOSED", "RELEASED", GateFacts(terminal_evidence_durable=True, release_policy_authorized=True))
    with pytest.raises(ContractError):
        validate_transition("RELEASED", "RUNNING", GateFacts())


def test_event_context_types_actor_authority_and_terminal_marker():
    event = copy.deepcopy(VECTORS["event"])
    with pytest.raises(ContractError):
        wire(Event, event | {"session_id": CALL})
    with pytest.raises(ContractError):
        wire(Event, event | {"event_type": "DEFENSE_RESULT", "outcome_code": "ALLOW"})
    with pytest.raises(ContractError):
        wire(Event, event | {"event_type": "RELEASED"})
    proposal = {k: v for k, v in event.items() if k not in {"schema_version", "sequence", "previous_digest", "actor_id", "public_manifest_digest", "utc_time"}}
    wire(EventProposal, proposal)
    with pytest.raises(ContractError):
        wire(EventProposal, proposal | {"actor_id": "spoofed"})


def test_canonical_vectors_and_published_ed25519_reference():
    event = Event.model_validate(VECTORS["event"])
    checkpoint = Checkpoint.model_validate(VECTORS["checkpoint"])
    assert canonical_bytes(event).decode() == VECTORS["event_canonical_ascii"]
    assert event_digest(event) == VECTORS["event_digest"]
    assert checkpoint_message(checkpoint).hex() == VECTORS["checkpoint_message_hex"]
    assert commitment(bytes.fromhex(VECTORS["content_hex"]), bytes.fromhex(VECTORS["commitment_nonce_hex"])) == VECTORS["commitment_digest"]
    public = bytes.fromhex(VECTORS["test_public_key_hex"])
    assert verify(b"", VECTORS["rfc8032_empty_signature"], public)
    assert not verify(b"other-message", VECTORS["rfc8032_empty_signature"], public)
    assert not verify(b"", VECTORS["rfc8032_empty_signature"], b"bad-key")


@pytest.mark.parametrize("value", [{"x": 1.0}, {"x": "é"}, {"x": 2**53}, {"x": b"bytes"}])
def test_canonical_metadata_rejects_unsupported_values(value):
    with pytest.raises(ContractError):
        canonical_bytes(value)


def test_signature_requires_external_run_key_and_prefix_context():
    checkpoint = Checkpoint.model_validate(VECTORS["checkpoint"])
    signed = SignedCheckpoint(checkpoint=checkpoint, signature=VECTORS["checkpoint_signature"])
    public = bytes.fromhex(VECTORS["test_public_key_hex"])
    expected = Context(**CONTEXT)
    assert verify_checkpoint(signed, public, expected, "a" * 64, "recorder.test")
    assert not verify_checkpoint(signed, public, Context(**(CONTEXT | {"epoch": 2})), "a" * 64, "recorder.test")
    assert not verify_checkpoint(signed, public, expected, "b" * 64, "recorder.test")
    assert not verify(b"arena.v2/witness\x00" + canonical_bytes(checkpoint), signed.signature, public)


def test_close_response_cannot_wrap_other_run_and_release_cannot_be_pending():
    signed = {"checkpoint": VECTORS["checkpoint"], "signature": VECTORS["checkpoint_signature"]}
    wire(CloseResponse, CONTEXT | {"phase": "CLOSED", "checkpoint": signed})
    with pytest.raises(ContractError):
        wire(CloseResponse, CONTEXT | {"epoch": 2, "phase": "CLOSED", "checkpoint": signed})
    response = CONTEXT | {"phase": "RELEASED", "release_receipt_id": CALL, "terminal_checkpoint_digest": "a" * 64, "integrity": "INVALID"}
    assert wire(ReleaseResponse, response).integrity == "INVALID"
    with pytest.raises(ContractError):
        wire(ReleaseResponse, response | {"integrity": "PENDING"})


def test_witness_signature_binds_the_exact_recorder_checkpoint():
    checkpoint = Checkpoint.model_validate(VECTORS["checkpoint"])
    witness = WitnessClose(**CONTEXT, schema_version="arena.v2", receipt_type="CLOSE", public_manifest_digest="a" * 64, checkpoint_digest=checkpoint_digest(checkpoint), event_count=checkpoint.event_count, final_root=checkpoint.final_root, witness_key_id="witness.test")
    key = Ed25519PrivateKey.generate()
    signed = SignedWitnessClose(receipt=witness, signature=sign(witness_message(witness), key.private_bytes_raw()))
    assert verify_witness_close(signed, key.public_key().public_bytes_raw(), checkpoint, Context(**CONTEXT), "witness.test")
    altered = Checkpoint.model_validate(checkpoint.model_dump(mode="json") | {"final_root": "b" * 64})
    assert not verify_witness_close(signed, key.public_key().public_bytes_raw(), altered, Context(**CONTEXT), "witness.test")


def test_chain_rejects_truncation_wrong_run_and_post_terminal_append():
    first = Event.model_validate(VECTORS["event"])
    middle = Event.model_validate(first.model_dump(mode="json") | {"sequence": 2, "previous_digest": event_digest(first), "event_type": "CLOSE_REQUESTED", "outcome_code": "INVALID"})
    last = Event.model_validate(first.model_dump(mode="json") | {"sequence": 3, "previous_digest": event_digest(middle), "event_type": "CLOSED", "outcome_code": "INVALID"})
    checkpoint = Checkpoint.model_validate(VECTORS["checkpoint"] | {"event_count": 3, "final_root": event_digest(last)})
    validate_chain((first, middle, last), checkpoint)  # Structural debug evidence; not a valid finding.
    for chain in [(first, middle), (middle, first, last), (first, last, middle)]:
        with pytest.raises(ContractError):
            validate_chain(chain, checkpoint)
    wrong = Checkpoint.model_validate(checkpoint.model_dump(mode="json") | {"epoch": 2})
    with pytest.raises(ContractError):
        validate_chain((first, middle, last), wrong)


def test_aead_tampering_wrong_key_and_wrong_identity_are_rejected():
    aad = ArtifactAAD(**CONTEXT, schema_version="arena.v2", artifact_id=CALL, classification="PRIVATE_PAYLOAD")
    key, blob = encrypt_artifact(b"private synthetic canary", aad)
    assert decrypt_artifact(blob, key, aad) == b"private synthetic canary"
    altered = ArtifactAAD.model_validate(aad.model_dump(mode="json") | {"epoch": 2})
    for bad_blob, bad_key, bad_aad in [(blob[:-1] + bytes([blob[-1] ^ 1]), key, aad), (blob, bytes(32), aad), (blob, key, altered)]:
        with pytest.raises(InvalidTag):
            decrypt_artifact(bad_blob, bad_key, bad_aad)


def test_model_responses_cannot_cross_sessions_or_claim_extra_tokens():
    request = TargetRequest.model_validate(TARGET)
    data = {k: v for k, v in TARGET.items() if k != "max_output_tokens"}
    response = TargetResponse(**(data | {"text": "reply", "input_tokens": 1, "output_tokens": 1, "duration_us": 5}))
    validate_target_binding(request, response)
    for changes in ({"epoch": 2}, {"session_id": CALL}, {"output_tokens": 17}):
        with pytest.raises(DependencyUnavailable):
            validate_target_binding(request, TargetResponse.model_validate(response.model_dump(mode="json") | changes))
    with pytest.raises(DependencyUnavailable, match="MODEL_UNAVAILABLE"):
        asyncio.run(UnavailableModel().infer(request))


def test_generated_schema_matches_checked_in_bytes():
    generated = json.dumps(schema_bundle(), sort_keys=True, ensure_ascii=True, indent=2) + "\n"
    assert (ROOT / "contracts/arena.v2.schema.json").read_bytes() == generated.encode()
    assert len(SCHEMAS) == 39


def test_cli_conformance_and_validation_failure_are_offline_and_do_not_echo(tmp_path):
    result = subprocess.run([sys.executable, "-m", "arena.cli.main", "check-vectors", "--path", str(ROOT / "fixtures/arena-v2/vectors.json")], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["checks"] == 6
    bad = tmp_path / "bad.json"
    bad.write_text('{"epoch":"PRIVATE_CANARY"}')
    result = subprocess.run([sys.executable, "-m", "arena.cli.main", "validate", "EpochRequest", str(bad)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 2
    assert "PRIVATE_CANARY" not in result.stdout + result.stderr
