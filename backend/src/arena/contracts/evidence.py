"""Canonical evidence messages shared by broker, recorder, witness and verifier."""

from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, model_validator

from .common import (Context, Count, Digest, Duration, Epoch, Index, Integrity, Opaque,
                     Signature, Text, TurnContext, Uuid, UtcTime, WireModel, as_tuple)


class ArtifactRef(WireModel):
    artifact_id: Uuid
    ciphertext_sha256: Digest


ArtifactRefs = Annotated[tuple[ArtifactRef, ...], BeforeValidator(as_tuple), Field(max_length=256)]


def unique_artifacts(refs: tuple[ArtifactRef, ...]) -> None:
    if len({ref.artifact_id for ref in refs}) != len(refs):
        raise ValueError("Duplicate artifact identity")


ATTEMPT_EVENTS = {"TURN_COMMITTED", "DISPATCH_INTENT", "DEFENSE_RESULT", "MODEL_RESULT", "SCORE_RESULT", "FEEDBACK_AUTHORIZED"}
EVENT_OUTCOMES = {
    "MANIFEST_SEALED": {"OK"}, "PREFLIGHT_PASSED": {"OK"}, "START_RESERVED": {"OK"},
    "TURN_COMMITTED": {"OK"}, "DISPATCH_INTENT": {"OK"},
    "DEFENSE_RESULT": {"ALLOW", "BLOCK", "SANITIZE", "FAILED"},
    "MODEL_RESULT": {"OK", "FAILED", "UNKNOWN"}, "SCORE_RESULT": {"OK", "FAILED"},
    "FEEDBACK_AUTHORIZED": {"OK"}, "CLOSE_REQUESTED": {"OK", "INVALID"}, "CLOSED": {"OK", "INVALID"},
    "INTEGRITY_VIOLATION": {"INVALID", "FAILED", "UNKNOWN", "UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "INVALID_SCHEMA", "WRONG_PHASE", "STALE_EPOCH", "VERSION_MISMATCH", "IDEMPOTENCY_CONFLICT", "BODY_TOO_LARGE", "RESOURCE_BUDGET_EXCEEDED", "AUDIT_UNAVAILABLE", "MODEL_UNAVAILABLE", "POLICY_NOT_READY", "DEADLINE_EXCEEDED"},
}
EventType = Literal["MANIFEST_SEALED", "PREFLIGHT_PASSED", "START_RESERVED", "TURN_COMMITTED", "DISPATCH_INTENT", "DEFENSE_RESULT", "MODEL_RESULT", "SCORE_RESULT", "FEEDBACK_AUTHORIZED", "INTEGRITY_VIOLATION", "CLOSE_REQUESTED", "CLOSED"]
OutcomeCode = Literal["OK", "ALLOW", "BLOCK", "SANITIZE", "FAILED", "UNKNOWN", "INVALID", "UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "INVALID_SCHEMA", "WRONG_PHASE", "STALE_EPOCH", "VERSION_MISMATCH", "IDEMPOTENCY_CONFLICT", "BODY_TOO_LARGE", "RESOURCE_BUDGET_EXCEEDED", "AUDIT_UNAVAILABLE", "MODEL_UNAVAILABLE", "POLICY_NOT_READY", "DEADLINE_EXCEEDED"]


class EventProposal(Context):
    """Authenticated caller proposes only these fields; recorder supplies all others."""
    session_id: Uuid | None
    turn_id: Uuid | None
    turn_index: Index | None
    event_type: EventType
    outcome_code: OutcomeCode
    artifact_ciphertext_refs: ArtifactRefs
    duration_us: Duration

    @model_validator(mode="after")
    def semantics(self):
        supplied = (self.session_id, self.turn_id, self.turn_index)
        count = sum(value is not None for value in supplied)
        if count not in (0, 3):
            raise ValueError("Mixed turn context")
        if self.event_type in ATTEMPT_EVENTS and count != 3:
            raise ValueError("Attempt event requires turn context")
        if self.event_type not in ATTEMPT_EVENTS | {"INTEGRITY_VIOLATION"} and count:
            raise ValueError("Campaign event cannot carry turn context")
        if self.outcome_code not in EVENT_OUTCOMES[self.event_type]:
            raise ValueError("Event/outcome mismatch")
        unique_artifacts(self.artifact_ciphertext_refs)
        return self


class Event(EventProposal):
    schema_version: Literal["arena.v2"]
    sequence: Count
    previous_digest: Digest
    actor_id: Opaque
    public_manifest_digest: Digest
    utc_time: UtcTime

    @model_validator(mode="after")
    def genesis(self):
        if self.sequence == 1 and self.previous_digest != "0" * 64:
            raise ValueError("First event requires zero genesis")
        return self


class Checkpoint(Context):
    schema_version: Literal["arena.v2"]
    public_manifest_digest: Digest
    event_count: Count
    final_root: Digest
    terminal_marker: Literal["CLOSED"]
    required_artifacts: ArtifactRefs
    signer_key_id: Opaque

    @model_validator(mode="after")
    def artifact_set(self):
        unique_artifacts(self.required_artifacts)
        if tuple(sorted(self.required_artifacts, key=lambda ref: ref.artifact_id)) != self.required_artifacts:
            raise ValueError("Required artifact set must be sorted by artifact_id")
        return self


class SignedCheckpoint(WireModel):
    checkpoint: Checkpoint
    signature: Signature


class WitnessStart(Context):
    schema_version: Literal["arena.v2"]
    receipt_type: Literal["START"]
    public_manifest_digest: Digest
    reservation_id: Uuid
    event_count: Count
    prefix_root: Digest
    witness_key_id: Opaque


class WitnessClose(Context):
    schema_version: Literal["arena.v2"]
    receipt_type: Literal["CLOSE"]
    public_manifest_digest: Digest
    checkpoint_digest: Digest
    event_count: Count
    final_root: Digest
    witness_key_id: Opaque


class SignedWitnessStart(WireModel):
    receipt: WitnessStart
    signature: Signature


class SignedWitnessClose(WireModel):
    receipt: WitnessClose
    signature: Signature


class TurnReceipt(TurnContext):
    schema_version: Literal["arena.v2"]
    input_commitment: Digest
    event_count: Count
    prefix_root: Digest
    public_response_commitment: Digest
    signer_key_id: Opaque


class SignedTurnReceipt(WireModel):
    receipt: TurnReceipt
    signature: Signature


class TurnFeedback(WireModel):
    turn_id: Uuid
    session_id: Uuid
    turn_index: Index
    public_reply: Text
    public_status: Literal["COMPLETED", "INFRASTRUCTURE_UNAVAILABLE"]
    feedback_receipt: SignedTurnReceipt
    padding: Annotated[str, Field(pattern=r"^ *$", max_length=131_072)]

    @model_validator(mode="after")
    def bound_receipt(self):
        receipt = self.feedback_receipt.receipt
        if (receipt.turn_id, receipt.session_id, receipt.turn_index) != (self.turn_id, self.session_id, self.turn_index):
            raise ValueError("Feedback receipt context mismatch")
        return self


class ArtifactAAD(Context):
    schema_version: Literal["arena.v2"]
    artifact_id: Uuid
    classification: Literal["PUBLIC_METADATA", "PRIVATE_PAYLOAD", "PRIVATE_MODEL_OUTPUT", "PRIVATE_DEFENSE", "PRIVATE_MANIFEST"]


class SealResponse(Context):
    phase: Literal["SEALED"]
    receipt_id: Uuid
    public_commitment: Digest


class StartResponse(Context):
    phase: Literal["RUNNING"]
    receipt_id: Uuid
    witness_start_receipt: SignedWitnessStart

    @model_validator(mode="after")
    def start_binding(self):
        receipt = self.witness_start_receipt.receipt
        if (self.domain_id, self.experiment_id, self.epoch) != (receipt.domain_id, receipt.experiment_id, receipt.epoch):
            raise ValueError("Start receipt context mismatch")
        return self


class CloseResponse(Context):
    phase: Literal["CLOSED"]
    checkpoint: SignedCheckpoint

    @model_validator(mode="after")
    def close_binding(self):
        checkpoint = self.checkpoint.checkpoint
        if (self.domain_id, self.experiment_id, self.epoch) != (checkpoint.domain_id, checkpoint.experiment_id, checkpoint.epoch):
            raise ValueError("Close receipt context mismatch")
        return self


class ReleaseResponse(Context):
    phase: Literal["RELEASED"]
    release_receipt_id: Uuid
    terminal_checkpoint_digest: Digest
    integrity: Literal["VALID_WITHIN_PROFILE", "INVALID"]
