"""Versioned, separately signed evidence for exact orphan-feedback replay."""

from __future__ import annotations

from typing import Literal

from arena.contracts.common import (
    ClientKey,
    Count,
    Digest,
    Opaque,
    Signature,
    TurnContext,
    Uuid,
    WireModel,
)
from arena.contracts.crypto import canonical_bytes, sign, verify
from arena.contracts.evidence import ArtifactRef


RECONCILIATION_SCHEMA = "arena.feedback-reconciliation.v1"
REPLAY_SCHEMA = "arena.feedback-replay.v1"
RECONCILIATION_PREFIX = b"arena.feedback-reconciliation.v1\0"
REPLAY_PREFIX = b"arena.feedback-replay.v1\0"


class FeedbackRecoveryRequest(WireModel):
    """Only the original turn and its original idempotency key cross the route."""

    turn_id: Uuid
    idempotency_key: ClientKey


class FeedbackReconciliationUnsigned(TurnContext):
    schema_version: Literal["arena.feedback-reconciliation.v1"]
    feedback_event_sequence: Count
    feedback_event_digest: Digest
    prefix_root: Digest
    anchor_record_digest: Digest
    input_artifact: ArtifactRef
    response_artifact: ArtifactRef
    input_commitment: Digest
    response_commitment: Digest
    reservation_id: Uuid
    model_result_digest: Digest
    score_result_digest: Digest
    queue_job_id: Uuid
    recovery_operation_id: Uuid
    recovery_authority_id: Opaque
    recovery_key_id: Opaque


class FeedbackReconciliation(FeedbackReconciliationUnsigned):
    signature: Signature


class FeedbackReplayUnsigned(TurnContext):
    schema_version: Literal["arena.feedback-replay.v1"]
    public_reply_base64: str
    public_status: Literal["COMPLETED"]
    response_commitment: Digest
    feedback_reconciliation: FeedbackReconciliation
    recovery_authority_id: Opaque
    recovery_key_id: Opaque


class FeedbackReplay(FeedbackReplayUnsigned):
    signature: Signature


def reconciliation_message(proof: FeedbackReconciliationUnsigned) -> bytes:
    # Signature input follows the canonical-message format: domain prefix plus
    # canonical JSON bytes, with no transport newline.
    return RECONCILIATION_PREFIX + canonical_bytes(proof)


def sign_reconciliation(
    proof: FeedbackReconciliationUnsigned, private_key: bytes
) -> FeedbackReconciliation:
    signature = sign(reconciliation_message(proof), private_key)
    return FeedbackReconciliation(**proof.model_dump(mode="json"), signature=signature)


def verify_reconciliation(
    proof: FeedbackReconciliation,
    public_key: bytes,
    authority_id: str,
    key_id: str,
) -> bool:
    unsigned = FeedbackReconciliationUnsigned.model_validate(
        proof.model_dump(mode="json", exclude={"signature"})
    )
    return (
        proof.schema_version == RECONCILIATION_SCHEMA
        and proof.feedback_event_sequence > 0
        and proof.feedback_event_digest == proof.prefix_root
        and proof.reservation_id == proof.turn_id
        and proof.queue_job_id == proof.turn_id
        and proof.recovery_authority_id == authority_id
        and proof.recovery_key_id == key_id
        and verify(reconciliation_message(unsigned), proof.signature, public_key)
    )


def replay_message(replay: FeedbackReplayUnsigned) -> bytes:
    return REPLAY_PREFIX + canonical_bytes(replay)


def sign_replay(replay: FeedbackReplayUnsigned, private_key: bytes) -> FeedbackReplay:
    signature = sign(replay_message(replay), private_key)
    return FeedbackReplay(**replay.model_dump(mode="json"), signature=signature)


def verify_replay(
    replay: FeedbackReplay,
    public_key: bytes,
    authority_id: str,
    key_id: str,
) -> bool:
    unsigned = FeedbackReplayUnsigned.model_validate(
        replay.model_dump(mode="json", exclude={"signature"})
    )
    return (
        replay.schema_version == REPLAY_SCHEMA
        and replay.recovery_authority_id == authority_id
        and replay.recovery_key_id == key_id
        and verify_reconciliation(
            replay.feedback_reconciliation, public_key, authority_id, key_id
        )
        and (
            replay.domain_id,
            replay.experiment_id,
            replay.epoch,
            replay.session_id,
            replay.turn_id,
            replay.turn_index,
        )
        == (
            replay.feedback_reconciliation.domain_id,
            replay.feedback_reconciliation.experiment_id,
            replay.feedback_reconciliation.epoch,
            replay.feedback_reconciliation.session_id,
            replay.feedback_reconciliation.turn_id,
            replay.feedback_reconciliation.turn_index,
        )
        and replay.response_commitment
        == replay.feedback_reconciliation.response_commitment
        and verify(replay_message(unsigned), replay.signature, public_key)
    )
