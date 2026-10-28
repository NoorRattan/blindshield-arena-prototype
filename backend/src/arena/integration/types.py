"""Strict additional local-profile types. These do not alter n02.1 wire schemas."""

from typing import Annotated, Literal
from pydantic import Field
from arena.contracts.common import (
    Digest,
    WireModel,
    TurnContext,
    Uuid,
    Opaque,
    Signature,
)
from arena.contracts.evidence import ArtifactRef


class AdmissionLock(WireModel):
    schema_version: Literal["arena-n04-admission.v2"]
    runtime_source_sha256: Annotated[
        dict[str, Digest], Field(min_length=1, max_length=128)
    ]
    model_repository: Literal["Qwen/Qwen2.5-0.5B-Instruct-GGUF"]
    model_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    model_filename: Literal["qwen2.5-0.5b-instruct-q4_k_m.gguf"]
    model_sha256: Digest
    model_license: Literal["Apache-2.0"]
    model_license_sha256: Digest
    tokenizer_binding: Literal["EMBEDDED_IN_EXACT_GGUF"]
    llama_image: Annotated[
        str, Field(pattern=r"^ghcr\.io/ggml-org/llama\.cpp@sha256:[0-9a-f]{64}$")
    ]
    llama_source_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    defense_python_base: Annotated[str, Field(pattern=r"^python@sha256:[0-9a-f]{64}$")]
    defense_image: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    defense_source_sha256: Digest
    corpus_receipt_sha256: Digest
    context_tokens: Literal[2048]
    input_token_cap: Annotated[int, Field(strict=True, ge=1, le=1536)]
    max_output_tokens: Annotated[int, Field(strict=True, ge=1, le=64)]
    deadline_seconds: Annotated[int, Field(strict=True, ge=1, le=45)]
    turn_limit: Literal[24]
    artifact_reservation_per_turn: Literal[8]
    claim_scope: Literal["N04_LOCAL_SINGLE_LANE_ONLY_NOT_FULL_ARENA_ACCEPTANCE"]


class ScoreObservation(WireModel):
    schema_version: Literal["arena-n04-score.v1"] = "arena-n04-score.v1"
    rubric_id: Literal["refusal-marker-observation.v1"] = (
        "refusal-marker-observation.v1"
    )
    scoring: Literal["UNCERTAIN"] = "UNCERTAIN"
    model_output: ArtifactRef
    refusal_marker_present: bool
    safety_finding: None = None


class PostHocReceipt(TurnContext):
    schema_version: Literal["arena.n04.post-hoc.v1"] = "arena.n04.post-hoc.v1"
    analysis_id: Uuid
    analysis_kind: Literal["POST_RELEASE_ONLY"] = "POST_RELEASE_ONLY"
    terminal_checkpoint_digest: Digest
    release_receipt_id: Uuid
    source_input: ArtifactRef
    source_output: ArtifactRef
    analysis_artifact: ArtifactRef
    aggregate_integrity: Literal["VALID_WITHIN_PROFILE", "INVALID"]
    signer_key_id: Opaque


class SignedPostHocReceipt(WireModel):
    receipt: PostHocReceipt
    signature: Signature


def post_hoc_message(receipt: PostHocReceipt) -> bytes:
    from arena.contracts.crypto import canonical_bytes

    return b"arena.n04/post-hoc\x00" + canonical_bytes(receipt)
