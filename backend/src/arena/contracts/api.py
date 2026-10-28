"""Public broker requests and private adapters. No server is started by these types."""

from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, TypeAdapter, model_validator

from .common import (ClientKey, Context, DefenseMode, Digest, Disposition, Duration,
                     Epoch, Execution, Index, Integrity, InteractionMode, Opaque,
                     Phase, Scoring, Text, TurnContext, Uuid, WireModel, as_tuple)


class CreateExperiment(WireModel):
    profile_id: Opaque
    model_version_id: Opaque
    defense_version_id: Opaque
    rubric_version_id: Opaque
    disclosure_profile_id: Opaque
    interaction_mode: InteractionMode
    defense_mode: DefenseMode
    dataset_catalog_id: Opaque
    strategy_version_id: Opaque
    budget_profile_id: Opaque


class EpochRequest(WireModel):
    epoch: Epoch


class AttackItem(WireModel):
    item_id: Opaque
    text: Text


class AttackBatch(EpochRequest):
    items: Annotated[tuple[AttackItem, ...], BeforeValidator(as_tuple), Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def unique_items(self):
        if len({item.item_id for item in self.items}) != len(self.items):
            raise ValueError("Duplicate item identity")
        return self


class TurnSubmission(EpochRequest):
    turn_index: Index
    text: Text | None = None
    payload_ref: Uuid | None = None

    @model_validator(mode="after")
    def exactly_one_source(self):
        supplied = self.model_fields_set
        if ("text" in supplied) == ("payload_ref" in supplied):
            raise ValueError("Exactly one source must be supplied")
        if self.text is None and self.payload_ref is None:
            raise ValueError("Null is not a payload source")
        return self


class IdempotencyScope(Context):
    subject_id: Opaque
    action: Opaque
    client_key: ClientKey

    def uniqueness_key(self) -> tuple:
        """Request digest is stored separately; never a uniqueness-key component."""
        return (self.subject_id, self.domain_id, self.experiment_id, self.epoch, self.action, self.client_key)


class PromptContent(WireModel):
    prompt: Text


class FeaturesContent(WireModel):
    length_bucket: Literal["SHORT", "MEDIUM", "LONG"]
    control_marker_present: bool


class ResponseContent(WireModel):
    response: Text


class PostHocContent(WireModel):
    prompt: Text
    response: Text


class InputDefenseRequest(WireModel):
    call_token: Uuid
    mode: Literal["INPUT"]
    content: PromptContent


class FeaturesDefenseRequest(WireModel):
    call_token: Uuid
    mode: Literal["FEATURES"]
    content: FeaturesContent


class OutputDefenseRequest(WireModel):
    call_token: Uuid
    mode: Literal["OUTPUT"]
    content: ResponseContent


class PostHocDefenseRequest(WireModel):
    call_token: Uuid
    mode: Literal["POST_HOC"]
    content: PostHocContent


DefenseRequest = Annotated[InputDefenseRequest | FeaturesDefenseRequest | OutputDefenseRequest | PostHocDefenseRequest, Field(discriminator="mode")]
DEFENSE_REQUEST = TypeAdapter(DefenseRequest)


class DefenseDecision(WireModel):
    call_token: Uuid
    verdict: Literal["ALLOW", "BLOCK", "SANITIZE"]
    reason_code: Literal["NONE", "INJECTION_PATTERN", "TOXICITY_PATTERN", "SCHEMA_POLICY", "UNSUPPORTED", "BUDGET_POLICY"]
    transform_id: Literal["REDACT_REGISTERED_MATCHES_V1"] | None

    @model_validator(mode="after")
    def finite_symbols(self):
        valid = (
            (self.verdict == "ALLOW" and self.reason_code == "NONE" and self.transform_id is None)
            or (self.verdict == "BLOCK" and self.reason_code != "NONE" and self.transform_id is None)
            or (self.verdict == "SANITIZE" and self.reason_code in ("INJECTION_PATTERN", "TOXICITY_PATTERN", "SCHEMA_POLICY") and self.transform_id == "REDACT_REGISTERED_MATCHES_V1")
        )
        if not valid:
            raise ValueError("Unregistered defense symbol")
        return self


class TargetRequest(Context):
    # One logical turn/attempt identity: attempt_id equals the broker's turn_id.
    attempt_id: Uuid
    session_id: Uuid
    turn_index: Index
    text: Text
    max_output_tokens: Annotated[int, Field(strict=True, ge=1, le=256)]


class TargetResponse(Context):
    attempt_id: Uuid
    session_id: Uuid
    turn_index: Index
    text: Text
    input_tokens: Index
    output_tokens: Index
    duration_us: Duration


class AttemptResult(WireModel):
    defense_mode: DefenseMode
    pipeline_disposition: Disposition
    model_execution: Execution
    scoring: Scoring
    integrity: Integrity

    @model_validator(mode="after")
    def execution_truth(self):
        if self.model_execution == "UNKNOWN" and self.integrity != "INVALID":
            raise ValueError("Unknown execution is invalid")
        if self.model_execution == "NOT_EVALUATED" and self.scoring != "NOT_EVALUATED":
            raise ValueError("No model execution means no model score")
        if self.pipeline_disposition == "BLOCKED_BY_DEFENSE":
            expected = "NOT_EVALUATED" if self.defense_mode in ("INPUT", "FEATURES") else "EXECUTED"
            if self.model_execution != expected:
                raise ValueError("Block execution disagrees with defense mode")
        return self


class ExperimentCreated(Context):
    phase: Literal["CREATED"]


class PhaseReceipt(Context):
    phase: Phase
    receipt_id: Uuid


class SessionCreated(Context):
    session_id: Uuid


class UploadReceipt(Context):
    receipt_id: Uuid
    accepted_items: Annotated[int, Field(strict=True, ge=1, le=16)]


class EmbargoedView(WireModel):
    """No context/phase/count/timing fields: blue-human active projection is static."""
    status: Literal["EMBARGOED"]


class PayloadProvenance(WireModel):
    source_id: Opaque
    immutable_revision: Opaque
    source_sha256: Digest
    record_id: Opaque
    license_id: Opaque
    run_label: Literal["SYNTHETIC_MOCK", "REAL_PUBLIC", "AUTHORIZED_PRIVATE"]


class ResolvedPayload(WireModel):
    """Private broker/data boundary; never a participant response."""
    payload_ref: Uuid
    text: Text
    provenance: PayloadProvenance
