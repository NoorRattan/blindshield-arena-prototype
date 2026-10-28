"""Separate local transport contract. No broker, runtime or schema-registry imports."""

from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .common import Context, Digest, Epoch, Opaque, Signature, WireModel
from .crypto import canonical_bytes, sha256, verify


class FeedbackPolicy(WireModel):
    schema_version: Literal["arena-n06-feedback-policy.v1"] = "arena-n06-feedback-policy.v1"
    policy_id: Opaque
    run_label: Literal["SYNTHETIC_MOCK", "REAL_PUBLIC"]
    execution_deadline_ms: Annotated[int, Field(strict=True, ge=1, le=120000)]
    release_floor_ms: Annotated[int, Field(strict=True, ge=1, le=120000)]
    body_bytes: Annotated[int, Field(strict=True, ge=2048, le=131072)]
    scope: Literal["N06_COMPONENT_ONLY_UNCALIBRATED"] = "N06_COMPONENT_ONLY_UNCALIBRATED"

    @model_validator(mode="after")
    def common_window(self):
        if self.release_floor_ms < self.execution_deadline_ms:
            raise ValueError("Release floor must cover the entire execution deadline")
        return self


class SignedPolicy(WireModel):
    policy: FeedbackPolicy
    signer_key_id: Opaque
    signature: Signature


class LabProfile(Context):
    schema_version: Literal["arena-n06-local-mtls-profile.v1"] = "arena-n06-local-mtls-profile.v1"
    scope: Literal["LOCAL_MTLS_MEASUREMENT_POC"] = "LOCAL_MTLS_MEASUREMENT_POC"
    execution_lock_sha256: Digest
    feedback_policy_sha256: Digest
    admission_window_ms: Annotated[int, Field(strict=True, ge=100, le=2000)] = 1000
    bind_address: Literal["127.0.0.1"] = "127.0.0.1"
    max_workers: Literal[3] = 3


class SignedLabProfile(WireModel):
    profile: LabProfile
    signer_key_id: Opaque
    signature: Signature


def policy_message(policy, key_id):
    return b"arena.n06/feedback-policy\x00" + canonical_bytes({"policy": policy.model_dump(), "signer_key_id": key_id})


def lab_message(profile, key_id):
    return b"arena.n06/local-mtls-profile\x00" + canonical_bytes({"profile": profile.model_dump(), "signer_key_id": key_id})


def disclosure_id(signed):
    return "feedback-" + sha256(policy_message(signed.policy, signed.signer_key_id))


class SealedTransportPlan(WireModel):
    schema_version: Literal["arena-n06-sealed-transport.v1"] = "arena-n06-sealed-transport.v1"
    feedback: SignedPolicy
    transport: SignedLabProfile


class SealIntent(WireModel):
    """Trusted internal idempotency intent, never a public EpochRequest extension."""
    epoch: Epoch
    transport_plan_sha256: Digest


def plan_digest(plan):
    return sha256(canonical_bytes(plan.model_dump()))


@dataclass(frozen=True)
class TransportTrust:
    feedback_public_key: bytes
    feedback_key_id: str
    transport_public_key: bytes
    transport_key_id: str

    def validate(self, plan, ctx, execution_lock_sha256, expected_disclosure, run_label):
        plan = SealedTransportPlan.model_validate(plan.model_dump())
        feedback, transport = plan.feedback, plan.transport
        if (feedback.signer_key_id != self.feedback_key_id or transport.signer_key_id != self.transport_key_id
            or not verify(policy_message(feedback.policy, self.feedback_key_id), feedback.signature, self.feedback_public_key)
            or not verify(lab_message(transport.profile, self.transport_key_id), transport.signature, self.transport_public_key)):
            raise ValueError("TRANSPORT_PLAN_INDEPENDENT_SIGNATURE_REJECTED")
        profile = transport.profile
        if (any(getattr(profile, field) != getattr(ctx, field) for field in ctx.model_dump())
            or profile.execution_lock_sha256 != execution_lock_sha256
            or profile.feedback_policy_sha256 != sha256(feedback.policy.model_dump_json().encode())
            or disclosure_id(feedback) != expected_disclosure or feedback.policy.run_label != run_label
            or profile.admission_window_ms >= feedback.policy.execution_deadline_ms):
            raise ValueError("TRANSPORT_PLAN_CONTEXT_OR_POLICY_REJECTED")
        return plan


@dataclass(frozen=True)
class TransportAdmission:
    """Trusted operator input. Public keys/IDs are external expectations, not plan fields."""
    plan: SealedTransportPlan
    trust: TransportTrust

    def manifest_value(self, ctx, profile):
        self.trust.validate(self.plan, ctx, profile.execution_lock_sha256,
                            profile.request.disclosure_profile_id, profile.run_label)
        return self.plan.model_dump()

    def check_manifest(self, manifest, expected_context):
        plan = SealedTransportPlan.model_validate(manifest["n06_transport"])
        if plan != self.plan or Context.model_validate(manifest["context"]) != expected_context:
            raise ValueError("SEALED_TRANSPORT_ATTACHMENT_MISMATCH")
        profile = manifest["profile"]
        self.trust.validate(plan, expected_context, profile["execution_lock_sha256"],
                            profile["request"]["disclosure_profile_id"], profile["run_label"])
        return plan
