"""Pure transition checks, not a controller, preflight implementation or authorization."""

from .common import Phase, WireModel
from .jsonwire import ContractError


class GateFacts(WireModel):
    """Trusted controller derives facts from verified receipts, never public JSON."""
    seal_admission_verified: bool = False
    runtime_profile_verified: bool = False
    model_artifacts_locked: bool = False
    dataset_admitted: bool = False
    fresh_lane_verified: bool = False
    witness_start_acknowledged: bool = False
    dispatch_intent_durable: bool = False
    admissions_closed: bool = False
    all_turns_settled: bool = False
    terminal_evidence_durable: bool = False
    release_policy_authorized: bool = False


def validate_transition(current: Phase, requested: Phase, facts: GateFacts) -> None:
    if current not in ("CREATED", "SEALED", "READY", "RUNNING", "SCORED", "INVALID", "CLOSED", "RELEASED"):
        raise ContractError("WRONG_PHASE")
    if requested == "INVALID" and current not in ("INVALID", "CLOSED", "RELEASED"):
        return
    required = {
        ("CREATED", "SEALED"): ("seal_admission_verified",),
        ("SEALED", "READY"): ("runtime_profile_verified", "model_artifacts_locked", "dataset_admitted", "fresh_lane_verified"),
        ("READY", "RUNNING"): ("runtime_profile_verified", "model_artifacts_locked", "dataset_admitted", "fresh_lane_verified", "witness_start_acknowledged", "dispatch_intent_durable"),
        ("RUNNING", "SCORED"): ("admissions_closed", "all_turns_settled"),
        ("SCORED", "CLOSED"): ("terminal_evidence_durable",),
        ("INVALID", "CLOSED"): ("terminal_evidence_durable",),
        ("CLOSED", "RELEASED"): ("terminal_evidence_durable", "release_policy_authorized"),
    }.get((current, requested))
    if required is None:
        raise ContractError("WRONG_PHASE")
    if not all(getattr(facts, name) for name in required):
        raise ContractError("POLICY_NOT_READY")
