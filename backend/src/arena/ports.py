"""Monu implements these async Python integration ports; no network/auth/durability implied."""

from typing import Protocol

from .contracts.api import (
    DefenseDecision,
    DefenseRequest,
    ResolvedPayload,
    TargetRequest,
    TargetResponse,
)
from .contracts.common import Context, Opaque, Uuid
from .contracts.evidence import (
    Event,
    EventProposal,
    SignedCheckpoint,
    SignedTurnReceipt,
    SignedWitnessClose,
    SignedWitnessStart,
    TurnReceipt,
    WitnessClose,
    WitnessStart,
)


class DependencyUnavailable(RuntimeError):
    """Missing authority or adapter fails closed; never a synthetic success receipt."""


class TargetNotDispatched(DependencyUnavailable):
    """Pinned adapter rejected work before calling the generation endpoint."""


class ModelAdapter(Protocol):
    async def infer(self, request: TargetRequest) -> TargetResponse: ...
    async def reset(self, session_id: Uuid) -> None: ...


class DefenseAdapter(Protocol):
    async def evaluate(self, request: DefenseRequest) -> DefenseDecision: ...


class PayloadStore(Protocol):
    async def resolve(self, payload_ref: Uuid) -> ResolvedPayload: ...


class Recorder(Protocol):
    async def append(
        self, proposal: EventProposal, authenticated_actor: Opaque
    ) -> Event:
        """Return only after durable commit; actor comes from trusted transport."""
        ...

    async def authorize_turn(self, receipt: TurnReceipt) -> SignedTurnReceipt: ...
    async def close(self, context: Context) -> SignedCheckpoint: ...


class Witness(Protocol):
    async def reserve_start(self, receipt: WitnessStart) -> SignedWitnessStart:
        """Durable anti-regression reservation; conflicting identity fails."""
        ...

    async def close(self, receipt: WitnessClose) -> SignedWitnessClose:
        """First close wins; identical retry returns original; conflicting close fails."""
        ...


class N04Recorder(Recorder, Protocol):
    """Additional trusted local integration operations; n02.1 wire bytes unchanged.

    Provisioning and authenticated actors are supplied by the trusted controller,
    never participant JSON. See docs/N04-INTEGRATION.md for authority/crash rules.
    """

    async def append_once(
        self, proposal: EventProposal, authenticated_actor: Opaque, operation_id: Uuid
    ) -> Event: ...
    async def authorize_bound_turn(
        self, receipt: TurnReceipt, authenticated_actor: Opaque, input_ref, response_ref
    ) -> SignedTurnReceipt: ...
    def authorize_start(
        self, receipt: WitnessStart, authenticated_actor: Opaque
    ) -> str: ...

    def authorize_analysis(self, receipt, authenticated_actor: Opaque):
        """Separately signed, checkpoint-linked post-release observation; no event append."""
        ...


class AuthenticatedWitness(Protocol):
    async def reserve_start_authenticated(
        self, receipt: WitnessStart, recorder_signature: str
    ) -> SignedWitnessStart: ...
    async def close_checkpoint(
        self, signed: SignedCheckpoint
    ) -> SignedWitnessClose: ...
    def watermark(self, context: Context) -> tuple[int, int | None]: ...


class UnavailableModel:
    async def infer(self, request: TargetRequest) -> TargetResponse:
        raise DependencyUnavailable("MODEL_UNAVAILABLE")

    async def reset(self, session_id: Uuid) -> None:
        raise DependencyUnavailable("MODEL_UNAVAILABLE")


def validate_target_binding(request: TargetRequest, response: TargetResponse) -> None:
    """Run after schema validation before associating an untrusted response with work."""
    names = (
        "domain_id",
        "experiment_id",
        "epoch",
        "attempt_id",
        "session_id",
        "turn_index",
    )
    if any(getattr(request, name) != getattr(response, name) for name in names):
        raise DependencyUnavailable("TARGET_CONTEXT_MISMATCH")
    if response.output_tokens > request.max_output_tokens:
        raise DependencyUnavailable("TARGET_OUTPUT_BUDGET_EXCEEDED")
