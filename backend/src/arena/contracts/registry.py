"""Explicit exported boundary registry. JSON Schema is accompanied by semantic validators."""

from . import api, common, evidence, lifecycle


SCHEMAS = {cls.__name__: cls for cls in (
    common.Context, common.TurnContext, common.Principal, common.ErrorResponse,
    api.CreateExperiment, api.EpochRequest, api.AttackBatch, api.TurnSubmission,
    api.IdempotencyScope, api.DefenseDecision, api.TargetRequest, api.TargetResponse,
    api.AttemptResult, api.ExperimentCreated, api.PhaseReceipt, api.SessionCreated,
    api.UploadReceipt, api.EmbargoedView, api.ResolvedPayload, api.PayloadProvenance,
    evidence.ArtifactRef, evidence.EventProposal, evidence.Event, evidence.Checkpoint,
    evidence.SignedCheckpoint, evidence.WitnessStart, evidence.WitnessClose,
    evidence.SignedWitnessStart, evidence.SignedWitnessClose, evidence.TurnReceipt,
    evidence.SignedTurnReceipt, evidence.TurnFeedback, evidence.ArtifactAAD,
    evidence.SealResponse, evidence.StartResponse, evidence.CloseResponse, evidence.ReleaseResponse,
    lifecycle.GateFacts,
)}
SCHEMAS["DefenseRequest"] = api.DEFENSE_REQUEST


def schema_bundle() -> dict:
    return {
        "protocol": "arena.v2", "contract_revision": "n02.1",
        "note": "JSON Schema covers structure; Python validators enforce cross-field semantics. No HTTP server/authentication/durability implied.",
        "schemas": {name: (schema.json_schema() if name == "DefenseRequest" else schema.model_json_schema()) for name, schema in sorted(SCHEMAS.items())},
    }
