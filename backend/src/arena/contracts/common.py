"""Strict immutable shared types. Identifiers are wire strings, never coerced UUIDs."""

from datetime import datetime
import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints


MAX_INT = 2_147_483_647
SAFE_INT = 9_007_199_254_740_991
Epoch = Annotated[int, Field(strict=True, ge=1, le=MAX_INT)]
Index = Annotated[int, Field(strict=True, ge=0, le=MAX_INT)]
Count = Annotated[int, Field(strict=True, ge=1, le=MAX_INT)]
Duration = Annotated[int, Field(strict=True, ge=0, le=SAFE_INT)]


def exact_uuid(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("Expected canonical lowercase hyphenated UUID")
    return value


def utf8_text(value: str) -> str:
    if len(value.encode("utf-8", errors="strict")) > 65_536:
        raise ValueError("UTF-8 text exceeds byte limit")
    return value


def utc_time(value: str) -> str:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        raise ValueError("Expected UTC RFC3339 timestamp ending Z")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def as_tuple(value):
    if type(value) not in (list, tuple):
        raise ValueError("Expected array")
    return tuple(value)


Uuid = Annotated[str, AfterValidator(exact_uuid)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
Signature = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$", min_length=128, max_length=128)]
Opaque = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$", min_length=1, max_length=128)]
ClientKey = Annotated[str, StringConstraints(pattern=r"^[!-~]+$", min_length=1, max_length=128)]
Text = Annotated[str, AfterValidator(utf8_text)]
UtcTime = Annotated[str, AfterValidator(utc_time)]
Role = Literal["operator", "red", "blue-human", "blue-runtime", "broker", "target", "recorder", "witness", "auditor"]
Phase = Literal["CREATED", "SEALED", "READY", "RUNNING", "SCORED", "INVALID", "CLOSED", "RELEASED"]
InteractionMode = Literal["INTERACTIVE", "SEALED_BATCH"]
DefenseMode = Literal["INPUT", "FEATURES", "OUTPUT", "POST_HOC"]
Disposition = Literal["PENDING", "ALLOWED", "SANITIZED", "BLOCKED_BY_DEFENSE", "INFRASTRUCTURE_FAILED"]
Execution = Literal["NOT_EVALUATED", "EXECUTED", "UNKNOWN"]
Scoring = Literal["NOT_EVALUATED", "SCORED", "UNCERTAIN", "FAILED"]
Integrity = Literal["PENDING", "VALID_WITHIN_PROFILE", "INVALID"]
ErrorCode = Literal["INVALID_SCHEMA", "UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "WRONG_PHASE", "STALE_EPOCH", "VERSION_MISMATCH", "IDEMPOTENCY_CONFLICT", "BODY_TOO_LARGE", "RESOURCE_BUDGET_EXCEEDED", "AUDIT_UNAVAILABLE", "MODEL_UNAVAILABLE", "POLICY_NOT_READY", "DEADLINE_EXCEEDED"]


class WireModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True,
                              validate_default=True, hide_input_in_errors=True)


class Context(WireModel):
    domain_id: Uuid
    experiment_id: Uuid
    epoch: Epoch


class TurnContext(Context):
    session_id: Uuid
    turn_id: Uuid
    turn_index: Index


class Principal(WireModel):
    """Trusted transport result, never a public caller-supplied identity header."""
    subject_id: Opaque
    role: Role
    domain_id: Uuid
    expires_at: UtcTime


class ErrorResponse(WireModel):
    code: ErrorCode
    request_id: Uuid
