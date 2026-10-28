"""Trusted operator configuration, never participant-provided runtime settings."""

from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, model_validator

from arena.contracts.api import CreateExperiment
from arena.contracts.common import Digest, Opaque, Uuid, WireModel, as_tuple


class Profile(WireModel):
    domain_id: Uuid
    request: CreateExperiment
    red_subject_id: Opaque
    blue_subject_id: Opaque
    auditor_subject_ids: Annotated[tuple[Opaque, ...], BeforeValidator(as_tuple)]
    query_budget: Annotated[int, Field(strict=True, ge=1, le=500)] = 500
    session_limit: Annotated[int, Field(strict=True, ge=1, le=3)] = 3
    domain_queue_limit: Annotated[int, Field(strict=True, ge=1, le=4)] = 4
    execution_lock_sha256: Digest | None = None
    run_label: Literal["SYNTHETIC_MOCK", "REAL_PUBLIC"] = "SYNTHETIC_MOCK"


class BrokerConfig(WireModel):
    schema_version: Literal["arena-broker-config.v1"] = "arena-broker-config.v1"
    profiles: Annotated[
        tuple[Profile, ...], BeforeValidator(as_tuple), Field(min_length=1)
    ]

    @model_validator(mode="after")
    def unique_profiles(self):
        keys = [(p.domain_id, p.request.profile_id) for p in self.profiles]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate registered profile")
        return self
