"""Offline sealed transport consumer. Never imports broker/execution/runtime code."""

import json

from arena.contracts.common import Context
from arena.contracts.transport_profile import SealedTransportPlan, TransportTrust, plan_digest


def transport_from_openings(plaintexts):
    manifests = [value["sealed"]["manifest"] for raw in plaintexts.values()
                 for value in [json.loads(raw)] if "sealed" in value and "execution_lock" in value]
    if len(manifests) != 1:
        raise ValueError("EXACTLY_ONE_SEALED_MANIFEST_REQUIRED")
    return manifests[0]


def verify_transport_opening(plaintexts, expected_context, trust: TransportTrust):
    manifest = transport_from_openings(plaintexts)
    if Context.model_validate(manifest["context"]) != expected_context:
        raise ValueError("SEALED_TRANSPORT_EXPECTED_CONTEXT_REJECTED")
    plan = SealedTransportPlan.model_validate(manifest["n06_transport"])
    profile = manifest["profile"]
    trust.validate(plan, expected_context, profile["execution_lock_sha256"],
                   profile["request"]["disclosure_profile_id"], profile["run_label"])
    return {"transport_profile_verified": True, "transport_plan_sha256": plan_digest(plan),
            "transport_scope": plan.transport.profile.scope, "transport_timing_application_attested": False,
            "transport_public_admission": False}
