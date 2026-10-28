"""Signed component-only release policy; no fabricated pilot/calibration authority."""

import json
from arena.contracts.transport_profile import (
    FeedbackPolicy, SignedPolicy, disclosure_id, policy_message,
)
from arena.contracts.crypto import verify
from arena.ports import DependencyUnavailable


def validate_policy(signed, public_key, key_id):
    signed = SignedPolicy.model_validate(signed.model_dump())
    if signed.signer_key_id != key_id or not verify(policy_message(signed.policy, key_id), signed.signature, public_key):
        raise DependencyUnavailable("FEEDBACK_POLICY_SIGNATURE_REJECTED")
    return signed.policy


def padded_json(value, size):
    """ASCII JSON byte bucket, without truncating text or changing signed content."""
    value = {**value, "padding": ""}
    encode = lambda obj: json.dumps(obj, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    raw = encode(value)
    if len(raw) > size:
        raise DependencyUnavailable("FEEDBACK_BUCKET_EXCEEDED")
    value["padding"] = " " * (size - len(raw))
    result = encode(value)
    if len(result) != size:
        raise DependencyUnavailable("FEEDBACK_BUCKET_INVALID")
    return result
