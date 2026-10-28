"""Prepare a local worker pilot policy or a six-sample estimate; no public admission."""

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire
from arena.execution.pilot import candidate_from_pilot
from arena.execution.policy import FeedbackPolicy, SignedPolicy, disclosure_id, policy_message
from arena.integration.cli import secret_file
from arena.integration.lanes import LaneAdmission
from arena.integration.runtime import runtime_source_hashes


ROOT = Path(__file__).resolve().parents[1]
KEY_ID = "n06-local-policy"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-lock", required=True, type=Path)
    parser.add_argument("--pilot-summary", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / "artifacts"):
        raise ValueError("NEW_PRIVATE_POLICY_DIRECTORY_REQUIRED")
    admission = load_wire(LaneAdmission, args.execution_lock.read_bytes())
    if admission.runtime_source_sha256 != runtime_source_hashes():
        raise ValueError("PILOT_POLICY_CURRENT_SOURCE_REQUIRED")
    metadata = {"schema_version": "arena-n06-local-policy-preparation.v1", "public_admission": False,
                "execution_lock_sha256": sha256(args.execution_lock.read_bytes()),
                "scope": "UNMEASURED_BOOTSTRAP_FOR_LOCAL_PILOT_ONLY"}
    policy = FeedbackPolicy(policy_id="n06-local-bootstrap.v1", run_label="REAL_PUBLIC", execution_deadline_ms=30000,
                            release_floor_ms=31000, body_bytes=16384)
    if args.pilot_summary:
        path = args.pilot_summary.resolve()
        if not path.is_relative_to(ROOT / "artifacts"):
            raise ValueError("TRUSTED_LOCAL_PILOT_SUMMARY_REQUIRED")
        raw = path.read_bytes()
        pilot = json.loads(raw)
        if (pilot["schema_version"] != "arena-n06-worker-pilot.v1" or pilot["execution_lock_sha256"] != metadata["execution_lock_sha256"]
            or pilot["run_label"] != "REAL_PUBLIC" or pilot["defense_mode"] != "INPUT" or pilot["lane_count"] != 3
            or pilot["turns"] != 6 or pilot["charged_queries"] != 6 or pilot["authorized_published_jobs"] != 6
            or pilot["verifier_exit_code"] != 0 or pilot["n06_worker_real_model"] is not True or pilot["worker_drained"] is not True
            or pilot["policy_signature_verified"] is not True or pilot["public_execution_available"] is not False):
            raise ValueError("SUCCESSFUL_EXACT_BUILD_LOCAL_PILOT_REQUIRED")
        policy, estimate = candidate_from_pilot(pilot["worker_samples"], FeedbackPolicy.model_validate(pilot["feedback_policy"]))
        metadata.update(estimate, pilot_summary_sha256=sha256(raw), workload_id="n06-jbb6-input-three-lanes.v1")
    key = Ed25519PrivateKey.generate()
    signed = SignedPolicy(policy=policy, signer_key_id=KEY_ID, signature=key.sign(policy_message(policy, KEY_ID)).hex())
    metadata.update(policy=policy.model_dump(), policy_disclosure_id=disclosure_id(signed), signer_key_id=KEY_ID)
    output.mkdir(parents=True)
    secret_file(output / "policy.key", key.private_bytes_raw())
    (output / "policy-public.hex").write_text(key.public_key().public_bytes_raw().hex() + "\n", encoding="ascii")
    (output / "policy.json").write_text(signed.model_dump_json(indent=2) + "\n", encoding="ascii")
    (output / "preparation.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="ascii")
    print(json.dumps({"result": "PREPARED_LOCAL_COMPONENT_POLICY_ONLY", "scope": metadata["scope"],
                      "execution_deadline_ms": policy.execution_deadline_ms, "release_floor_ms": policy.release_floor_ms,
                      "body_bytes": policy.body_bytes, "public_admission": False}))


if __name__ == "__main__":
    main()
