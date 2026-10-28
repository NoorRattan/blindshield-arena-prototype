"""Synthetic import/contract exercise for Monu. No model call or durable receipt."""

import json
from pathlib import Path

from arena.contracts.api import TargetRequest, TargetResponse
from arena.contracts.evidence import ArtifactAAD
from arena.contracts.crypto import decrypt_artifact, encrypt_artifact
from arena.contracts.jsonwire import load_wire
from arena.ports import validate_target_binding


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    request = load_wire(TargetRequest, (root / "fixtures/arena-v2/target-request.json").read_bytes())
    fields = request.model_dump(mode="json", exclude={"max_output_tokens"})
    response = TargetResponse(**(fields | {"text": "synthetic response", "input_tokens": 2,
                                           "output_tokens": 2, "duration_us": 1}))
    validate_target_binding(request, response)
    aad = ArtifactAAD(domain_id=request.domain_id, experiment_id=request.experiment_id,
                      epoch=request.epoch, schema_version="arena.v2",
                      artifact_id=request.attempt_id, classification="PRIVATE_PAYLOAD")
    key, blob = encrypt_artifact(request.text.encode("utf-8"), aad)
    assert decrypt_artifact(blob, key, aad) == request.text.encode("utf-8")
    print(json.dumps({"result": "PASS", "scope": "synthetic contracts/encryption only",
                      "real_inference": False, "durable_receipt": False}))


if __name__ == "__main__":
    main()
