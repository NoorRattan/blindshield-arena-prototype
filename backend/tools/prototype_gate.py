"""Issue a static-calibration or measured-service grant using external local trust."""
import argparse
import json
from pathlib import Path

from arena.model_runtime import BACKEND
from arena.prototype.admission import issue, key_public, service_check, static_check


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("stage", choices=("static", "service"))
    p.add_argument("--profile", required=True, type=Path)
    p.add_argument("--model", type=Path)
    p.add_argument("--authority-key", required=True, type=Path)
    p.add_argument("--authority-public-key", required=True, type=Path)
    p.add_argument("--static-grant", type=Path)
    p.add_argument("--calibration", type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    output = a.output.resolve()
    if not output.is_relative_to(BACKEND / "artifacts") or output.exists():
        raise ValueError("NEW_IGNORED_GRANT_OUTPUT_REQUIRED")
    public = key_public(a.authority_public_key)
    if a.stage == "static":
        if a.model is None:
            p.error("static requires --model")
        observed = static_check(a.profile, a.model, public)
        parent = None
    else:
        if a.calibration is None or a.static_grant is None:
            p.error("service requires --static-grant and --calibration")
        observed = service_check(a.profile, a.calibration, a.static_grant, public)
        from arena.model_runtime import file_digest
        parent = file_digest(a.calibration)
    signed = issue("STATIC" if a.stage == "static" else "SERVICE", a.profile, a.authority_key, observed, parent=parent)
    output.write_bytes((signed.model_dump_json(indent=2) + "\n").encode())
    print(json.dumps({"result": observed["result"], "stage": signed.receipt.stage, "full_t_p_acceptance": False}))


if __name__ == "__main__":
    main()
