"""Offline teammate entry point. Commands do not start services or perform inference."""

import argparse
import json
from pathlib import Path
import sys

from arena.contracts.common import Context
from arena.contracts.crypto import (canonical_bytes, checkpoint_message, commitment,
                                    event_digest, verify)
from arena.contracts.evidence import Checkpoint, Event
from arena.contracts.jsonwire import ContractError, MAX_BODY_BYTES, load_wire
from arena.contracts.registry import SCHEMAS, schema_bundle


def check_vectors(path: Path) -> int:
    vectors = json.loads(path.read_text(encoding="utf-8"))
    if vectors.get("scope") != "SYNTHETIC_CONTRACT_TEST_ONLY":
        raise ContractError()
    event = Event.model_validate(vectors["event"])
    checkpoint = Checkpoint.model_validate(vectors["checkpoint"])
    checks = (
        canonical_bytes(event).decode("ascii") == vectors["event_canonical_ascii"],
        event_digest(event) == vectors["event_digest"],
        checkpoint_message(checkpoint).hex() == vectors["checkpoint_message_hex"],
        commitment(bytes.fromhex(vectors["content_hex"]), bytes.fromhex(vectors["commitment_nonce_hex"])) == vectors["commitment_digest"],
        verify(checkpoint_message(checkpoint), vectors["checkpoint_signature"], bytes.fromhex(vectors["test_public_key_hex"])),
        verify(b"", vectors["rfc8032_empty_signature"], bytes.fromhex(vectors["test_public_key_hex"])),
    )
    if not all(checks):
        raise ContractError("VERSION_MISMATCH")
    print(json.dumps({"result": "PASS", "checks": len(checks), "scope": "synthetic byte/signature interoperability only; not evidence authenticity or a valid safety finding"}))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("schemas", help="Export independent structural schema bundle")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--check", action="store_true", help="Check existing bytes without writing")
    vectors = commands.add_parser("check-vectors", help="Synthetic conformance, never a bundle verifier")
    vectors.add_argument("--path", type=Path, required=True)
    validate = commands.add_parser("validate", help="Validate one local JSON message, without echoing data")
    validate.add_argument("schema", choices=sorted(SCHEMAS))
    validate.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "schemas":
            output = json.dumps(schema_bundle(), sort_keys=True, ensure_ascii=True, indent=2) + "\n"
            if args.check:
                if args.output.read_bytes() != output.encode("utf-8"):
                    raise ContractError("VERSION_MISMATCH")
            else:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(output, encoding="utf-8", newline="\n")
            print(json.dumps({"result": "PASS", "schemas": len(SCHEMAS), "scope": "contract schema bundle"}))
            return 0
        if args.command == "check-vectors":
            return check_vectors(args.path)
        with args.path.open("rb") as stream:
            load_wire(SCHEMAS[args.schema], stream.read(MAX_BODY_BYTES + 1))
        print(json.dumps({"result": "PASS", "schema": args.schema, "scope": "schema only; no authorization/execution implied"}))
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        # Do not serialize ValidationError or attacker-controlled values to shared logs.
        print(json.dumps({"result": "FAIL", "code": "INVALID_SCHEMA_OR_CONTRACT"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
