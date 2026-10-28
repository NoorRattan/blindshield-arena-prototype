"""Comprehensive independent verifier matrix tests for MN07-04, T-007, and P-014.

Validates that the offline standalone verifier CLI (python -m arena.verifier.cli)
enforces fail-closed cryptographic, semantic, context, archive security,
and sealed transport boundaries across real bundle exports without broker dependencies.
"""

import asyncio
from contextlib import closing
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Tuple
from uuid import uuid4
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.common import Context
from arena.contracts.crypto import checkpoint_digest
from arena.integration.controller import ACTOR
from arena.ports import TargetNotDispatched
from arena.verifier.cli import main as cli_main

# Import integration test environment helpers
from test_n04 import environment as n04_environment, payload as n04_payload, turn as n04_turn
from test_n06_execution import environment as n06_environment, submit as n06_submit


def run_verifier_cli(argv: List[str]) -> Tuple[int, Dict[str, Any], Dict[str, Any]]:
    """Run verifier CLI capturing stdout and stderr JSON responses."""
    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = out_buf = StringIO()
    sys.stderr = err_buf = StringIO()
    try:
        exit_code = cli_main(argv)
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr

    out_str = out_buf.getvalue().strip()
    err_str = err_buf.getvalue().strip()

    out_json = json.loads(out_str) if out_str else {}
    err_json = json.loads(err_str) if err_str else {}
    return exit_code, out_json, err_json


def mutate_zip_bundle(
    source_zip: Path,
    target_zip: Path,
    mutator: Callable[[str, bytes], bytes | None],
) -> None:
    """Read source zip, apply mutator(filename, bytes) -> bytes or None to delete, write target zip."""
    with zipfile.ZipFile(source_zip, "r") as zin:
        with zipfile.ZipFile(target_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                new_data = mutator(item.filename, data)
                if new_data is not None:
                    zout.writestr(item, new_data)


@pytest.fixture(scope="module")
def valid_exported_bundle(tmp_path_factory) -> Dict[str, Any]:
    """Export an intact, authentic valid bundle with START receipt and turn receipts."""
    tmp_path = tmp_path_factory.mktemp("valid_bundle_dir")

    async def build():
        env = await n04_environment(tmp_path / "env")
        item = n04_payload("monu n07 test prompt")
        await n04_turn(env, item)
        closed = await env.controller.close(env.principals["operator"])
        env.controller.release(env.principals["operator"])
        bundle_path = tmp_path / "evidence_valid.zip"
        env.controller.export(env.principals["auditor"], bundle_path)

        manifest = env.start.witness_start_receipt.receipt.public_manifest_digest
        keys_path = tmp_path / "keys_valid.json"
        keys_path.write_text(
            json.dumps(env.controller.vault.private_replay_keys(closed.checkpoint.required_artifacts)),
            encoding="utf-8",
        )

        return {
            "bundle_path": bundle_path,
            "keys_path": keys_path,
            "rec_pub_hex": env.rec_pub.hex(),
            "wit_pub_hex": env.wit_pub.hex(),
            "domain_id": env.ctx.domain_id,
            "experiment_id": env.ctx.experiment_id,
            "epoch": str(env.ctx.epoch),
            "manifest_digest": manifest,
            "rec_key_id": "recorder",
            "wit_key_id": "witness",
            "defense_mode": "INPUT",
            "broker_actor": ACTOR,
            "tmp_path": tmp_path,
        }

    return asyncio.run(build())


@pytest.fixture(scope="module")
def authentic_invalid_exported_bundle(tmp_path_factory) -> Dict[str, Any]:
    """Export an authentic INVALID bundle produced when model dispatch fails."""
    tmp_path = tmp_path_factory.mktemp("invalid_bundle_dir")

    async def build():
        env = await n04_environment(tmp_path / "env")
        env.runtime.model.failure = TargetNotDispatched("simulated model target unavailable")
        item = n04_payload("failing turn prompt")
        try:
            await n04_turn(env, item)
        except TargetNotDispatched:
            pass
        await env.controller.close(env.principals["operator"])
        from test_n04 import verify_export
        verify_export(env, tmp_path, "INPUT", invalid_fixture=True)
        bundle_path = tmp_path / "evidence.zip"

        manifest = env.start.witness_start_receipt.receipt.public_manifest_digest
        return {
            "bundle_path": bundle_path,
            "rec_pub_hex": env.rec_pub.hex(),
            "wit_pub_hex": env.wit_pub.hex(),
            "domain_id": env.ctx.domain_id,
            "experiment_id": env.ctx.experiment_id,
            "epoch": str(env.ctx.epoch),
            "manifest_digest": manifest,
            "rec_key_id": "recorder",
            "wit_key_id": "witness",
            "defense_mode": "INPUT",
            "broker_actor": ACTOR,
            "tmp_path": tmp_path,
        }

    return asyncio.run(build())


@pytest.fixture(scope="module")
def sealed_transport_bundle(tmp_path_factory) -> Dict[str, Any]:
    """Export an intact bundle with N06 sealed transport plan and admission trust."""
    tmp_path = tmp_path_factory.mktemp("sealed_bundle_dir")

    async def build():
        env = await n06_environment(tmp_path / "env", sealed_transport=True)
        turn = n06_submit(env)
        assert await env.worker.run_once()
        env.clock.ns = 6_000_000_000
        env.queue.project(env.p["red"], env.ctx, env.session, turn["turn_id"])
        closed = await env.controller.close(env.p["operator"])
        env.controller.release(env.p["operator"])
        bundle_path = tmp_path / "evidence_sealed.zip"
        env.controller.export(env.p["auditor"], bundle_path)

        keys_path = tmp_path / "keys_sealed.json"
        keys_path.write_text(
            json.dumps(env.controller.vault.private_replay_keys(closed.checkpoint.required_artifacts)),
            encoding="utf-8",
        )

        with closing(env.store.connect()) as conn:
            manifest = conn.execute("SELECT public_commitment FROM experiments").fetchone()[0]

        trust = env.admission.trust
        return {
            "bundle_path": bundle_path,
            "keys_path": keys_path,
            "rec_pub_hex": env.controller.recorder_public_key.hex(),
            "wit_pub_hex": env.controller.witness_public_key.hex(),
            "domain_id": env.ctx.domain_id,
            "experiment_id": env.ctx.experiment_id,
            "epoch": str(env.ctx.epoch),
            "manifest_digest": manifest,
            "rec_key_id": "recorder",
            "wit_key_id": "witness",
            "defense_mode": "INPUT",
            "broker_actor": ACTOR,
            "trust": trust,
            "tmp_path": tmp_path,
        }

    return asyncio.run(build())


def build_cli_args(env: Dict[str, Any], bundle_path: Path | None = None) -> List[str]:
    """Helper to assemble standard verifier CLI argument list."""
    target = bundle_path or env["bundle_path"]
    return [
        "--bundle", str(target),
        "--recorder-key", env["rec_pub_hex"],
        "--witness-key", env["wit_pub_hex"],
        "--domain-id", env["domain_id"],
        "--experiment-id", env["experiment_id"],
        "--epoch", env["epoch"],
        "--manifest-digest", env["manifest_digest"],
        "--recorder-key-id", env["rec_key_id"],
        "--witness-key-id", env["wit_key_id"],
        "--defense-mode", env["defense_mode"],
        "--broker-actor", env["broker_actor"],
    ]


# ---------------------------------------------------------------------------
# Section 1: Baseline Verification and Refusal Without Start Proof
# ---------------------------------------------------------------------------

def test_verifier_baseline_valid_public_evidence(valid_exported_bundle):
    """Clean bundle with valid witness START and receipts passes with exit code 0."""
    args = build_cli_args(valid_exported_bundle)
    code, out, err = run_verifier_cli(args)
    assert code == 0
    assert out["status"] == "PASS_PUBLIC_EVIDENCE"
    assert out["diagnostics"]["witness_start_verified"] is True
    assert out["diagnostics"]["integrity"] == "VALID_WITHIN_PROFILE"
    assert out["diagnostics"]["scope"] == "N04_PUBLIC_EVIDENCE_ONLY"


def test_verifier_incomplete_without_start_receipt(valid_exported_bundle, tmp_path):
    """Removing witness_start.json and turn_receipts.jsonl results in exit code 4 (INCOMPLETE_START_PROOF)."""
    corrupt_zip = tmp_path / "missing_start.zip"

    def strip_start_metadata(filename: str, data: bytes) -> bytes | None:
        if filename in {"witness_start.json", "turn_receipts.jsonl"}:
            return None
        return data

    mutate_zip_bundle(valid_exported_bundle["bundle_path"], corrupt_zip, strip_start_metadata)
    args = build_cli_args(valid_exported_bundle, corrupt_zip)
    code, out, err = run_verifier_cli(args)
    assert code == 4
    assert out["status"] == "INCOMPLETE_START_PROOF"
    assert out["diagnostics"]["witness_start_verified"] is False
    assert out["diagnostics"]["integrity"] == "NOT_ESTABLISHED"


# ---------------------------------------------------------------------------
# Section 2: Authentic INVALID Run Reporting (Failure Preserved)
# ---------------------------------------------------------------------------

def test_verifier_authentic_invalid_run_preserves_failure(authentic_invalid_exported_bundle):
    """An authentic run with model dispatch failure verifies signatures but returns exit code 5 (AUTHENTIC_INVALID)."""
    args = build_cli_args(authentic_invalid_exported_bundle)
    code, out, err = run_verifier_cli(args)
    assert code == 5
    assert out["status"] == "AUTHENTIC_INVALID"
    assert out["diagnostics"]["integrity"] == "INVALID"
    assert out["diagnostics"]["witness_start_verified"] is True
    # Crucial invariant: never convert authentic failure into a passing safety finding
    assert out["exit_code"] == 5


# ---------------------------------------------------------------------------
# Section 3: Hash Chain and Event Mutation Matrix (Exit Code 1)
# ---------------------------------------------------------------------------

def test_verifier_rejects_tampered_event_duration(valid_exported_bundle, tmp_path):
    """Tampering with duration_us in events.jsonl breaks the event digest -> exit code 1."""
    target_zip = tmp_path / "tampered_duration.zip"

    def mutator(filename: str, data: bytes) -> bytes | None:
        if filename == "events.jsonl":
            lines = data.decode("utf-8").splitlines()
            obj = json.loads(lines[0])
            obj["duration_us"] = 777777
            lines[0] = json.dumps(obj)
            return ("\n".join(lines) + "\n").encode("utf-8")
        return data

    mutate_zip_bundle(valid_exported_bundle["bundle_path"], target_zip, mutator)
    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 1
    assert err["status"] == "FAIL"


def test_verifier_rejects_deleted_event_chain_truncation(valid_exported_bundle, tmp_path):
    """Deleting an event breaks sequence monotonicity and final_root link -> exit code 1."""
    target_zip = tmp_path / "truncated_events.zip"

    def mutator(filename: str, data: bytes) -> bytes | None:
        if filename == "events.jsonl":
            lines = data.decode("utf-8").splitlines()
            return ("\n".join(lines[:-1]) + "\n").encode("utf-8")
        return data

    mutate_zip_bundle(valid_exported_bundle["bundle_path"], target_zip, mutator)
    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 1


def test_verifier_rejects_reordered_events(valid_exported_bundle, tmp_path):
    """Reordering events in events.jsonl breaks sequence and digest chaining -> exit code 1."""
    target_zip = tmp_path / "reordered_events.zip"

    def mutator(filename: str, data: bytes) -> bytes | None:
        if filename == "events.jsonl":
            lines = data.decode("utf-8").splitlines()
            if len(lines) >= 2:
                lines[0], lines[1] = lines[1], lines[0]
            return ("\n".join(lines) + "\n").encode("utf-8")
        return data

    mutate_zip_bundle(valid_exported_bundle["bundle_path"], target_zip, mutator)
    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 1


# ---------------------------------------------------------------------------
# Section 4: Schema and Context Integrity (Exit Code 1 & 2)
# ---------------------------------------------------------------------------

def test_verifier_rejects_boolean_epoch_injection(valid_exported_bundle, tmp_path):
    """Boolean epoch injection in checkpoint.json violates strict integer epoch -> exit code 2."""
    target_zip = tmp_path / "bool_epoch.zip"

    def mutator(filename: str, data: bytes) -> bytes | None:
        if filename == "checkpoint.json":
            obj = json.loads(data.decode("utf-8"))
            obj["checkpoint"]["epoch"] = True
            return json.dumps(obj).encode("utf-8")
        return data

    mutate_zip_bundle(valid_exported_bundle["bundle_path"], target_zip, mutator)
    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 2
    assert "epoch must be strict integer" in err["error"]


def test_verifier_rejects_wrong_recorder_key(valid_exported_bundle):
    """Supplying a wrong pinned recorder key rejects checkpoint signature -> exit code 1."""
    args = build_cli_args(valid_exported_bundle)
    # Replace recorder key with random key
    idx = args.index("--recorder-key") + 1
    args[idx] = os.urandom(32).hex()
    code, out, err = run_verifier_cli(args)
    assert code == 1
    assert "Recorder signature verification failed" in err["error"] or "signature" in err["error"].lower()


def test_verifier_rejects_wrong_witness_key(valid_exported_bundle):
    """Supplying a wrong pinned witness key rejects witness_close signature -> exit code 1."""
    args = build_cli_args(valid_exported_bundle)
    idx = args.index("--witness-key") + 1
    args[idx] = os.urandom(32).hex()
    code, out, err = run_verifier_cli(args)
    assert code == 1


def test_verifier_rejects_mismatched_domain_id(valid_exported_bundle):
    """Supplying a mismatched domain UUID rejects context check -> exit code 1."""
    args = build_cli_args(valid_exported_bundle)
    idx = args.index("--domain-id") + 1
    args[idx] = str(uuid4())
    code, out, err = run_verifier_cli(args)
    assert code == 1
    assert "signature verification FAILED" in err["error"] or "context mismatch" in err["error"].lower()


def test_verifier_rejects_mismatched_manifest_digest(valid_exported_bundle):
    """Supplying a mismatched manifest digest rejects checkpoint check -> exit code 1."""
    args = build_cli_args(valid_exported_bundle)
    idx = args.index("--manifest-digest") + 1
    args[idx] = "0" * 64
    code, out, err = run_verifier_cli(args)
    assert code == 1
    assert "signature verification FAILED" in err["error"] or "context mismatch" in err["error"].lower()


# ---------------------------------------------------------------------------
# Section 5: Witness Close / Root Tampering (Exit Code 3)
# ---------------------------------------------------------------------------

def test_verifier_rejects_substituted_witness_close_final_root(valid_exported_bundle, tmp_path):
    """Altering final_root in witness_close.json triggers rollback/conflict detection -> exit code 3."""
    target_zip = tmp_path / "bad_root.zip"

    def mutator(filename: str, data: bytes) -> bytes | None:
        if filename == "witness_close.json":
            obj = json.loads(data.decode("utf-8"))
            obj["receipt"]["final_root"] = "0" * 64
            return json.dumps(obj).encode("utf-8")
        return data

    mutate_zip_bundle(valid_exported_bundle["bundle_path"], target_zip, mutator)
    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 3
    assert "Witness conflict" in err["error"] and "final_root mismatch" in err["error"]


def test_verifier_rejects_substituted_witness_close_checkpoint_digest(valid_exported_bundle, tmp_path):
    """Altering checkpoint_digest in witness_close.json triggers conflict -> exit code 3."""
    target_zip = tmp_path / "bad_cp_digest.zip"

    def mutator(filename: str, data: bytes) -> bytes | None:
        if filename == "witness_close.json":
            obj = json.loads(data.decode("utf-8"))
            obj["receipt"]["checkpoint_digest"] = "1" * 64
            return json.dumps(obj).encode("utf-8")
        return data

    mutate_zip_bundle(valid_exported_bundle["bundle_path"], target_zip, mutator)
    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 3
    assert "Witness conflict" in err["error"] and "checkpoint_digest" in err["error"]


# ---------------------------------------------------------------------------
# Section 6: Artifact Ciphertext Integrity (Exit Code 1)
# ---------------------------------------------------------------------------

def test_verifier_rejects_corrupted_ciphertext_bytes(valid_exported_bundle, tmp_path):
    """Modifying bytes of an encrypted artifact fails SHA-256 integrity -> exit code 1."""
    target_zip = tmp_path / "corrupt_ciphertext.zip"

    def mutator(filename: str, data: bytes) -> bytes | None:
        if filename.startswith("artifacts/") and filename.endswith(".bin"):
            return data + b"\x00"
        return data

    mutate_zip_bundle(valid_exported_bundle["bundle_path"], target_zip, mutator)
    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 1
    assert "checksum tampering detected" in err["error"].lower() or "hash mismatch" in err["error"].lower()


def test_verifier_rejects_missing_required_ciphertext(valid_exported_bundle, tmp_path):
    """Removing a required ciphertext file fails completeness check -> exit code 1."""
    target_zip = tmp_path / "missing_ciphertext.zip"
    first_removed = False

    def mutator(filename: str, data: bytes) -> bytes | None:
        nonlocal first_removed
        if filename.startswith("artifacts/") and filename.endswith(".bin") and not first_removed:
            first_removed = True
            return None
        return data

    mutate_zip_bundle(valid_exported_bundle["bundle_path"], target_zip, mutator)
    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 1
    assert "Artifact file missing" in err["error"] or "missing" in err["error"].lower()


def test_verifier_rejects_unreferenced_extra_ciphertext(valid_exported_bundle, tmp_path):
    """Adding an unreferenced file into artifacts/ fails closed -> exit code 1."""
    target_zip = tmp_path / "extra_ciphertext.zip"
    with zipfile.ZipFile(valid_exported_bundle["bundle_path"], "r") as zin:
        with zipfile.ZipFile(target_zip, "w") as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            zout.writestr("artifacts/unreferenced_extra.bin", b"injected attack bytes")

    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 1
    assert "unexpected entries" in err["error"].lower() or "artifacts" in err["error"].lower()


# ---------------------------------------------------------------------------
# Section 7: Archive Security Boundaries
# ---------------------------------------------------------------------------

def test_verifier_rejects_directory_traversal_in_archive(valid_exported_bundle, tmp_path):
    """Archive with path traversal '../escape.bin' is rejected by safe extraction -> exit code 1."""
    target_zip = tmp_path / "traversal.zip"
    with zipfile.ZipFile(valid_exported_bundle["bundle_path"], "r") as zin:
        with zipfile.ZipFile(target_zip, "w") as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            zout.writestr("../escape.bin", b"evil traversal payload")

    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 1
    assert "unsafe" in err["error"].lower() or "archive entry" in err["error"].lower()


@pytest.mark.filterwarnings("ignore:Duplicate name:UserWarning")
def test_verifier_rejects_duplicate_archive_entries(valid_exported_bundle, tmp_path):
    """Archive with duplicate entry names is rejected -> exit code 1."""
    target_zip = tmp_path / "duplicate_entries.zip"
    with zipfile.ZipFile(target_zip, "w") as zout:
        with zipfile.ZipFile(valid_exported_bundle["bundle_path"], "r") as zin:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
        # Write duplicate entry
        zout.writestr("checkpoint.json", b"{}")

    code, out, err = run_verifier_cli(build_cli_args(valid_exported_bundle, target_zip))
    assert code == 1
    assert "ArchiveSecurityError" in err["error"] or "duplicate" in err["error"].lower()


# ---------------------------------------------------------------------------
# Section 8: Private Replay and Sealed Transport Profile Matrix
# ---------------------------------------------------------------------------

def test_verifier_sealed_transport_incomplete_without_keys(sealed_transport_bundle):
    """--require-transport-profile without keys JSON returns exit code 4 (INCOMPLETE_TRANSPORT_TRUST)."""
    args = build_cli_args(sealed_transport_bundle) + ["--require-transport-profile"]
    code, out, err = run_verifier_cli(args)
    assert code == 4
    assert out["status"] == "INCOMPLETE_TRANSPORT_TRUST"
    assert out["diagnostics"]["transport_profile_verified"] is False


def test_verifier_sealed_transport_incomplete_without_transport_pins(sealed_transport_bundle):
    """Providing replay keys without transport profile pins still reports incomplete transport trust (exit code 4)."""
    args = build_cli_args(sealed_transport_bundle) + [
        "--keys-json", str(sealed_transport_bundle["keys_path"]),
    ]
    code, out, err = run_verifier_cli(args)
    assert code == 4
    assert not out["diagnostics"]["transport_profile_verified"]


def test_verifier_sealed_transport_partial_pins_rejected(sealed_transport_bundle):
    """Providing only 2 of 4 transport pins triggers ALL_TRANSPORT_TRUST_FIELDS_REQUIRED -> exit code 2."""
    trust = sealed_transport_bundle["trust"]
    partial_pins = [
        "--feedback-policy-key", trust.feedback_public_key.hex(),
        "--feedback-policy-key-id", trust.feedback_key_id,
    ]
    args = build_cli_args(sealed_transport_bundle) + partial_pins
    code, out, err = run_verifier_cli(args)
    assert code == 2
    assert "ALL_TRANSPORT_TRUST_FIELDS_REQUIRED" in err["error"]


def test_verifier_sealed_transport_full_pass(sealed_transport_bundle):
    """Full N06 sealed profile verification with keys and all 4 pinned keys returns exit code 0."""
    trust = sealed_transport_bundle["trust"]
    pins = [
        "--feedback-policy-key", trust.feedback_public_key.hex(),
        "--feedback-policy-key-id", trust.feedback_key_id,
        "--transport-profile-key", trust.transport_public_key.hex(),
        "--transport-profile-key-id", trust.transport_key_id,
    ]
    args = build_cli_args(sealed_transport_bundle) + [
        "--keys-json", str(sealed_transport_bundle["keys_path"]),
        "--require-transport-profile",
    ] + pins
    code, out, err = run_verifier_cli(args)
    assert code == 0
    assert out["diagnostics"]["transport_profile_verified"] is True
    assert out["diagnostics"]["turn_openings_verified"] == 1
    assert out["diagnostics"]["scope"] == "N06_SEALED_TRANSPORT_AND_PRIVATE_OPENINGS"
    # Essential timing claim limitation: timing application is NOT attested by offline verifier alone
    assert out["diagnostics"]["transport_timing_application_attested"] is False


def test_verifier_sealed_transport_tampered_key_rejected(sealed_transport_bundle):
    """Supplying a wrong transport public key rejects sealed profile verification -> exit code 1."""
    trust = sealed_transport_bundle["trust"]
    wrong_pins = [
        "--feedback-policy-key", trust.feedback_public_key.hex(),
        "--feedback-policy-key-id", trust.feedback_key_id,
        "--transport-profile-key", os.urandom(32).hex(),
        "--transport-profile-key-id", trust.transport_key_id,
    ]
    args = build_cli_args(sealed_transport_bundle) + [
        "--keys-json", str(sealed_transport_bundle["keys_path"]),
        "--require-transport-profile",
    ] + wrong_pins
    code, out, err = run_verifier_cli(args)
    assert code == 1
    assert "rejected" in err["error"].lower()


def test_verifier_missing_keys_file_rejected(sealed_transport_bundle, tmp_path):
    """Pointing --keys-json to a missing file fails with exit code 2."""
    missing_keys = tmp_path / "nonexistent_keys.json"
    args = build_cli_args(sealed_transport_bundle) + [
        "--keys-json", str(missing_keys),
    ]
    code, out, err = run_verifier_cli(args)
    assert code == 2
    assert "Requested replay key file is missing" in err["error"]


def test_verifier_incomplete_artifact_keys_rejected(sealed_transport_bundle, tmp_path):
    """A keys-json dictionary missing required artifact keys fails with exit code 2."""
    incomplete_keys_path = tmp_path / "incomplete_keys.json"
    incomplete_keys_path.write_text(json.dumps({}), encoding="utf-8")
    args = build_cli_args(sealed_transport_bundle) + [
        "--keys-json", str(incomplete_keys_path),
    ]
    code, out, err = run_verifier_cli(args)
    assert code == 2
    assert "Replay keys must cover exactly the required artifacts" in err["error"]
