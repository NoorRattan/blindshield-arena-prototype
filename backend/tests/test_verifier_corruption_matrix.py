"""Comprehensive corruption matrix test for T-007 and P-014 offline verifier."""

import asyncio
import hashlib
import json
from pathlib import Path
from uuid import uuid4
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.common import Context
from arena.contracts.crypto import checkpoint_digest
from arena.contracts.evidence import (
    ArtifactRef,
    EventProposal,
    WitnessClose,
    WitnessStart,
)
from arena.recorder.recorder import DurableRecorder
from arena.verifier.bundle import export_experiment_bundle
from arena.verifier.cli import main as verifier_main
from arena.witness.authority import SQLiteWitnessAuthority


@pytest.fixture
def valid_bundle_env(tmp_path: Path):
    rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
    rec_pub_bytes = (
        Ed25519PrivateKey.from_private_bytes(rec_priv).public_key().public_bytes_raw()
    )
    wit_pub_bytes = (
        Ed25519PrivateKey.from_private_bytes(wit_priv).public_key().public_bytes_raw()
    )

    domain_id = str(uuid4())
    experiment_id = str(uuid4())
    epoch = 1
    manifest_digest = hashlib.sha256(b"manifest-test").hexdigest()
    rec_key_id = "rec-key-1"
    wit_key_id = "wit-key-1"

    rec_db = tmp_path / "recorder.db"
    wit_db = tmp_path / "witness.db"
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Create dummy artifact ciphertext
    artifact_id = str(uuid4())
    art_content = b"cipher-dummy-data-12345"
    art_sha256 = hashlib.sha256(art_content).hexdigest()
    (artifacts_dir / f"{artifact_id}.bin").write_bytes(art_content)

    recorder = DurableRecorder(rec_db, rec_priv, rec_key_id)
    ctx = Context(domain_id=domain_id, experiment_id=experiment_id, epoch=epoch)
    recorder.register_run(ctx, manifest_digest)
    recorder.register_artifact(
        artifact_id, art_sha256, str(artifacts_dir / f"{artifact_id}.bin")
    )

    witness = SQLiteWitnessAuthority(
        db_path=wit_db,
        private_key=wit_priv,
        witness_key_id=wit_key_id,
        initialize_if_missing=True,
    )

    # Reserve witness start
    start_receipt = WitnessStart(
        domain_id=domain_id,
        experiment_id=experiment_id,
        epoch=epoch,
        schema_version="arena.v2",
        receipt_type="START",
        public_manifest_digest=manifest_digest,
        reservation_id=str(uuid4()),
        event_count=1,
        prefix_root="0" * 64,
        witness_key_id=wit_key_id,
    )
    asyncio.run(witness.reserve_start(start_receipt))

    # Append valid events
    art_ref = ArtifactRef(artifact_id=artifact_id, ciphertext_sha256=art_sha256)
    proposal1 = EventProposal(
        domain_id=domain_id,
        experiment_id=experiment_id,
        epoch=epoch,
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="START_RESERVED",
        outcome_code="OK",
        artifact_ciphertext_refs=[],
        duration_us=1000,
    )
    asyncio.run(recorder.append(proposal1, authenticated_actor="broker"))

    proposal2 = EventProposal(
        domain_id=domain_id,
        experiment_id=experiment_id,
        epoch=epoch,
        session_id=str(uuid4()),
        turn_id=str(uuid4()),
        turn_index=1,
        event_type="DISPATCH_INTENT",
        outcome_code="OK",
        artifact_ciphertext_refs=[art_ref],
        duration_us=5000,
    )
    asyncio.run(recorder.append(proposal2, authenticated_actor="broker"))

    terminal = EventProposal(
        domain_id=domain_id,
        experiment_id=experiment_id,
        epoch=epoch,
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="CLOSED",
        outcome_code="OK",
        artifact_ciphertext_refs=[],
        duration_us=0,
    )
    asyncio.run(recorder.append(terminal, authenticated_actor="broker"))

    signed_cp = asyncio.run(recorder.close(ctx))

    wit_close_receipt = WitnessClose(
        domain_id=domain_id,
        experiment_id=experiment_id,
        epoch=epoch,
        schema_version="arena.v2",
        receipt_type="CLOSE",
        public_manifest_digest=manifest_digest,
        checkpoint_digest=checkpoint_digest(signed_cp.checkpoint),
        event_count=signed_cp.checkpoint.event_count,
        final_root=signed_cp.checkpoint.final_root,
        witness_key_id=wit_key_id,
    )
    signed_wit_close = asyncio.run(witness.close(wit_close_receipt))

    bundle_zip = tmp_path / "valid_bundle.zip"
    export_experiment_bundle(
        recorder=recorder,
        signed_checkpoint=signed_cp,
        signed_witness_close=signed_wit_close,
        artifacts_dir=artifacts_dir,
        output_zip_path=bundle_zip,
    )

    return {
        "bundle_zip": bundle_zip,
        "rec_pub_hex": rec_pub_bytes.hex(),
        "wit_pub_hex": wit_pub_bytes.hex(),
        "domain_id": domain_id,
        "experiment_id": experiment_id,
        "epoch": str(epoch),
        "manifest_digest": manifest_digest,
        "rec_key_id": rec_key_id,
        "wit_key_id": wit_key_id,
        "tmp_path": tmp_path,
    }


def run_verifier(env, bundle_path) -> int:
    args = [
        "--bundle",
        str(bundle_path),
        "--recorder-key",
        env["rec_pub_hex"],
        "--witness-key",
        env["wit_pub_hex"],
        "--domain-id",
        env["domain_id"],
        "--experiment-id",
        env["experiment_id"],
        "--epoch",
        env["epoch"],
        "--manifest-digest",
        env["manifest_digest"],
        "--recorder-key-id",
        env["rec_key_id"],
        "--witness-key-id",
        env["wit_key_id"],
    ]
    return verifier_main(args)


def test_t007_baseline_bundle_checks_are_incomplete_without_start_receipt(
    valid_bundle_env,
):
    """Available checks pass, but the absent witness START keeps verification incomplete."""
    code = run_verifier(valid_bundle_env, valid_bundle_env["bundle_zip"])
    assert code == 4


def test_t007_tampered_event_payload(valid_bundle_env):
    """Test 1: Tampered event payload in events.jsonl breaks hash chain -> exit code 1."""
    corrupt_zip = valid_bundle_env["tmp_path"] / "corrupt_event.zip"
    with zipfile.ZipFile(valid_bundle_env["bundle_zip"], "r") as zin:
        with zipfile.ZipFile(corrupt_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "events.jsonl":
                    lines = data.decode("utf-8").splitlines()
                    obj = json.loads(lines[0])
                    obj["duration_us"] = 999999
                    lines[0] = json.dumps(obj)
                    data = ("\n".join(lines) + "\n").encode("utf-8")
                zout.writestr(item, data)

    code = run_verifier(valid_bundle_env, corrupt_zip)
    assert code == 1


def test_t007_deleted_event_truncated_chain(valid_bundle_env):
    """Test 2: Deleted event breaks sequence/count -> exit code 1."""
    corrupt_zip = valid_bundle_env["tmp_path"] / "corrupt_deleted.zip"
    with zipfile.ZipFile(valid_bundle_env["bundle_zip"], "r") as zin:
        with zipfile.ZipFile(corrupt_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "events.jsonl":
                    lines = data.decode("utf-8").splitlines()
                    data = (lines[0] + "\n").encode("utf-8")
                zout.writestr(item, data)

    code = run_verifier(valid_bundle_env, corrupt_zip)
    assert code == 1


def test_t007_reordered_events(valid_bundle_env):
    """Test 3: Reordered events break hash links -> exit code 1."""
    corrupt_zip = valid_bundle_env["tmp_path"] / "corrupt_reordered.zip"
    with zipfile.ZipFile(valid_bundle_env["bundle_zip"], "r") as zin:
        with zipfile.ZipFile(corrupt_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "events.jsonl":
                    lines = data.decode("utf-8").splitlines()
                    lines.reverse()
                    data = ("\n".join(lines) + "\n").encode("utf-8")
                zout.writestr(item, data)

    code = run_verifier(valid_bundle_env, corrupt_zip)
    assert code == 1


def test_t007_boolean_epoch_injection(valid_bundle_env):
    """Test 4: Boolean epoch injection (L-004 regression) -> exit code 2."""
    corrupt_zip = valid_bundle_env["tmp_path"] / "corrupt_bool_epoch.zip"
    with zipfile.ZipFile(valid_bundle_env["bundle_zip"], "r") as zin:
        with zipfile.ZipFile(corrupt_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "checkpoint.json":
                    raw = json.loads(data.decode("utf-8"))
                    raw["checkpoint"]["epoch"] = True
                    data = json.dumps(raw).encode("utf-8")
                zout.writestr(item, data)

    code = run_verifier(valid_bundle_env, corrupt_zip)
    assert code == 2


def test_t007_tampered_ciphertext_artifact(valid_bundle_env):
    """Test 5: Tampered ciphertext artifact fails SHA-256 digest check -> exit code 1."""
    corrupt_zip = valid_bundle_env["tmp_path"] / "corrupt_art.zip"
    with zipfile.ZipFile(valid_bundle_env["bundle_zip"], "r") as zin:
        with zipfile.ZipFile(corrupt_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename.startswith("artifacts/"):
                    data = b"tampered-ciphertext-bytes-00000"
                zout.writestr(item, data)

    code = run_verifier(valid_bundle_env, corrupt_zip)
    assert code == 1


def test_t007_witness_conflict_mismatched_root(valid_bundle_env):
    """Test 6: Witness final_root mismatch (rollback attempt) -> exit code 3."""
    corrupt_zip = valid_bundle_env["tmp_path"] / "corrupt_witness.zip"
    with zipfile.ZipFile(valid_bundle_env["bundle_zip"], "r") as zin:
        with zipfile.ZipFile(corrupt_zip, "w") as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == "witness_close.json":
                    raw = json.loads(data.decode("utf-8"))
                    raw["receipt"]["final_root"] = "0" * 64
                    data = json.dumps(raw).encode("utf-8")
                zout.writestr(item, data)

    code = run_verifier(valid_bundle_env, corrupt_zip)
    assert code == 3
