"""Comprehensive unit and negative tests for standalone offline verifier (BAR-4)."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4
import zipfile

from arena.contracts.common import Context
from arena.contracts.crypto import (
    checkpoint_digest,
    checkpoint_message,
    encrypt_artifact,
    event_digest,
    sign,
    witness_message,
)
from arena.contracts.evidence import (
    ArtifactAAD,
    ArtifactRef,
    Checkpoint,
    Event,
    SignedCheckpoint,
    SignedWitnessClose,
    WitnessClose,
)
from arena.verifier import (
    ArchiveSecurityError,
    VerificationError,
    replay_and_decrypt_artifacts,
    safe_extract_archive,
    verify_commitment_opening,
    verify_evidence_directory,
)
from arena.verifier.cli import main as cli_main
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TestStandaloneVerifier(unittest.TestCase):
    def setUp(self):
        self.rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
        self.rec_pub = Ed25519PrivateKey.from_private_bytes(self.rec_priv).public_key().public_bytes_raw()
        self.rec_key_id = "recorder-pub-1"

        self.wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
        self.wit_pub = Ed25519PrivateKey.from_private_bytes(self.wit_priv).public_key().public_bytes_raw()
        self.wit_key_id = "witness-pub-1"

        self.domain_id = str(uuid4())
        self.experiment_id = str(uuid4())
        self.epoch = 1
        self.context = Context(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
        )
        self.manifest_digest = "a" * 64

    def _create_valid_bundle(self, base_dir: Path) -> dict:
        """Create valid evidence files and return keys and paths."""
        base_dir.mkdir(parents=True, exist_ok=True)
        art_dir = base_dir / "artifacts"
        art_dir.mkdir(parents=True, exist_ok=True)

        # 1. Create and encrypt an artifact
        art_id = str(uuid4())
        aad = ArtifactAAD(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            schema_version="arena.v2",
            artifact_id=art_id,
            classification="PRIVATE_PAYLOAD",
        )
        plaintext = b"Confidential attack prompt: prompt payload 123"
        enc_key, ciphertext_blob = encrypt_artifact(plaintext, aad)
        ciphertext_sha = hashlib.sha256(ciphertext_blob).hexdigest()
        art_file = art_dir / f"{art_id}.bin"
        art_file.write_bytes(ciphertext_blob)

        art_ref = ArtifactRef(artifact_id=art_id, ciphertext_sha256=ciphertext_sha)

        # 2. Build 2 events: attempt event + terminal CLOSED event
        ev1 = Event(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            session_id=str(uuid4()),
            turn_id=str(uuid4()),
            turn_index=0,
            event_type="DISPATCH_INTENT",
            outcome_code="OK",
            artifact_ciphertext_refs=(art_ref,),
            duration_us=1000,
            schema_version="arena.v2",
            sequence=1,
            previous_digest="0" * 64,
            actor_id=self.rec_key_id,
            public_manifest_digest=self.manifest_digest,
            utc_time="2026-10-20T10:00:00Z",
        )
        d1 = event_digest(ev1)

        ev2 = Event(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            session_id=None,
            turn_id=None,
            turn_index=None,
            event_type="CLOSED",
            outcome_code="OK",
            artifact_ciphertext_refs=(),
            duration_us=0,
            schema_version="arena.v2",
            sequence=2,
            previous_digest=d1,
            actor_id=self.rec_key_id,
            public_manifest_digest=self.manifest_digest,
            utc_time="2026-10-20T10:00:01Z",
        )
        d2 = event_digest(ev2)

        events_file = base_dir / "events.jsonl"
        events_file.write_text(
            ev1.model_dump_json() + "\n" + ev2.model_dump_json() + "\n",
            encoding="utf-8",
        )

        # 3. Terminal Checkpoint
        cp = Checkpoint(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            schema_version="arena.v2",
            public_manifest_digest=self.manifest_digest,
            event_count=2,
            final_root=d2,
            terminal_marker="CLOSED",
            required_artifacts=(art_ref,),
            signer_key_id=self.rec_key_id,
        )
        cp_sig = sign(checkpoint_message(cp), self.rec_priv)
        signed_cp = SignedCheckpoint(checkpoint=cp, signature=cp_sig)
        (base_dir / "checkpoint.json").write_text(signed_cp.model_dump_json(indent=2), encoding="utf-8")

        # 4. Witness Close
        wit_close = WitnessClose(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            schema_version="arena.v2",
            receipt_type="CLOSE",
            public_manifest_digest=self.manifest_digest,
            checkpoint_digest=checkpoint_digest(cp),
            event_count=2,
            final_root=d2,
            witness_key_id=self.wit_key_id,
        )
        wit_sig = sign(witness_message(wit_close), self.wit_priv)
        signed_wit = SignedWitnessClose(receipt=wit_close, signature=wit_sig)
        (base_dir / "witness_close.json").write_text(signed_wit.model_dump_json(indent=2), encoding="utf-8")

        return {
            "artifact_id": art_id,
            "enc_key": enc_key,
            "plaintext": plaintext,
            "final_root": d2,
            "base_dir": base_dir,
        }

    def _zip_directory(self, src_dir: Path, zip_path: Path) -> Path:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(src_dir):
                for file in files:
                    full_p = Path(root) / file
                    rel_p = full_p.relative_to(src_dir)
                    zf.write(full_p, arcname=str(rel_p).replace("\\", "/"))
        return zip_path

    def test_public_checks_are_valid_but_incomplete_without_witness_start(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = Path(tmpdir) / "bundle"
            info = self._create_valid_bundle(bundle_dir)

            # Direct directory verification
            res = verify_evidence_directory(
                bundle_dir=bundle_dir,
                pinned_recorder_key=self.rec_pub,
                pinned_witness_key=self.wit_pub,
                expected_context=self.context,
                expected_manifest_digest=self.manifest_digest,
                expected_recorder_key_id=self.rec_key_id,
                expected_witness_key_id=self.wit_key_id,
            )
            self.assertEqual(res.status, "INCOMPLETE_START_PROOF")
            self.assertEqual(res.exit_code, 4)
            self.assertFalse(res.diagnostics["witness_start_verified"])
            self.assertEqual(res.event_count, 2)
            self.assertEqual(res.final_root, info["final_root"])

            # Authorized replay decryption
            decrypted = replay_and_decrypt_artifacts(
                artifacts_dir=bundle_dir / "artifacts",
                artifact_keys={info["artifact_id"]: info["enc_key"]},
                context=self.context,
            )
            self.assertEqual(decrypted[info["artifact_id"]], info["plaintext"])

            # Commitment opening test
            nonce = os.urandom(32)
            from arena.contracts.crypto import commitment
            com = commitment(info["plaintext"], nonce)
            self.assertTrue(verify_commitment_opening(com, info["plaintext"], nonce))
            self.assertFalse(verify_commitment_opening(com, b"altered plaintext", nonce))

    def test_safe_archive_zip_and_traversal_protection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = Path(tmpdir) / "bundle"
            self._create_valid_bundle(bundle_dir)
            zip_p = Path(tmpdir) / "valid.zip"
            self._zip_directory(bundle_dir, zip_p)

            # Extract valid zip
            extract_dest = Path(tmpdir) / "extracted"
            extracted_files = safe_extract_archive(zip_p, extract_dest)
            self.assertTrue(len(extracted_files) >= 4)

            # Negative test: Malicious zip with path traversal
            bad_zip_p = Path(tmpdir) / "malicious.zip"
            with zipfile.ZipFile(bad_zip_p, "w") as zf:
                zf.writestr("../../etc/passwd", "malicious payload")

            with self.assertRaises(ArchiveSecurityError):
                safe_extract_archive(bad_zip_p, Path(tmpdir) / "bad_extract")

            # Negative test: Malicious zip with absolute path
            abs_zip_p = Path(tmpdir) / "abs.zip"
            with zipfile.ZipFile(abs_zip_p, "w") as zf:
                zf.writestr("/absolute-test.txt", "malicious payload")

            with self.assertRaises(ArchiveSecurityError):
                safe_extract_archive(abs_zip_p, Path(tmpdir) / "abs_extract")

    def test_verifier_corruption_detection_t007(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = Path(tmpdir) / "bundle"
            info = self._create_valid_bundle(bundle_dir)

            # 1. Altered event payload (tampering)
            events_p = bundle_dir / "events.jsonl"
            lines = events_p.read_text(encoding="utf-8").splitlines()
            ev1_dict = json.loads(lines[0])
            ev1_dict["duration_us"] = 999999  # alter field without re-hashing
            events_p.write_text(json.dumps(ev1_dict) + "\n" + lines[1] + "\n", encoding="utf-8")

            with self.assertRaises(VerificationError) as ctx:
                verify_evidence_directory(
                    bundle_dir=bundle_dir,
                    pinned_recorder_key=self.rec_pub,
                    pinned_witness_key=self.wit_pub,
                    expected_context=self.context,
                    expected_manifest_digest=self.manifest_digest,
                    expected_recorder_key_id=self.rec_key_id,
                    expected_witness_key_id=self.wit_key_id,
                )
            self.assertEqual(ctx.exception.exit_code, 1)

            # 2. Re-create and test artifact tampering
            bundle_dir2 = Path(tmpdir) / "bundle2"
            info2 = self._create_valid_bundle(bundle_dir2)
            art_file = bundle_dir2 / "artifacts" / f"{info2['artifact_id']}.bin"
            art_file.write_bytes(art_file.read_bytes() + b"\x00")  # corrupt single byte

            with self.assertRaises(VerificationError) as ctx2:
                verify_evidence_directory(
                    bundle_dir=bundle_dir2,
                    pinned_recorder_key=self.rec_pub,
                    pinned_witness_key=self.wit_pub,
                    expected_context=self.context,
                    expected_manifest_digest=self.manifest_digest,
                    expected_recorder_key_id=self.rec_key_id,
                    expected_witness_key_id=self.wit_key_id,
                )
            self.assertEqual(ctx2.exception.exit_code, 1)
            self.assertTrue("tampering" in str(ctx2.exception))

            # 3. Schema violation: boolean epoch
            bundle_dir3 = Path(tmpdir) / "bundle3"
            self._create_valid_bundle(bundle_dir3)
            cp_file = bundle_dir3 / "checkpoint.json"
            cp_raw = json.loads(cp_file.read_text(encoding="utf-8"))
            cp_raw["checkpoint"]["epoch"] = True  # boolean epoch
            cp_file.write_text(json.dumps(cp_raw), encoding="utf-8")

            with self.assertRaises(VerificationError) as ctx3:
                verify_evidence_directory(
                    bundle_dir=bundle_dir3,
                    pinned_recorder_key=self.rec_pub,
                    pinned_witness_key=self.wit_pub,
                    expected_context=self.context,
                    expected_manifest_digest=self.manifest_digest,
                    expected_recorder_key_id=self.rec_key_id,
                    expected_witness_key_id=self.wit_key_id,
                )
            self.assertEqual(ctx3.exception.exit_code, 2)

            # 4. Witness conflict
            bundle_dir4 = Path(tmpdir) / "bundle4"
            self._create_valid_bundle(bundle_dir4)
            wit_file = bundle_dir4 / "witness_close.json"
            wit_raw = json.loads(wit_file.read_text(encoding="utf-8"))
            wit_raw["receipt"]["checkpoint_digest"] = "f" * 64  # conflicting checkpoint
            wit_file.write_text(json.dumps(wit_raw), encoding="utf-8")

            with self.assertRaises(VerificationError) as ctx4:
                verify_evidence_directory(
                    bundle_dir=bundle_dir4,
                    pinned_recorder_key=self.rec_pub,
                    pinned_witness_key=self.wit_pub,
                    expected_context=self.context,
                    expected_manifest_digest=self.manifest_digest,
                    expected_recorder_key_id=self.rec_key_id,
                    expected_witness_key_id=self.wit_key_id,
                )
            self.assertEqual(ctx4.exception.exit_code, 3)

    def test_cli_execution_clean_and_corrupt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = Path(tmpdir) / "bundle"
            info = self._create_valid_bundle(bundle_dir)
            zip_p = Path(tmpdir) / "evidence.zip"
            self._zip_directory(bundle_dir, zip_p)

            keys_json_p = Path(tmpdir) / "keys.json"
            keys_json_p.write_text(
                json.dumps({info["artifact_id"]: info["enc_key"].hex()}),
                encoding="utf-8",
            )

            # Run CLI on valid zip
            argv = [
                "--bundle", str(zip_p),
                "--recorder-key", self.rec_pub.hex(),
                "--witness-key", self.wit_pub.hex(),
                "--domain-id", self.domain_id,
                "--experiment-id", self.experiment_id,
                "--epoch", "1",
                "--manifest-digest", self.manifest_digest,
                "--recorder-key-id", self.rec_key_id,
                "--witness-key-id", self.wit_key_id,
                "--keys-json", str(keys_json_p),
            ]
            exit_code = cli_main(argv)
            self.assertEqual(exit_code, 4)

            # Run CLI on bad key -> fails with exit code 1
            bad_argv = list(argv)
            bad_argv[3] = ("0" * 64)  # bad recorder public key
            exit_code_bad = cli_main(bad_argv)
            self.assertEqual(exit_code_bad, 1)


if __name__ == "__main__":
    unittest.main()
