"""Tests for evidence ZIP bundle exporter and full T-007 / P-014 corruption matrix (BAR-9)."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
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
from arena.ports import DependencyUnavailable
from arena.verifier import (
    ArchiveSecurityError,
    VerificationError,
    export_evidence_bundle,
    safe_extract_archive,
    verify_evidence_directory,
)
from arena.verifier.cli import main as cli_main
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TestVerifierBundleAndCorruptionMatrix(unittest.TestCase):
    def setUp(self):
        self.rec_priv = Ed25519PrivateKey.generate().private_bytes_raw()
        self.rec_pub = Ed25519PrivateKey.from_private_bytes(self.rec_priv).public_key().public_bytes_raw()
        self.rec_key_id = "recorder-key-1"

        self.wit_priv = Ed25519PrivateKey.generate().private_bytes_raw()
        self.wit_pub = Ed25519PrivateKey.from_private_bytes(self.wit_priv).public_key().public_bytes_raw()
        self.wit_key_id = "witness-key-1"

        self.domain_id = str(uuid4())
        self.experiment_id = str(uuid4())
        self.epoch = 1
        self.context = Context(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
        )
        self.manifest_digest = "f" * 64

    def _generate_valid_evidence_structures(self):
        art_id = str(uuid4())
        aad = ArtifactAAD(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            schema_version="arena.v2",
            artifact_id=art_id,
            classification="PRIVATE_PAYLOAD",
        )
        enc_key, blob = encrypt_artifact(b"Valid attack prompt", aad)
        blob_sha = hashlib.sha256(blob).hexdigest()
        art_ref = ArtifactRef(artifact_id=art_id, ciphertext_sha256=blob_sha)

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
            utc_time="2026-10-20T12:00:00Z",
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
            utc_time="2026-10-20T12:00:01Z",
        )
        d2 = event_digest(ev2)

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

        wc = WitnessClose(
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
        wc_sig = sign(witness_message(wc), self.wit_priv)
        signed_wc = SignedWitnessClose(receipt=wc, signature=wc_sig)

        events = [ev1, ev2]
        artifacts = {art_id: blob}
        return signed_cp, signed_wc, events, artifacts

    def test_export_bundle_lifecycle_and_verification(self):
        signed_cp, signed_wc, events, artifacts = self._generate_valid_evidence_structures()

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "evidence.zip"
            exported = export_evidence_bundle(zip_path, signed_cp, signed_wc, events, artifacts)
            self.assertTrue(exported.exists())

            # Verify extraction and validation
            dest = Path(tmpdir) / "extracted"
            safe_extract_archive(exported, dest)

            result = verify_evidence_directory(
                bundle_dir=dest,
                pinned_recorder_key=self.rec_pub,
                pinned_witness_key=self.wit_pub,
                expected_context=self.context,
                expected_manifest_digest=self.manifest_digest,
                expected_recorder_key_id=self.rec_key_id,
                expected_witness_key_id=self.wit_key_id,
            )
            self.assertEqual(result.status, "INCOMPLETE_START_PROOF")
            self.assertEqual(result.exit_code, 4)
            self.assertEqual(result.event_count, 2)

    def test_export_is_deterministic_and_sorts_artifact_entries(self):
        signed_cp, signed_wc, events, artifacts = self._generate_valid_evidence_structures()
        second_artifact_id = str(uuid4())
        second_aad = ArtifactAAD(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            schema_version="arena.v2",
            artifact_id=second_artifact_id,
            classification="PRIVATE_PAYLOAD",
        )
        _enc_key, second_blob = encrypt_artifact(b"Second valid attack prompt", second_aad)
        second_ref = ArtifactRef(
            artifact_id=second_artifact_id,
            ciphertext_sha256=hashlib.sha256(second_blob).hexdigest(),
        )
        first_event = events[0].model_copy(update={
            "artifact_ciphertext_refs": (*events[0].artifact_ciphertext_refs, second_ref),
        })
        first_root = event_digest(first_event)
        close_event = events[1].model_copy(update={"previous_digest": first_root})
        final_root = event_digest(close_event)
        checkpoint = signed_cp.checkpoint.model_copy(update={
            "final_root": final_root,
            "required_artifacts": tuple(sorted(
                (*signed_cp.checkpoint.required_artifacts, second_ref),
                key=lambda ref: str(ref.artifact_id),
            )),
        })
        signed_cp = SignedCheckpoint(
            checkpoint=checkpoint,
            signature=sign(checkpoint_message(checkpoint), self.rec_priv),
        )
        witness_close = signed_wc.receipt.model_copy(update={
            "checkpoint_digest": checkpoint_digest(checkpoint),
            "final_root": final_root,
        })
        signed_wc = SignedWitnessClose(
            receipt=witness_close,
            signature=sign(witness_message(witness_close), self.wit_priv),
        )
        events = [first_event, close_event]
        artifacts = {**artifacts, second_artifact_id: second_blob}

        with tempfile.TemporaryDirectory() as tmpdir:
            first = Path(tmpdir) / "first.zip"
            second = Path(tmpdir) / "second.zip"
            export_evidence_bundle(first, signed_cp, signed_wc, events, artifacts)
            export_evidence_bundle(second, signed_cp, signed_wc, events, dict(reversed(list(artifacts.items()))))
            self.assertEqual(first.read_bytes(), second.read_bytes())

            with zipfile.ZipFile(first) as archive:
                infos = archive.infolist()
                self.assertEqual(
                    [info.filename for info in infos if info.filename.startswith("artifacts/") and info.filename.endswith(".bin")],
                    [f"artifacts/{artifact_id}.bin" for artifact_id in sorted(artifacts)],
                )
                self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in infos))
                directory = next(info for info in infos if info.filename == "artifacts/")
                self.assertEqual((directory.external_attr >> 16) & 0o777, 0o755)
                self.assertEqual(
                    {(info.external_attr >> 16) & 0o777 for info in infos if not info.is_dir()},
                    {0o644},
                )

    def test_export_refuses_existing_and_symlinked_output_paths_without_writes(self):
        signed_cp, signed_wc, events, artifacts = self._generate_valid_evidence_structures()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            existing = root / "existing.zip"
            original = b"preserve these preexisting bytes"
            existing.write_bytes(original)
            with self.assertRaises(DependencyUnavailable):
                export_evidence_bundle(existing, signed_cp, signed_wc, events, artifacts)
            self.assertEqual(existing.read_bytes(), original)

            protected = root / "protected.bin"
            protected.write_bytes(b"protected target")
            destination_link = root / "destination-link.zip"
            ancestor_link = root / "ancestor-link"
            real_directory = root / "real-directory"
            real_directory.mkdir()
            try:
                destination_link.symlink_to(protected)
                ancestor_link.symlink_to(real_directory, target_is_directory=True)
            except (OSError, NotImplementedError):
                # Some Windows hosts disable symlink creation. Exercise the same
                # no-write branches by marking the lexical paths as link paths.
                with patch(
                    "arena.verifier.bundle._is_symlink_or_reparse_point",
                    side_effect=lambda path: path == destination_link,
                ):
                    with self.assertRaises(DependencyUnavailable):
                        export_evidence_bundle(destination_link, signed_cp, signed_wc, events, artifacts)
                with patch(
                    "arena.verifier.bundle._is_symlink_or_reparse_point",
                    side_effect=lambda path: path == ancestor_link,
                ):
                    with self.assertRaises(DependencyUnavailable):
                        export_evidence_bundle(ancestor_link / "new.zip", signed_cp, signed_wc, events, artifacts)
            else:
                with self.assertRaises(DependencyUnavailable):
                    export_evidence_bundle(destination_link, signed_cp, signed_wc, events, artifacts)
                self.assertTrue(destination_link.is_symlink())
                self.assertEqual(protected.read_bytes(), b"protected target")

                with self.assertRaises(DependencyUnavailable):
                    export_evidence_bundle(ancestor_link / "new.zip", signed_cp, signed_wc, events, artifacts)
            self.assertFalse((real_directory / "new.zip").exists())
            self.assertEqual(list(real_directory.iterdir()), [])
            self.assertEqual(list(root.glob(".arena-bundle-*.zip")), [])

    def test_export_no_clobber_publish_preserves_destination_created_at_publish(self):
        signed_cp, signed_wc, events, artifacts = self._generate_valid_evidence_structures()

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            output = root / "racing.zip"
            racing_bytes = b"created by a competing publisher"

            def competing_publisher(_source, destination):
                Path(destination).write_bytes(racing_bytes)
                raise FileExistsError("destination appeared during publication")

            with patch("arena.verifier.bundle.os.link", side_effect=competing_publisher):
                with self.assertRaises(DependencyUnavailable):
                    export_evidence_bundle(output, signed_cp, signed_wc, events, artifacts)

            self.assertEqual(output.read_bytes(), racing_bytes)
            self.assertEqual(list(root.glob(".arena-bundle-*.zip")), [])

    def test_export_bundle_preflight_rejections(self):
        signed_cp, signed_wc, events, artifacts = self._generate_valid_evidence_structures()

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "test.zip"

            # 1. Event count mismatch
            with self.assertRaises(DependencyUnavailable) as ctx:
                export_evidence_bundle(zip_path, signed_cp, signed_wc, events[:1], artifacts)
            self.assertTrue("event count mismatch" in str(ctx.exception))

            # 2. Missing artifact
            with self.assertRaises(DependencyUnavailable) as ctx2:
                export_evidence_bundle(zip_path, signed_cp, signed_wc, events, {})
            self.assertTrue("missing required artifact" in str(ctx2.exception))

            # 3. Checksum mismatch
            bad_artifacts = {k: v + b"\x00" for k, v in artifacts.items()}
            with self.assertRaises(DependencyUnavailable) as ctx3:
                export_evidence_bundle(zip_path, signed_cp, signed_wc, events, bad_artifacts)
            self.assertTrue("checksum mismatch" in str(ctx3.exception))

            extra_artifacts = {**artifacts, str(uuid4()): b"unreferenced"}
            with self.assertRaises(DependencyUnavailable) as ctx4:
                export_evidence_bundle(zip_path, signed_cp, signed_wc, events, extra_artifacts)
            self.assertTrue("unexpected artifact" in str(ctx4.exception))

    def test_archive_rejects_duplicate_names_and_verifier_rejects_extra_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            duplicate_zip = root / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate_zip, "w") as zf:
                    zf.writestr("checkpoint.json", "{}")
                    zf.writestr("checkpoint.json", "{}")
            with self.assertRaises(ArchiveSecurityError):
                safe_extract_archive(duplicate_zip, root / "duplicate-out")

            signed_cp, signed_wc, events, artifacts = self._generate_valid_evidence_structures()
            bundle_zip = root / "evidence.zip"
            export_evidence_bundle(bundle_zip, signed_cp, signed_wc, events, artifacts)
            extracted = root / "extracted"
            safe_extract_archive(bundle_zip, extracted)
            (extracted / "artifacts" / "unexpected.bin").write_bytes(b"extra")
            with self.assertRaises(VerificationError):
                verify_evidence_directory(
                    extracted,
                    self.rec_pub,
                    self.wit_pub,
                    self.context,
                    self.manifest_digest,
                    self.rec_key_id,
                    self.wit_key_id,
                )

    def test_full_t007_p014_verifier_corruption_matrix(self):
        """Execute full matrix of corrupted bundle variations, verifying standard exit codes (1, 2, 3)."""
        signed_cp, signed_wc, events, artifacts = self._generate_valid_evidence_structures()

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Tampered event digest (Exit code 1)
            b1 = Path(tmpdir) / "b1"
            safe_extract_archive(export_evidence_bundle(Path(tmpdir) / "b1.zip", signed_cp, signed_wc, events, artifacts), b1)
            lines = (b1 / "events.jsonl").read_text(encoding="utf-8").splitlines()
            e1 = json.loads(lines[0])
            e1["duration_us"] = 88888  # modify without updating signature or root
            (b1 / "events.jsonl").write_text(json.dumps(e1) + "\n" + lines[1] + "\n")
            with self.assertRaises(VerificationError) as ctx1:
                verify_evidence_directory(b1, self.rec_pub, self.wit_pub, self.context, self.manifest_digest, self.rec_key_id, self.wit_key_id)
            self.assertEqual(ctx1.exception.exit_code, 1)

            # 2. Deleted event / truncated chain (Exit code 1)
            b2 = Path(tmpdir) / "b2"
            safe_extract_archive(export_evidence_bundle(Path(tmpdir) / "b2.zip", signed_cp, signed_wc, events, artifacts), b2)
            (b2 / "events.jsonl").write_text(lines[0] + "\n")
            with self.assertRaises(VerificationError) as ctx2:
                verify_evidence_directory(b2, self.rec_pub, self.wit_pub, self.context, self.manifest_digest, self.rec_key_id, self.wit_key_id)
            self.assertEqual(ctx2.exception.exit_code, 1)

            # 3. Boolean epoch injection (Exit code 2)
            b3 = Path(tmpdir) / "b3"
            safe_extract_archive(export_evidence_bundle(Path(tmpdir) / "b3.zip", signed_cp, signed_wc, events, artifacts), b3)
            raw_cp = json.loads((b3 / "checkpoint.json").read_text(encoding="utf-8"))
            raw_cp["checkpoint"]["epoch"] = True
            (b3 / "checkpoint.json").write_text(json.dumps(raw_cp))
            with self.assertRaises(VerificationError) as ctx3:
                verify_evidence_directory(b3, self.rec_pub, self.wit_pub, self.context, self.manifest_digest, self.rec_key_id, self.wit_key_id)
            self.assertEqual(ctx3.exception.exit_code, 2)

            # 4. Bad recorder signature (Exit code 1)
            b4 = Path(tmpdir) / "b4"
            safe_extract_archive(export_evidence_bundle(Path(tmpdir) / "b4.zip", signed_cp, signed_wc, events, artifacts), b4)
            with self.assertRaises(VerificationError) as ctx4:
                verify_evidence_directory(b4, bytes.fromhex("11" * 32), self.wit_pub, self.context, self.manifest_digest, self.rec_key_id, self.wit_key_id)
            self.assertEqual(ctx4.exception.exit_code, 1)

            # 5. Witness conflict / altered checkpoint digest (Exit code 3)
            b5 = Path(tmpdir) / "b5"
            safe_extract_archive(export_evidence_bundle(Path(tmpdir) / "b5.zip", signed_cp, signed_wc, events, artifacts), b5)
            raw_wc = json.loads((b5 / "witness_close.json").read_text(encoding="utf-8"))
            raw_wc["receipt"]["checkpoint_digest"] = "99" * 32
            (b5 / "witness_close.json").write_text(json.dumps(raw_wc))
            with self.assertRaises(VerificationError) as ctx5:
                verify_evidence_directory(b5, self.rec_pub, self.wit_pub, self.context, self.manifest_digest, self.rec_key_id, self.wit_key_id)
            self.assertEqual(ctx5.exception.exit_code, 3)

            # 6. Corrupt ciphertext (Exit code 1)
            b6 = Path(tmpdir) / "b6"
            safe_extract_archive(export_evidence_bundle(Path(tmpdir) / "b6.zip", signed_cp, signed_wc, events, artifacts), b6)
            art_file = list((b6 / "artifacts").glob("*.bin"))[0]
            art_file.write_bytes(art_file.read_bytes() + b"\x00")
            with self.assertRaises(VerificationError) as ctx6:
                verify_evidence_directory(b6, self.rec_pub, self.wit_pub, self.context, self.manifest_digest, self.rec_key_id, self.wit_key_id)
            self.assertEqual(ctx6.exception.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
