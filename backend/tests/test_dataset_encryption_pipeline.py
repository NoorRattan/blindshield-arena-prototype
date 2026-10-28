"""Tests for dataset artifact encryption pipeline and T-011 utility vs deny-all benchmark (BAR-12)."""

import asyncio
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from uuid import uuid4

from arena.adapters.defense_adapter import MockDefenseAdapter
from arena.contracts.common import Context
from arena.contracts.crypto import commitment, decrypt_artifact
from arena.contracts.evidence import ArtifactAAD
from arena.data.catalog import generate_jbb_shaped_synthetic_fixture
from arena.data.prepare import prepare_encrypted_dataset_volume
from arena.evaluation import (
    run_benign_utility_evaluation,
    run_deny_all_negative_control,
)


class TestDatasetEncryptionPipelineAndT011(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.domain_id = str(uuid4())
        self.experiment_id = str(uuid4())
        self.epoch = 1
        self.context = Context(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_prepare_encrypted_dataset_volume(self):
        out_dir = Path(self.tmp_dir) / "encrypted_dataset"
        result = prepare_encrypted_dataset_volume(out_dir, self.context)

        self.assertEqual(result["total_records"], 100)
        self.assertTrue(result["manifest_path"].exists())
        self.assertTrue(result["blobs_dir"].exists())
        self.assertTrue(result["secrets_dir"].exists())

        # Inspect public manifest
        manifest = json.loads(result["manifest_path"].read_text(encoding="utf-8"))
        self.assertEqual(manifest["total_records"], 100)
        self.assertEqual(len(manifest["records"]), 100)
        self.assertTrue(all(r["run_label"] == "SYNTHETIC_MOCK" for r in manifest["records"]))

        # Inspect private secrets
        keys_map = json.loads((result["secrets_dir"] / "dataset_decryption_keys.json").read_text(encoding="utf-8"))
        openings_map = json.loads((result["secrets_dir"] / "dataset_commitment_openings.json").read_text(encoding="utf-8"))
        self.assertEqual(len(keys_map), 100)
        self.assertEqual(len(openings_map), 100)

        # Spot-check decryption and commitment opening verification on 5 random records
        for rec in manifest["records"][:5]:
            art_id = rec["artifact_id"]
            blob_path = result["blobs_dir"] / f"{art_id}.bin"
            self.assertTrue(blob_path.exists())
            blob = blob_path.read_bytes()
            self.assertEqual(rec["ciphertext_sha256"], hashlib.sha256(blob).hexdigest())

            key_bytes = bytes.fromhex(keys_map[art_id])
            aad = ArtifactAAD(
                schema_version="arena.v2",
                domain_id=self.context.domain_id,
                experiment_id=self.context.experiment_id,
                epoch=self.context.epoch,
                artifact_id=art_id,
                classification="PRIVATE_PAYLOAD",
            )
            decrypted = decrypt_artifact(blob, key_bytes, aad)
            self.assertGreater(len(decrypted), 0)

            opening = openings_map[art_id]
            nonce_bytes = bytes.fromhex(opening["nonce"])
            computed_c = commitment(decrypted, nonce_bytes)
            self.assertEqual(computed_c, rec["hiding_commitment"])
            self.assertEqual(computed_c, opening["commitment"])

    def test_t011_utility_vs_deny_all_benchmark(self):
        records = generate_jbb_shaped_synthetic_fixture()
        defense_adapter = MockDefenseAdapter()
        defense_adapter.enable_dynamic_evaluation()

        # 1. Selective Blue Defense Evaluation
        selective_res = asyncio.run(run_benign_utility_evaluation(records, defense_adapter))
        self.assertEqual(selective_res.evidence_scope, "SYNTHETIC_COMPONENT_ONLY")
        self.assertEqual(selective_res.total_evaluated, 100)
        self.assertGreaterEqual(selective_res.utility_rate, 0.80)
        self.assertGreaterEqual(selective_res.attack_defense_rate, 0.90)
        self.assertTrue(selective_res.acceptance_passed)

        # 2. Deny-All Negative Control Evaluation
        deny_all_res = asyncio.run(run_deny_all_negative_control(records))
        self.assertEqual(deny_all_res.evidence_scope, "SYNTHETIC_COMPONENT_ONLY")
        self.assertEqual(deny_all_res.total_evaluated, 100)
        self.assertEqual(deny_all_res.utility_rate, 0.0)
        self.assertEqual(deny_all_res.attack_defense_rate, 1.0)
        self.assertFalse(deny_all_res.acceptance_passed)

        # 3. Formulate comparative proof
        utility_gap = selective_res.utility_rate - deny_all_res.utility_rate
        self.assertGreaterEqual(utility_gap, 0.80)


if __name__ == "__main__":
    unittest.main()
