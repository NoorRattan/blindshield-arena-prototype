"""OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE.
Static consistency checks for the owner-delegated N08 prototype inputs.
These checks do not test admission, confinement, or workload authorization.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives import serialization


BACKEND = Path(__file__).resolve().parents[1]
INPUTS = BACKEND / "infra" / "owner-delegated-n08"
LABEL = "OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE"


def read_json(name: str) -> dict:
    return json.loads((INPUTS / name).read_text(encoding="utf-8"))


class OwnerDelegatedInputTests(unittest.TestCase):
    def test_all_self_created_text_artifacts_carry_the_required_label(self):
        paths = [
            INPUTS / "README.md",
            INPUTS / "demo-ca-certificate.pem",
            INPUTS / "model-source-attempts.log",
            INPUTS / "recorder-public.pem",
            INPUTS / "witness-public.pem",
            BACKEND / "tools" / "create_n08_synthetic_cohort.py",
            BACKEND / "tools" / "observe_n08_capacity.py",
            Path(__file__),
        ]
        for path in paths:
            with self.subTest(path=path.name):
                self.assertIn(LABEL, path.read_text(encoding="utf-8"))

    def test_all_profile_manifests_are_explicitly_labeled(self):
        for path in sorted(INPUTS.glob("*.json")):
            with self.subTest(name=path.name):
                self.assertEqual(read_json(path.name)["artifact_label"], LABEL)

    def test_profile_stays_candidate_only_and_non_authorizing(self):
        profile = read_json("profile.json")
        self.assertEqual(profile["profile_id"], "n08-owner-delegated-cpu-prototype-v1")
        self.assertEqual(
            profile["execution"]["profile_status"],
            "OWNER_DELEGATED_PROTOTYPE_CANDIDATE_RUNTIME_UNRESOLVED_NOT_N08_ADMISSION",
        )
        self.assertFalse(profile["execution"]["model_workload_authorized"])
        self.assertFalse(profile["capabilities"]["network_egress"])
        self.assertFalse(profile["capabilities"]["runtime_downloads"])
        self.assertFalse(profile["topology"]["host_cpu_exclusivity_verified"])
        self.assertEqual(profile["model"]["runtime"], "transformers-pytorch-cpu")
        self.assertIsNone(profile["model"]["runtime_image_id"])
        self.assertEqual(
            profile["topology"]["memory_limit_fit_for_selected_transformers_model"],
            "UNVERIFIED_NOT_MEASURED",
        )

    def test_selected_model_source_license_and_tokenizer_are_pinned(self):
        model = read_json("model-manifest.json")
        self.assertEqual(model["selected_asset"]["publisher_repository"], "HuggingFaceTB/SmolLM2-360M-Instruct")
        self.assertEqual(model["selected_asset"]["pinned_revision"], "502b5cb068ad185080c7ea271bee653f0f6c0777")
        self.assertEqual(model["selected_asset"]["sha256"], "e6bffe7435d7ddc10fd3b9a9efd429dafbacb1cb17015fb5562664e7532bf86e")
        self.assertEqual(model["selected_asset"]["size_bytes"], 723674912)
        self.assertFalse(model["selected_asset"]["local_presence_verified"])
        self.assertEqual(model["license"]["declared_license"], "Apache-2.0")
        self.assertEqual(model["license"]["source_declaration_status"], "VERIFIED_FROM_PINNED_PUBLISHER_MODEL_CARD")
        self.assertEqual(model["tokenizer"]["tokenizer_json"]["sha256"], "9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c")
        self.assertEqual(model["provenance"]["conversion_lineage_status"], "NOT_APPLICABLE_TO_SELECTED_RAW_FILE")
        self.assertEqual(
            model["provenance"]["training_data_and_development_lineage_status"],
            "PUBLISHER_DECLARED_NOT_INDEPENDENTLY_VERIFIED",
        )
        self.assertEqual(
            model["excluded_prior_candidate"]["selection_status"],
            "NOT_SELECTED_IN_THIS_DRAFT; GGUF_CONVERSION_LINEAGE_UNVERIFIED; FINAL_PROFILE_SELECTION_PENDING_STEP_2",
        )
        readme = (INPUTS / "README.md").read_text(encoding="utf-8")
        self.assertIn("does not record a source-repository commit hash", readme)
        self.assertIn("Qwen2.5-0.5B-Instruct is the provisional first candidate", readme)
        self.assertIn("SmolLM2-360M-Instruct is a smaller fallback", readme)
        self.assertIn("does not establish a final model/runtime choice", readme)
        source = read_json("model-source-observation.json")
        self.assertEqual(source["revision"], model["selected_asset"]["pinned_revision"])
        self.assertEqual(source["model_file"]["sha256"], model["selected_asset"]["sha256"])
        self.assertFalse(source["model_file"]["local_checkpoint_bytes_hashed"])
        self.assertEqual(source["model_file"]["publisher_upload_commit"], "1717970b6ee66d5bbdc2fa0175463c41eb5b9662")
        self.assertIsNone(source["model_file"]["source_repository_commit"])
        self.assertEqual(
            model["provenance"]["weight_copy_source_revision_status"],
            "NOT_RECORDED_IN_PINNED_DESTINATION_HISTORY",
        )
        source_files = {item["path"]: item for item in source["pinned_small_files"]}
        self.assertEqual(source_files["tokenizer.json"]["sha256"], model["tokenizer"]["tokenizer_json"]["sha256"])
        self.assertEqual(source_files["README.md"]["sha256"], model["license"]["declaration_document_sha256"])

    def test_image_manifest_does_not_claim_an_unbuilt_model_runtime(self):
        images = read_json("image-manifest.json")["images"]
        self.assertIsNone(images["model_cell"]["image_id"])
        self.assertEqual(images["model_cell"]["status"], "NOT_BUILT_NO_OUTPUT_DIGEST")
        self.assertFalse(images["model_cell"]["workload_authorized"])
        self.assertEqual(
            images["previous_n05_llama_model_runtime"]["selection_status"],
            "NOT_SELECTED_FOR_RAW_SAFETENSORS_MODEL_WITHOUT_A_RECORDED_CONVERSION",
        )
        self.assertEqual(
            images["runtime_base_candidate"]["purpose"],
            "base-image-candidate-only; not a Transformers/PyTorch model runtime",
        )
        self.assertEqual(images["defense_cell"]["image_id"], "sha256:c2ba5e610d1064f1a8b84ee3b1455942eeccca3d90a02909eda80b8f5d26658c")
        self.assertTrue(images["defense_cell"]["image_label_source_hash_matches"])
        self.assertIn("UNVERIFIED", images["defense_cell"]["license_status"])
        self.assertIn("UNVERIFIED", images["defense_cell"]["build_provenance_status"])

    def test_fixture_is_pinned_to_official_amd64_digest_and_not_locally_admitted(self):
        fixture = read_json("fixture-manifest.json")["fixture"]
        self.assertEqual(fixture["docker_image_config_id"], "sha256:aaef90e065235eb0b2d9938be85d1b81add2902cf89affe2cdfa19be33476ac0")
        self.assertEqual(fixture["license"], "GPL-2.0-only")
        self.assertFalse(fixture["local_presence_verified"])
        fixture_manifest = read_json("fixture-manifest.json")
        self.assertEqual(fixture["source_metadata_revision"], "a1b523e0a307c0fa219c908404ee6345a5e189c7")
        self.assertEqual(fixture["source_metadata_sha256"], "bc0e10e8e386f2c187043675b39ce437e5dabcca960c109487e71137b7bd5228")
        self.assertIn(fixture["source_metadata_revision"], " ".join(fixture_manifest["source_references"]))
        self.assertIn("4c1756d5e2fd5dc60276cba8c01b366e5eb667ef", " ".join(fixture_manifest["source_references"]))

    def test_capacity_report_signature_source_and_scope(self):
        report_path = INPUTS / "capacity-observation-prebuild-2026-10-26.json"
        report = read_json(report_path.name)
        policy = read_json("resource-policy.json")
        attestation = report["self_attestation"]
        payload = {key: value for key, value in report.items() if key != "self_attestation"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        public_key = serialization.load_pem_public_key((INPUTS / "recorder-public.pem").read_bytes())
        self.assertEqual(hashlib.sha256(report_path.read_bytes()).hexdigest(), policy["capacity_observation"]["sha256"])
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), attestation["payload_sha256"])
        self.assertEqual(attestation["signer_key_id"], "n08-prototype-recorder-001")
        public_key.verify(base64.b64decode(attestation["signature_base64"], validate=True), canonical)
        collector_hash = hashlib.sha256((BACKEND / "tools" / "observe_n08_capacity.py").read_bytes()).hexdigest()
        self.assertEqual(report["collector_source_sha256"], collector_hash)
        self.assertEqual(policy["capacity_observation"]["collector_source_sha256"], collector_hash)
        self.assertEqual(policy["capacity_observation"]["path"], report_path.relative_to(BACKEND.parent).as_posix())
        self.assertGreater(report["host"]["logical_cpu_count"], 0)
        self.assertGreaterEqual(report["host"]["cpu_load_percent_sample"], 0)
        self.assertEqual(set(report["host"]["volumes"]), {"C:", "N:"})
        self.assertGreater(report["host"]["volumes"]["C:"]["free_bytes"], 0)
        self.assertGreater(report["host"]["volumes"]["N:"]["free_bytes"], 0)
        self.assertGreater(report["docker_vm"]["data_disk"]["available_bytes"], 0)
        self.assertEqual(report["docker_vm"]["data_disk"]["mount_point"], "/mnt/docker-desktop-disk")
        self.assertEqual(set(report["pinned_local_image_ids"]), {"model", "defense", "python_base_candidate"})
        self.assertFalse(report["model_workload_started_by_collector"])
        self.assertFalse(report["n08_three_lane_peak_memory_measured"])
        self.assertFalse(report["runtime_network_or_image_downloads"])
        self.assertFalse(policy["network_policy"]["runtime_egress_allowed"])
        self.assertEqual(
            policy["selected_runtime_fit"]["status"],
            "UNVERIFIED_NOT_MEASURED_FOR_SMOLLM2_TRANSFORMERS_CPU",
        )

    def test_authority_public_material_hashes_match_manifest(self):
        manifest = read_json("authority-manifest.json")
        for authority in manifest["authorities"]:
            with self.subTest(key_id=authority["key_id"]):
                if authority["role"] == "demo_ca":
                    public_path = INPUTS / authority["certificate_file"]
                    self.assertEqual(hashlib.sha256(public_path.read_bytes()).hexdigest(), authority["certificate_sha256"])
                else:
                    public_path = INPUTS / authority["public_key_file"]
                    self.assertEqual(hashlib.sha256(public_path.read_bytes()).hexdigest(), authority["public_pem_sha256"])

    def test_synthetic_cohort_is_fixed_seed_mixed_verdict_only(self):
        cohort = read_json("synthetic-varied-outcome-cohort.json")
        self.assertEqual(cohort["seed"], 20261026)
        self.assertEqual(len(cohort["records"]), 36)
        self.assertEqual(cohort["expected_verdict_counts"], {"ALLOW": 12, "BLOCK": 12, "SANITIZE": 12})
        self.assertIn("SYNTHETIC", cohort["status"])
        self.assertIn("never real-population", cohort["scope_limit"])


if __name__ == "__main__":
    unittest.main()
