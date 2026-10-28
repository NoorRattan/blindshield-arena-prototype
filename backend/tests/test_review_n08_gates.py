"""Source-only N08 gate report tests; none creates a Docker/model workload."""

import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import review_n08_gates as gates


MODEL_IMAGE = "sha256:" + "a" * 64
DEFENSE_IMAGE = "sha256:" + "b" * 64


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def candidate_facts() -> dict:
    return {
        "published_mem041_admission_sha256": "c" * 64,
        "published_mem041_model_sha256": "d" * 64,
        "published_mem041_license_sha256": "e" * 64,
        "local_n05_admission_present": True,
        "local_n05_admission_sha256": "c" * 64,
        "local_n05_admission_matches_mem041": True,
        "model_artifact_present": True,
        "model_artifact_bytes": 12,
        "model_artifact_sha256": "d" * 64,
        "model_artifact_matches_mem041": True,
        "license_file_present": True,
        "license_file_sha256": "e" * 64,
        "license_file_matches_mem041": True,
        "candidate_model_revision": "f" * 40,
        "candidate_model_license": "Apache-2.0",
        "candidate_llama_source_revision": "1" * 40,
        "candidate_model_image_id": MODEL_IMAGE,
        "candidate_defense_image_id": DEFENSE_IMAGE,
        "candidate_tokenizer_binding": "EMBEDDED_IN_EXACT_GGUF",
        "candidate_input_token_cap": 1536,
        "candidate_context_tokens": 2048,
        "candidate_max_output_tokens": 64,
        "candidate_deadline_seconds": 45,
        "candidate_scope": "N05_LOCAL_THREE_PROCESS_BASELINE_NOT_FULL_ARENA_ACCEPTANCE",
        "candidate_model_cpusets": ["0,1,2,3", "4,5,6,7", "8,9,10,11"],
        "candidate_defense_cpuset": "12,13,14,15,16,17,18,19,20,21,22,23",
        "candidate_minimum_available_memory_bytes": 7516192768,
        "candidate_model_lane_memory_limit_bytes": 2 * 1024**3,
        "candidate_model_lane_memory_limit_source": "backend/src/arena/integration/runtime.py",
        "candidate_scope_note": "N05 candidates only.",
    }


def review_inputs(root: Path, *, approved_images=None, locked_images=None, malformed=False):
    lock = {
        "status": "INCOMPLETE_NOT_READY",
        "lock_complete": False,
        "linux_runtime": None if malformed else {"image_ids": locked_images or []},
        "tooling": {},
        "model": {},
        "authorities": None,
        "resource_policy": None,
        "blocked_prerequisites": [],
    }
    allowlist = {
        "status": "DRAFT_NO_ACQUISITION_IMPLEMENTED",
        "downloads_enabled": False,
        "runtime_egress_allowed": False,
        "approved_execution_images": None if malformed else (
            [{"image_id": value} for value in approved_images]
            if approved_images is not None else [{"image_id": MODEL_IMAGE}]
        ),
    }
    fixture_policy = {"approved_probe_images": None if malformed else []}
    n05 = {"admission": {}, "n08_acceptance": False, "guarantee_tier_achieved": None, "n05_run": {}}
    n042 = {"runtime_observation": [] if malformed else {}}
    paths = {
        "environment.lock.json": lock,
        "source-allowlist.json": allowlist,
        "policy.json": fixture_policy,
        "n04-sources.json": {},
        "n08-fresh-n05-baseline-2026-10-25-mem041.json": n05,
        "n08-passive-runtime-environment-lock-inventory-2026-10-25-mem042.json": n042,
    }

    def load(path):
        return paths.get(path.name, {})

    hashes = {relative: "a" * 64 for relative in gates.SOURCE_PATHS}
    return lock, allowlist, fixture_policy, load, hashes


class N08GateReviewTests(unittest.TestCase):
    def test_image_digest_parser_rejects_mutable_or_malformed_references(self):
        self.assertEqual(gates.image_id("repo/model@" + MODEL_IMAGE), MODEL_IMAGE)
        self.assertEqual(gates.image_id(MODEL_IMAGE), MODEL_IMAGE)
        self.assertIsNone(gates.image_id("repo/model:latest"))
        self.assertIsNone(gates.image_id({"image_id": MODEL_IMAGE}))
        self.assertEqual(gates._approved_image_id({"image_id": MODEL_IMAGE}), MODEL_IMAGE)
        self.assertIsNone(gates._approved_image_id({"image_id": "latest"}))

    def test_n05_memory_candidate_is_extracted_from_runtime_source(self):
        source = 'docker("run", "--memory", "2g", "--memory-swap", "2g")'
        self.assertEqual(gates._n05_model_memory_limit(source), 2 * 1024**3)
        self.assertIsNone(gates._n05_model_memory_limit('docker("run", "--memory", "unbounded")'))

    def test_unmatched_local_admission_never_emits_candidate_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backend = root / "backend"
            artifact = backend / "artifacts/n04-release-preparation/model.gguf"
            license_path = artifact.parent / "LICENSE"
            admission_path = backend / "artifacts/n05-prepared-mem041/admission.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"model bytes")
            license_path.write_bytes(b"license bytes")
            local = {
                "model_sha256": sha256_bytes(b"model bytes"),
                "model_license_sha256": sha256_bytes(b"license bytes"),
                "llama_image": "repo/model@" + MODEL_IMAGE,
                "defense_image": DEFENSE_IMAGE,
                "model_revision": "untrusted-revision",
                "tokenizer_binding": "UNTRUSTED",
                "input_token_cap": 999999,
            }
            write_json(admission_path, local)
            published = {
                "sha256": "0" * 64,
                "model_sha256": local["model_sha256"],
                "model_license_sha256": local["model_license_sha256"],
                "model_image_digest": MODEL_IMAGE,
                "defense_image_digest": DEFENSE_IMAGE,
            }
            runtime = backend / "src/arena/integration/runtime.py"
            runtime.parent.mkdir(parents=True)
            runtime.write_text('docker("run", "--memory", "2g")', encoding="utf-8")
            facts = gates._read_candidate_artifacts(backend, {"model_filename": "model.gguf"}, published)

            self.assertFalse(facts["local_n05_admission_matches_mem041"])
            self.assertIsNone(facts["candidate_model_revision"])
            self.assertIsNone(facts["candidate_tokenizer_binding"])
            self.assertIsNone(facts["candidate_input_token_cap"])
            self.assertIsNone(facts["candidate_model_image_id"])
            self.assertEqual(facts["candidate_model_lane_memory_limit_bytes"], 2 * 1024**3)

    def test_populated_wrong_image_allowlist_does_not_clear_candidate_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrong_image = "sha256:" + "9" * 64
            _, _, _, loader, hashes = review_inputs(root, approved_images=[wrong_image])
            with patch.object(gates, "_source_hashes", return_value=(hashes, [])), \
                    patch.object(gates, "load_json", side_effect=loader), \
                    patch.object(gates, "_read_candidate_artifacts", return_value=candidate_facts()):
                report = gates.review(root / "backend", root, "1" * 40)

        codes = {item["code"] for item in report["blocking_gates"]}
        self.assertIn("N05_CANDIDATE_IMAGE_NOT_ALLOWLISTED", codes)
        self.assertIn("N05_CANDIDATE_IMAGE_NOT_IN_FULL_LOCK", codes)
        self.assertFalse(report["ready_for_n08_workload"])
        self.assertFalse(report["workload_authorized"])

    def test_empty_image_catalog_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, loader, hashes = review_inputs(root, approved_images=[])
            with patch.object(gates, "_source_hashes", return_value=(hashes, [])), \
                    patch.object(gates, "load_json", side_effect=loader), \
                    patch.object(gates, "_read_candidate_artifacts", return_value=candidate_facts()):
                report = gates.review(root / "backend", root, "1" * 40)

        codes = {item["code"] for item in report["blocking_gates"]}
        self.assertIn("NO_APPROVED_EXECUTION_IMAGES", codes)
        self.assertIn("N05_CANDIDATE_IMAGE_NOT_ALLOWLISTED", codes)

    def test_candidate_image_membership_requires_both_approved_and_locked_digests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, loader, hashes = review_inputs(
                root,
                approved_images=[MODEL_IMAGE, DEFENSE_IMAGE],
                locked_images=[MODEL_IMAGE, DEFENSE_IMAGE],
            )
            with patch.object(gates, "_source_hashes", return_value=(hashes, [])), \
                    patch.object(gates, "load_json", side_effect=loader), \
                    patch.object(gates, "_read_candidate_artifacts", return_value=candidate_facts()):
                report = gates.review(root / "backend", root, "1" * 40)

        codes = {item["code"] for item in report["blocking_gates"]}
        self.assertNotIn("N05_CANDIDATE_IMAGE_NOT_ALLOWLISTED", codes)
        self.assertNotIn("N05_CANDIDATE_IMAGE_NOT_IN_FULL_LOCK", codes)
        self.assertTrue(report["blocking_gates"])

    def test_malformed_nested_catalogs_fail_closed_without_attribute_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, loader, hashes = review_inputs(root, malformed=True)
            with patch.object(gates, "_source_hashes", return_value=(hashes, [])), \
                    patch.object(gates, "load_json", side_effect=loader), \
                    patch.object(gates, "_read_candidate_artifacts", return_value=candidate_facts()):
                report = gates.review(root / "backend", root, "1" * 40)

        codes = {item["code"] for item in report["blocking_gates"]}
        self.assertIn("EXECUTION_IMAGE_ALLOWLIST_MALFORMED", codes)
        self.assertIn("LOCKED_LINUX_IMAGE_IDS_MISSING_OR_INVALID", codes)
        self.assertIn("SYNTHETIC_FIXTURE_CATALOG_MALFORMED", codes)
        self.assertEqual(report["status"], "INCOMPLETE_NOT_READY")

    def test_source_only_report_never_authorizes_n08_or_claims_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, loader, hashes = review_inputs(root)
            with patch.object(gates, "_source_hashes", return_value=(hashes, [])), \
                    patch.object(gates, "load_json", side_effect=loader), \
                    patch.object(gates, "_read_candidate_artifacts", return_value=candidate_facts()):
                report = gates.review(root / "backend", root, "1" * 40)

        self.assertFalse(report["workload_authorized"])
        self.assertFalse(report["ready_for_n08_workload"])
        self.assertFalse(report["n08_acceptance"])
        self.assertFalse(report["n07_acceptance"])
        self.assertFalse(report["arena_acceptance"])
        self.assertIn("CALLER_ASSERTED", report["source_commit_provenance"])
        self.assertIn(
            "Docker and current host/VM capacity were not queried; local N05 model/license bytes were hashed only to compare candidate digests.",
            report["non_blocking_scope_notes"],
        )
        self.assertTrue(report["blocking_gates"])

    def test_output_paths_are_confined_and_existing_evidence_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backend = root / "backend"
            evidence = root / "memory files/hackathon/evidence/review.json"
            self.assertEqual(gates.output_path(evidence, backend, root), evidence.resolve())
            with self.assertRaises(ValueError):
                gates.output_path(root / "frontend/review.json", backend, root)
            evidence.parent.mkdir(parents=True)
            evidence.write_text("original", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                gates.output_path(evidence, backend, root)
            self.assertEqual(evidence.read_text(encoding="utf-8"), "original")

    def test_tool_has_no_process_network_or_docker_imports(self):
        tree = ast.parse(Path(gates.__file__).read_text(encoding="utf-8"))
        prohibited = {"subprocess", "socket", "urllib", "http", "requests", "docker", "httpx"}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertFalse(imported & prohibited)


if __name__ == "__main__":
    unittest.main()
