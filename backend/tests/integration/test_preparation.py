"""Fresh subset admission and private-output boundaries; no network or Docker used."""

import asyncio
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from arena.integration.cli import run
from arena.integration.runtime import ensure_local_docker
from arena.ports import DependencyUnavailable


def preparation_module():
    path = Path(__file__).resolve().parents[2] / "tools/prepare_n04.py"
    spec = importlib.util.spec_from_file_location("n04_prepare_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_new_public_selection_is_bound_to_its_actual_receipt(tmp_path):
    prepare = preparation_module()
    source = {
        "corpus_source_pins": [
            {
                "dataset": "JailbreakBench/JBB-Behaviors",
                "revision": "a" * 40,
                "sha256": "b" * 64,
                "file": "data/benign-behaviors.csv",
            }
        ]
    }
    receipt = {
        "schema": "arena-corpus-prep.v1",
        "license_basis": "pinned first-party MIT cards inspected; preserve attribution/cards",
        "sources": source["corpus_source_pins"],
        "normalized_artifact_id": "newly-randomized-selection",
    }
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt))
    original = prepare.admit_corpus_receipt(path, source)
    receipt["normalized_artifact_id"] = "another-selection"
    path.write_text(json.dumps(receipt))
    assert prepare.admit_corpus_receipt(path, source) != original
    receipt["sources"][0]["sha256"] = "c" * 64
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="CORPUS_SOURCE_PINS_MISMATCH"):
        prepare.admit_corpus_receipt(
            path,
            {
                "corpus_source_pins": [
                    {
                        "dataset": "JailbreakBench/JBB-Behaviors",
                        "revision": "a" * 40,
                        "sha256": "b" * 64,
                        "file": "data/benign-behaviors.csv",
                    }
                ]
            },
        )


def test_cli_rejects_nonprivate_output_before_creating_any_files(tmp_path):
    destination = tmp_path / "frontend"
    with pytest.raises(
        ValueError, match="N04_PRIVATE_OUTPUT_MUST_STAY_IN_IGNORED_BACKEND_ARTIFACTS"
    ):
        asyncio.run(run(SimpleNamespace(output=destination)))
    assert not destination.exists()


def test_remote_docker_override_is_rejected_without_contacting_it(monkeypatch):
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote.example.invalid:2375")

    def no_docker(*args, **kwargs):
        raise AssertionError("Must not contact remote daemon")

    monkeypatch.setattr("arena.integration.runtime.docker", no_docker)
    with pytest.raises(
        DependencyUnavailable, match="N04_REQUIRES_LOCAL_DOCKER_ENDPOINT"
    ):
        ensure_local_docker()
