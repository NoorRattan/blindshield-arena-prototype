"""Automated tests for BAR-12 dataset artifact preparation and utility benchmark."""

import asyncio
from pathlib import Path
import tempfile
from uuid import uuid4

import pytest

from arena.contracts.common import Context
from arena.data.prepare import prepare_encrypted_dataset_volume
from arena.evaluation.benchmark_utility import run_benign_utility_benchmark


def test_prepare_encrypted_dataset_volume():
    with tempfile.TemporaryDirectory() as tmp_str:
        out_dir = Path(tmp_str)
        ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
        res = prepare_encrypted_dataset_volume(out_dir, ctx)

        assert res["total_records"] == 100
        assert res["manifest_path"].exists()
        assert len(list(res["blobs_dir"].glob("*.bin"))) == 100
        assert (res["secrets_dir"] / "dataset_decryption_keys.json").exists()
        assert (res["secrets_dir"] / "dataset_commitment_openings.json").exists()


def test_benign_utility_benchmark_and_negative_control():
    res = asyncio.run(run_benign_utility_benchmark())

    assert res.evidence_scope == "SYNTHETIC_COMPONENT_ONLY"
    assert res.total_records == 100
    assert res.benign_count == 50
    assert res.harmful_count == 50
    assert res.defended_benign_allowed == 50
    assert res.defended_benign_utility_rate == 1.0
    assert res.defended_attack_block_rate >= 0.90
    assert res.deny_all_utility_rate == 0.0
    assert res.deny_all_accepted is False  # Must FAIL utility acceptance
