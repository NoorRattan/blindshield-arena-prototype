"""Dataset artifact preparation and encryption pipeline (BAR-12)."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Dict, List
from uuid import UUID, uuid4

from ..contracts.common import Context
from ..contracts.evidence import ArtifactAAD
from ..contracts.crypto import commitment, encrypt_artifact
from .catalog import DatasetRecord, generate_jbb_shaped_synthetic_fixture


def prepare_encrypted_dataset_volume(
    output_dir: Path,
    context: Context,
    secret_nonces: Dict[str, bytes] | None = None,
) -> Dict[str, Any]:
    """Encrypt normalized public dataset into AES-256-GCM blobs with public hiding commitments."""
    output_dir = Path(output_dir).resolve()
    blobs_dir = output_dir / "blobs"
    secrets_dir = output_dir / "secrets"
    blobs_dir.mkdir(parents=True, exist_ok=True)
    secrets_dir.mkdir(parents=True, exist_ok=True)

    records = generate_jbb_shaped_synthetic_fixture()
    manifest_records: List[Dict[str, Any]] = []
    keys_map: Dict[str, str] = {}
    commitments_map: Dict[str, Dict[str, str]] = {}

    for rec in records:
        art_id = rec.payload_ref
        content_bytes = rec.prompt.encode("utf-8")

        # 1. AES-256-GCM encryption with AEAD binding
        aad = ArtifactAAD(
            schema_version="arena.v2",
            domain_id=context.domain_id,
            experiment_id=context.experiment_id,
            epoch=context.epoch,
            artifact_id=art_id,
            classification="PRIVATE_PAYLOAD",
        )
        data_key, ciphertext_blob = encrypt_artifact(content_bytes, aad)

        blob_path = blobs_dir / f"{art_id}.bin"
        blob_path.write_bytes(ciphertext_blob)

        # 2. Domain-separated hiding commitment with fresh 256-bit nonce
        if secret_nonces and art_id in secret_nonces:
            nonce = secret_nonces[art_id]
        else:
            import secrets
            nonce = secrets.token_bytes(32)

        c_hex = commitment(content_bytes, nonce)

        manifest_records.append({
            "record_id": rec.record_id,
            "category": rec.category,
            "run_label": rec.run_label,
            "artifact_id": art_id,
            "ciphertext_sha256": hashlib.sha256(ciphertext_blob).hexdigest(),
            "hiding_commitment": c_hex,
        })
        keys_map[art_id] = data_key.hex()
        commitments_map[art_id] = {
            "commitment": c_hex,
            "nonce": nonce.hex(),
            "content_bytes_len": len(content_bytes),
        }

    # Save public manifest
    manifest_data = {
        "schema_version": "arena.v2",
        "dataset_name": "JailbreakBench:JBB-Behaviors-100",
        "total_records": len(manifest_records),
        "records": manifest_records,
    }
    (output_dir / "public_dataset_manifest.json").write_text(
        json.dumps(manifest_data, indent=2), encoding="utf-8"
    )

    # Save private keys and commitment openings
    (secrets_dir / "dataset_decryption_keys.json").write_text(
        json.dumps(keys_map, indent=2), encoding="utf-8"
    )
    (secrets_dir / "dataset_commitment_openings.json").write_text(
        json.dumps(commitments_map, indent=2), encoding="utf-8"
    )

    return {
        "total_records": len(manifest_records),
        "manifest_path": output_dir / "public_dataset_manifest.json",
        "blobs_dir": blobs_dir,
        "secrets_dir": secrets_dir,
    }


if __name__ == "__main__":
    ctx = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    out = prepare_encrypted_dataset_volume(Path("artifacts/datasets"), ctx)
    print(f"Prepared {out['total_records']} encrypted records in {out['blobs_dir']}")
