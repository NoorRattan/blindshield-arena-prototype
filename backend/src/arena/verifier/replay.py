"""Authorized offline decryption, commitment opening verification, and context replay."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional
from uuid import UUID

from ..contracts.common import Context
from ..contracts.crypto import commitment, decrypt_artifact
from ..contracts.evidence import ArtifactAAD
from .rules import VerificationError


def replay_and_decrypt_artifacts(
    artifacts_dir: Path,
    artifact_keys: Dict[str, bytes],
    context: Context,
    classifications: Optional[Dict[str, str]] = None,
) -> Dict[str, bytes]:
    """Decrypt artifacts using authorized 256-bit AES keys and verify AEAD AAD binding."""
    artifacts_dir = artifacts_dir.resolve()
    decrypted_map: Dict[str, bytes] = {}

    for artifact_id_str, key_bytes in artifact_keys.items():
        art_id = UUID(artifact_id_str)
        # Locate encrypted blob
        blob_path = artifacts_dir / f"{str(art_id).lower()}.bin"
        if not blob_path.exists():
            blob_path = artifacts_dir / str(art_id).lower()
        if not blob_path.exists():
            raise VerificationError(
                f"Missing ciphertext for artifact {art_id}", exit_code=1
            )

        blob = blob_path.read_bytes()
        classification = (
            classifications.get(artifact_id_str, "PRIVATE_PAYLOAD")
            if classifications
            else "PRIVATE_PAYLOAD"
        )

        aad = ArtifactAAD(
            domain_id=context.domain_id,
            experiment_id=context.experiment_id,
            epoch=context.epoch,
            schema_version="arena.v2",
            artifact_id=str(art_id),
            classification=classification,  # type: ignore[arg-type]
        )

        try:
            plaintext = decrypt_artifact(blob, key_bytes, aad)
            decrypted_map[str(art_id).lower()] = plaintext
        except Exception as exc:
            raise VerificationError(
                f"Decryption failed for artifact {art_id} (wrong key, corrupted tag, or AAD mismatch): {exc}",
                exit_code=1,
            ) from exc

    return decrypted_map


def verify_commitment_opening(
    expected_commitment: str,
    content: bytes,
    nonce: bytes,
) -> bool:
    """Verify that (content, nonce) matches the expected public hiding commitment."""
    computed = commitment(content, nonce)
    return computed.lower() == expected_commitment.lower()
