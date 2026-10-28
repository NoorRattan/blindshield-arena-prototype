"""AES-256-GCM payload encryption with AEAD context binding."""

from __future__ import annotations

import hashlib
from typing import Tuple

from ..contracts.common import Context
from ..contracts.crypto import decrypt_artifact, encrypt_artifact
from ..contracts.evidence import ArtifactAAD


def encrypt_payload_artifact(
    plaintext: bytes,
    context: Context,
    artifact_id: str,
    classification: str = "PRIVATE_PAYLOAD",
) -> Tuple[bytes, bytes, str]:
    """Encrypt payload using fresh AES-256-GCM key and AEAD AAD binding.
    
    Returns (key_bytes, ciphertext_blob, ciphertext_sha256).
    """
    aad = ArtifactAAD(
        domain_id=context.domain_id,
        experiment_id=context.experiment_id,
        epoch=context.epoch,
        schema_version="arena.v2",
        artifact_id=artifact_id,
        classification=classification,  # type: ignore[arg-type]
    )
    key, ciphertext_blob = encrypt_artifact(plaintext, aad)
    ciphertext_sha256 = hashlib.sha256(ciphertext_blob).hexdigest()
    return key, ciphertext_blob, ciphertext_sha256


def decrypt_payload_artifact(
    ciphertext_blob: bytes,
    key: bytes,
    context: Context,
    artifact_id: str,
    classification: str = "PRIVATE_PAYLOAD",
) -> bytes:
    """Decrypt payload verifying AES-256-GCM authentication tag and AEAD AAD."""
    aad = ArtifactAAD(
        domain_id=context.domain_id,
        experiment_id=context.experiment_id,
        epoch=context.epoch,
        schema_version="arena.v2",
        artifact_id=artifact_id,
        classification=classification,  # type: ignore[arg-type]
    )
    return decrypt_artifact(ciphertext_blob, key, aad)
