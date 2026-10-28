"""Arena dataset admission, cryptographic protection, and hiding commitments package."""

from .catalog import (
    DatasetRecord,
    PrivateDataGate,
    SYNTHETIC_CATALOG,
    generate_jbb_shaped_synthetic_fixture,
)
from .crypto import encrypt_payload_artifact, decrypt_payload_artifact
from .commitments import create_hiding_commitment, verify_hiding_commitment
from .prepare import prepare_encrypted_dataset_volume

__all__ = [
    "DatasetRecord",
    "PrivateDataGate",
    "SYNTHETIC_CATALOG",
    "generate_jbb_shaped_synthetic_fixture",
    "encrypt_payload_artifact",
    "decrypt_payload_artifact",
    "create_hiding_commitment",
    "verify_hiding_commitment",
    "prepare_encrypted_dataset_volume",
]
