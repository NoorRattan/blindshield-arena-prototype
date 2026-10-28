"""Domain-separated hiding commitments for raw prompts and responses."""

from __future__ import annotations

import os
from typing import Optional, Tuple

from ..contracts.crypto import commitment


def create_hiding_commitment(
    content: bytes | str,
    nonce: Optional[bytes] = None,
) -> Tuple[str, bytes]:
    """Create hiding commitment over content using high-entropy 256-bit nonce.
    
    Protects against rainbow-table reconstruction while enabling offline authorized verification.
    Returns (commitment_hex, nonce_bytes).
    """
    if isinstance(content, str):
        content_bytes = content.encode("utf-8")
    else:
        content_bytes = content

    if nonce is None:
        nonce = os.urandom(32)
    elif len(nonce) != 32:
        raise ValueError("Nonce must be strictly 32 bytes")

    commitment_hex = commitment(content_bytes, nonce)
    return commitment_hex, nonce


def verify_hiding_commitment(
    expected_commitment: str,
    content: bytes | str,
    nonce: bytes,
) -> bool:
    """Verify that (content, nonce) opens to the expected commitment."""
    if isinstance(content, str):
        content_bytes = content.encode("utf-8")
    else:
        content_bytes = content

    if len(nonce) != 32:
        return False

    computed = commitment(content_bytes, nonce)
    return computed.lower() == expected_commitment.lower()
