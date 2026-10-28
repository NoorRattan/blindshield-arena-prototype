"""Canonical ASCII RFC-8785 serialization helpers."""

from __future__ import annotations

from ..contracts.crypto import canonical_bytes


def to_canonical_bytes(obj) -> bytes:
    """Serialize model or dictionary strictly into RFC 8785 canonical ASCII JSON bytes."""
    return canonical_bytes(obj)


def to_canonical_ascii_str(obj) -> str:
    """Serialize strictly to ASCII string."""
    return to_canonical_bytes(obj).decode("ascii")
