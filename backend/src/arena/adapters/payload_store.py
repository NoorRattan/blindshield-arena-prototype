"""ResolvedPayload store implementations for admitted datasets and synthetic fixtures."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Dict, Optional
from uuid import UUID

from ..contracts.api import PayloadProvenance, ResolvedPayload
from ..contracts.common import Uuid
from ..contracts.jsonwire import load_wire
from ..ports import DependencyUnavailable

UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class InMemoryPayloadStore:
    """In-memory store for registered ResolvedPayload records."""

    def __init__(self) -> None:
        self._store: Dict[str, ResolvedPayload] = {}

    def register(self, payload: ResolvedPayload) -> None:
        """Register a valid payload."""
        ref_str = str(payload.payload_ref).lower()
        self._store[ref_str] = payload

    async def resolve(self, payload_ref: Uuid) -> ResolvedPayload:
        """Resolve a payload by UUID ref, failing closed if missing."""
        ref_str = str(payload_ref).lower()
        if not UUID_REGEX.match(ref_str):
            raise DependencyUnavailable("INVALID_PAYLOAD_REF")
        if ref_str not in self._store:
            raise DependencyUnavailable("PAYLOAD_NOT_FOUND")
        return self._store[ref_str]

    def __len__(self) -> int:
        return len(self._store)


class DirectoryPayloadStore:
    """Plaintext development-fixture store, restricted to SYNTHETIC_MOCK payloads.
    
    Rejects any path traversal, non-UUID references, and arbitrary file access.
    """

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir.resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def _safe_path_for_ref(self, payload_ref: Uuid) -> Path:
        ref_str = str(payload_ref).lower()
        if not UUID_REGEX.match(ref_str):
            raise DependencyUnavailable("INVALID_PAYLOAD_REF")
        # Ensure no path separators or traversal
        if "/" in ref_str or "\\" in ref_str or ".." in ref_str:
            raise DependencyUnavailable("PATH_TRAVERSAL_REJECTED")
        target_path = (self.root_dir / f"{ref_str}.json").resolve()
        if not target_path.is_relative_to(self.root_dir):
            raise DependencyUnavailable("PATH_TRAVERSAL_REJECTED")
        return target_path

    def save(self, payload: ResolvedPayload) -> Path:
        """Persist a synthetic fixture; admitted or private inputs need encrypted custody."""
        if payload.provenance.run_label != "SYNTHETIC_MOCK":
            raise DependencyUnavailable("PLAINTEXT_STORE_SYNTHETIC_ONLY")
        target_path = self._safe_path_for_ref(payload.payload_ref)
        target_path.write_text(payload.model_dump_json(indent=2), encoding="utf-8")
        return target_path

    async def resolve(self, payload_ref: Uuid) -> ResolvedPayload:
        """Resolve payload from disk, verifying integrity and schema."""
        target_path = self._safe_path_for_ref(payload_ref)
        if not target_path.exists() or not target_path.is_file():
            raise DependencyUnavailable("PAYLOAD_NOT_FOUND")
        try:
            payload = load_wire(ResolvedPayload, target_path.read_bytes())
            if payload.provenance.run_label != "SYNTHETIC_MOCK":
                raise DependencyUnavailable("PLAINTEXT_STORE_SYNTHETIC_ONLY")
            # Recheck UUID identity matches exactly
            if str(payload.payload_ref).lower() != str(payload_ref).lower():
                raise DependencyUnavailable("PAYLOAD_IDENTITY_MISMATCH")
            return payload
        except Exception as exc:
            if isinstance(exc, DependencyUnavailable):
                raise
            raise DependencyUnavailable(f"PAYLOAD_CORRUPT: {exc}") from exc
