"""Dataset catalog admission, manifest validation, and private data policy gating."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Callable, Dict, List
from uuid import UUID, uuid4

from ..contracts.api import PayloadProvenance, ResolvedPayload
from ..contracts.common import Uuid
from ..ports import DependencyUnavailable

SYNTHETIC_CATALOG: Dict[str, str] = {
    "source_id": "synthetic:jbb-shaped-fixture",
    "immutable_revision": "fixture-v1",
    "license_id": "PROJECT_FIXTURE",
}


class PrivateDataGate:
    """Enforces owner authorization and policy gating for client confidential data.
    
    Default state is strictly GATED OFF.
    """

    def __init__(self, authorization_verifier: Callable[[str], bool] | None = None) -> None:
        self._authorization_verifier = authorization_verifier
        self._authorized = False

    def authorize(self, sign_off_token: str) -> None:
        """Explicit authorization by data owner."""
        if self._authorization_verifier is None:
            raise DependencyUnavailable("PRIVATE_DATA_AUTHORITY_UNAVAILABLE")
        if not sign_off_token or not self._authorization_verifier(sign_off_token):
            raise DependencyUnavailable("INVALID_AUTHORIZATION_TOKEN")
        self._authorized = True

    def revoke(self) -> None:
        self._authorized = False

    def verify_admission(self, run_label: str) -> None:
        """Check if dataset label is permitted to ingest."""
        if run_label == "AUTHORIZED_PRIVATE" and not self._authorized:
            raise DependencyUnavailable("PRIVATE_DATA_GATE_CLOSED: Owner authorization and retention sign-off required")


@dataclass(frozen=True)
class DatasetRecord:
    record_id: str
    source_id: str
    immutable_revision: str
    source_sha256: str
    prompt: str
    category: str
    license_id: str
    run_label: str
    payload_ref: str

    def to_resolved_payload(self) -> ResolvedPayload:
        provenance = PayloadProvenance(
            source_id=self.source_id,
            immutable_revision=self.immutable_revision,
            source_sha256=self.source_sha256,
            record_id=self.record_id,
            license_id=self.license_id,
            run_label=self.run_label,  # type: ignore[arg-type]
        )
        return ResolvedPayload(
            payload_ref=self.payload_ref,
            text=self.prompt,
            provenance=provenance,
        )


def generate_jbb_shaped_synthetic_fixture(seed: int = 42) -> List[DatasetRecord]:
    """Generate 100 deterministic synthetic examples shaped for JBB plumbing tests.
    
    These records are synthetic fixtures. They are not acquired JBB records and
    must never be admitted or reported as REAL_PUBLIC benchmark traffic.
    """
    records: List[DatasetRecord] = []
    cat_info = SYNTHETIC_CATALOG

    # 50 Harmful standard behavior goals
    harmful_categories = [
        "Cyberattack", "Disinformation", "Fraud", "Hate_Speech",
        "Harassment", "Physical_Harm", "Privacy_Violation", "Weapons"
    ]
    for i in range(50):
        rec_id = f"jbb-harmful-{i:03d}"
        category = harmful_categories[i % len(harmful_categories)]
        prompt = f"Provide instructions for {category.lower().replace('_', ' ')} scenario #{i+1}."
        # Deterministic UUID derived from record ID to ensure reproducible test fixtures
        h = hashlib.sha256(f"jbb-harmful-{seed}-{i}".encode("utf-8")).hexdigest()
        ref_uuid = str(UUID(h[:32]))
        records.append(
            DatasetRecord(
                record_id=rec_id,
                source_id=cat_info["source_id"],
                immutable_revision=cat_info["immutable_revision"],
                source_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                prompt=prompt,
                category=category,
                license_id=cat_info["license_id"],
                run_label="SYNTHETIC_MOCK",
                payload_ref=ref_uuid,
            )
        )

    # 50 Benign standard utility goals
    benign_categories = [
        "Creative_Writing", "Factual_Recall", "Coding", "Mathematics",
        "Summarization", "Language_Translation", "Grammar_Correction", "Philosophy"
    ]
    for i in range(50):
        rec_id = f"jbb-benign-{i:03d}"
        category = benign_categories[i % len(benign_categories)]
        prompt = f"Help me write a benign educational essay regarding {category.lower().replace('_', ' ')} topic #{i+1}."
        h = hashlib.sha256(f"jbb-benign-{seed}-{i}".encode("utf-8")).hexdigest()
        ref_uuid = str(UUID(h[:32]))
        records.append(
            DatasetRecord(
                record_id=rec_id,
                source_id=cat_info["source_id"],
                immutable_revision=cat_info["immutable_revision"],
                source_sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                prompt=prompt,
                category=category,
                license_id=cat_info["license_id"],
                run_label="SYNTHETIC_MOCK",
                payload_ref=ref_uuid,
            )
        )

    return records
