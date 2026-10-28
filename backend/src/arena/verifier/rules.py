"""Cryptographic, structural, and state transition validation rules for evidence packages."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from ..contracts.common import Context
from ..contracts.crypto import (
    checkpoint_digest,
    event_digest,
    same_context,
    verify_checkpoint,
    verify_witness_close,
    verify,
    witness_message,
)
from ..contracts.evidence import (
    Event,
    SignedCheckpoint,
    SignedWitnessClose,
    SignedWitnessStart,
    SignedTurnReceipt,
)
from .semantics import validate_run_semantics
from ..contracts.jsonwire import load_wire


class VerificationError(Exception):
    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class VerificationResult:
    status: str
    exit_code: int
    message: str
    event_count: int
    final_root: str
    diagnostics: Dict[str, Any]


def validate_raw_epoch_type(data: Any, path_label: str) -> None:
    """Enforce strict integer epoch: rejects boolean, float, string, or None."""
    if isinstance(data, dict):
        if "epoch" in data:
            epoch_val = data["epoch"]
            if (
                isinstance(epoch_val, bool)
                or not isinstance(epoch_val, int)
                or epoch_val < 1
            ):
                raise VerificationError(
                    f"Schema violation in {path_label}: epoch must be strict integer >= 1, got {type(epoch_val).__name__} ({epoch_val})",
                    exit_code=2,
                )
        for k, v in data.items():
            validate_raw_epoch_type(v, f"{path_label}.{k}")
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            validate_raw_epoch_type(item, f"{path_label}[{idx}]")


def verify_evidence_directory(
    bundle_dir: Path,
    pinned_recorder_key: bytes,
    pinned_witness_key: bytes,
    expected_context: Context,
    expected_manifest_digest: str,
    expected_recorder_key_id: str,
    expected_witness_key_id: str,
    *,
    expected_defense_mode: str | None = None,
    expected_broker_actor: str | None = None,
) -> VerificationResult:
    """Verify available public evidence; this bundle format does not carry witness START."""
    bundle_dir = bundle_dir.resolve()
    if pinned_recorder_key == pinned_witness_key:
        raise VerificationError(
            "Recorder and witness require distinct pinned keys", exit_code=2
        )
    if not bundle_dir.is_dir():
        raise VerificationError("Evidence bundle path must be a directory", exit_code=1)
    expected_root_names = {
        "checkpoint.json",
        "witness_close.json",
        "events.jsonl",
        "artifacts",
    }
    has_start = (bundle_dir / "witness_start.json").exists()
    if has_start:
        expected_root_names |= {"witness_start.json", "turn_receipts.jsonl"}
    try:
        actual_root_names = {path.name for path in bundle_dir.iterdir()}
    except OSError as exc:
        raise VerificationError(
            "Evidence bundle directory is unreadable", exit_code=1
        ) from exc
    if actual_root_names != expected_root_names:
        raise VerificationError(
            "Evidence bundle contains missing or unexpected top-level entries",
            exit_code=1,
        )
    cp_file = bundle_dir / "checkpoint.json"
    wit_file = bundle_dir / "witness_close.json"
    events_file = bundle_dir / "events.jsonl"
    artifacts_dir = bundle_dir / "artifacts"

    # 1. File existence checks
    if not cp_file.exists():
        raise VerificationError(
            f"Missing required checkpoint file: {cp_file}", exit_code=1
        )
    if not wit_file.exists():
        raise VerificationError(
            f"Missing required witness close file: {wit_file}", exit_code=1
        )
    if not events_file.exists():
        raise VerificationError(
            f"Missing required events file: {events_file}", exit_code=1
        )
    for path in (cp_file, wit_file, events_file):
        if path.is_symlink() or not path.is_file():
            raise VerificationError(
                "Evidence metadata paths must be regular files", exit_code=1
            )
    if cp_file.stat().st_size > 70_000 or wit_file.stat().st_size > 70_000:
        raise VerificationError(
            "Evidence metadata exceeds the wire size bound", exit_code=2
        )
    if events_file.stat().st_size > 100 * 1024 * 1024:
        raise VerificationError(
            "Event log exceeds the verifier resource bound", exit_code=2
        )

    # 2. Schema and type checks (raw JSON inspection before parsing)
    try:
        cp_bytes = cp_file.read_bytes()
        raw_cp = json.loads(cp_bytes.decode("utf-8", errors="strict"))
        validate_raw_epoch_type(raw_cp, "checkpoint.json")
        wit_bytes = wit_file.read_bytes()
        raw_wit = json.loads(wit_bytes.decode("utf-8", errors="strict"))
        validate_raw_epoch_type(raw_wit, "witness_close.json")
    except json.JSONDecodeError as exc:
        raise VerificationError(
            f"Malformed JSON in bundle metadata: {exc}", exit_code=2
        ) from exc

    # Parse typed structures
    try:
        signed_cp = load_wire(SignedCheckpoint, cp_bytes)
        signed_wit = load_wire(SignedWitnessClose, wit_bytes)
    except Exception as exc:
        raise VerificationError(
            f"Contract model validation failed: {exc}", exit_code=2
        ) from exc

    checkpoint = signed_cp.checkpoint
    witness_receipt = signed_wit.receipt

    # 3. Cryptographic signature check: Recorder Checkpoint
    if not verify_checkpoint(
        signed_cp,
        pinned_recorder_key,
        expected_context,
        expected_manifest_digest,
        expected_recorder_key_id,
    ):
        raise VerificationError(
            "Terminal checkpoint signature verification FAILED (invalid recorder signature or context mismatch)",
            exit_code=1,
        )

    # 4. Cryptographic signature and consensus check: Witness Close
    if witness_receipt.checkpoint_digest != checkpoint_digest(checkpoint):
        raise VerificationError(
            f"Witness conflict detected: witness checkpoint_digest {witness_receipt.checkpoint_digest} != computed {checkpoint_digest(checkpoint)}",
            exit_code=3,
        )
    if witness_receipt.final_root != checkpoint.final_root:
        raise VerificationError(
            f"Witness conflict: final_root mismatch ({witness_receipt.final_root} != {checkpoint.final_root})",
            exit_code=3,
        )
    if witness_receipt.event_count != checkpoint.event_count:
        raise VerificationError(
            f"Witness conflict: event_count mismatch ({witness_receipt.event_count} != {checkpoint.event_count})",
            exit_code=3,
        )

    if not verify_witness_close(
        signed_wit,
        pinned_witness_key,
        checkpoint,
        expected_context,
        expected_witness_key_id,
    ):
        raise VerificationError(
            "Witness close receipt signature verification FAILED",
            exit_code=1,
        )

    # 5. Event hash chain verification
    events: List[Event] = []
    lines = events_file.read_text(encoding="utf-8").splitlines()
    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            line_bytes = line.encode("utf-8", errors="strict")
            raw_ev = json.loads(line_bytes.decode("utf-8", errors="strict"))
            validate_raw_epoch_type(raw_ev, f"events.jsonl:{line_num}")
            ev = load_wire(Event, line_bytes)
            events.append(ev)
        except json.JSONDecodeError as exc:
            raise VerificationError(
                f"JSON syntax error in events.jsonl at line {line_num}: {exc}",
                exit_code=2,
            )
        except Exception as exc:
            raise VerificationError(
                f"Schema violation in events.jsonl at line {line_num}: {exc}",
                exit_code=2,
            )

    if len(events) != checkpoint.event_count:
        raise VerificationError(
            f"Event count mismatch: checkpoint declares {checkpoint.event_count}, found {len(events)} events",
            exit_code=1,
        )

    if not events:
        raise VerificationError("Event chain is empty", exit_code=1)

    # Validate sequence, hash continuity, context, and manifest
    expected_previous = "0" * 64
    for idx, ev in enumerate(events, start=1):
        if ev.sequence != idx:
            raise VerificationError(
                f"Sequence gap detected at index {idx}: event has sequence {ev.sequence}",
                exit_code=1,
            )
        if ev.previous_digest != expected_previous:
            raise VerificationError(
                f"Hash chain broken at sequence {ev.sequence}: previous_digest {ev.previous_digest} != expected {expected_previous}",
                exit_code=1,
            )
        if not same_context(ev, expected_context):
            raise VerificationError(
                f"Context mismatch at sequence {ev.sequence}: event context != expected context",
                exit_code=1,
            )
        if ev.public_manifest_digest != expected_manifest_digest:
            raise VerificationError(
                f"Manifest digest mismatch at sequence {ev.sequence}",
                exit_code=1,
            )
        current_digest = event_digest(ev)
        expected_previous = current_digest

    # Terminal event must be CLOSED
    if events[-1].event_type != "CLOSED":
        raise VerificationError(
            f"Terminal event violation: last event is {events[-1].event_type}, must be CLOSED",
            exit_code=1,
        )

    if expected_previous != checkpoint.final_root:
        raise VerificationError(
            f"Terminal root mismatch: chain computed {expected_previous} != checkpoint {checkpoint.final_root}",
            exit_code=1,
        )

    # 6. Artifact integrity checks
    artifacts_map: Dict[str, str] = {}
    for ev in events:
        for ref in ev.artifact_ciphertext_refs:
            ref_id = str(ref.artifact_id).lower()
            if (
                ref_id in artifacts_map
                and artifacts_map[ref_id] != ref.ciphertext_sha256
            ):
                raise VerificationError(
                    f"Conflicting artifact checksum declared for {ref_id}",
                    exit_code=1,
                )
            artifacts_map[ref_id] = ref.ciphertext_sha256

    checkpoint_artifacts = {
        str(ref.artifact_id).lower(): ref.ciphertext_sha256
        for ref in checkpoint.required_artifacts
    }
    if artifacts_map != checkpoint_artifacts:
        raise VerificationError(
            "Checkpoint artifact set does not exactly match the event-chain artifact set",
            exit_code=1,
        )

    required_names = {f"{artifact_id}.bin" for artifact_id in checkpoint_artifacts}
    if artifacts_dir.exists():
        if artifacts_dir.is_symlink() or not artifacts_dir.is_dir():
            raise VerificationError(
                "Artifact path must be a real directory", exit_code=1
            )
        actual_names: set[str] = set()
        for path in artifacts_dir.iterdir():
            if path.is_symlink() or not path.is_file():
                raise VerificationError(
                    "Unsafe or unexpected artifact entry", exit_code=1
                )
            actual_names.add(path.name)
        if actual_names != required_names:
            raise VerificationError(
                "Artifact directory contains missing or unexpected entries", exit_code=1
            )
    elif required_names:
        raise VerificationError("Missing artifact directory", exit_code=1)

    for ref in checkpoint.required_artifacts:
        ref_id = str(ref.artifact_id).lower()
        # Find artifact file (try <id>.bin or <id>)
        art_path = artifacts_dir / f"{ref_id}.bin"
        if not art_path.exists():
            art_path = artifacts_dir / ref_id
        if not art_path.exists():
            raise VerificationError(
                f"Required artifact file missing from bundle: {ref_id}", exit_code=1
            )

        file_bytes = art_path.read_bytes()
        actual_sha256 = hashlib.sha256(file_bytes).hexdigest().lower()
        if actual_sha256 != ref.ciphertext_sha256.lower():
            raise VerificationError(
                f"Artifact ciphertext checksum tampering detected on {ref_id}: {actual_sha256} != {ref.ciphertext_sha256}",
                exit_code=1,
            )

    invalid_evidence = events[-1].outcome_code == "INVALID" or any(
        event.event_type == "INTEGRITY_VIOLATION"
        or (event.event_type == "MODEL_RESULT" and event.outcome_code == "UNKNOWN")
        for event in events
    )
    if (
        has_start
        and expected_defense_mode is not None
        and expected_broker_actor is not None
    ):
        try:
            start_path, receipts_path = (
                bundle_dir / "witness_start.json",
                bundle_dir / "turn_receipts.jsonl",
            )
            if any(
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > 1_000_000
                for path in (start_path, receipts_path)
            ):
                raise ValueError("Unsafe START/turn metadata")
            signed_start = load_wire(SignedWitnessStart, start_path.read_bytes())
            start = signed_start.receipt
            if (
                not same_context(start, expected_context)
                or start.public_manifest_digest != expected_manifest_digest
                or start.witness_key_id != expected_witness_key_id
                or not verify(
                    witness_message(start), signed_start.signature, pinned_witness_key
                )
            ):
                raise ValueError("Witness START signature/context mismatch")
            turn_receipts = [
                load_wire(SignedTurnReceipt, line.encode())
                for line in receipts_path.read_text(encoding="utf-8").splitlines()
                if line
            ]
            invalid_evidence |= validate_run_semantics(
                events,
                start,
                turn_receipts,
                expected_defense_mode,
                expected_broker_actor,
                pinned_recorder_key,
                expected_recorder_key_id,
            )
        except Exception as exc:
            raise VerificationError(
                "START/turn/semantic verification failed", exit_code=1
            ) from exc
        return VerificationResult(
            status="AUTHENTIC_INVALID" if invalid_evidence else "PASS_PUBLIC_EVIDENCE",
            exit_code=5 if invalid_evidence else 0,
            message="Verified public evidence and N04 mode semantics; model safety and private openings require separate evaluation.",
            event_count=len(events),
            final_root=checkpoint.final_root,
            diagnostics={
                "witness_start_verified": True,
                "turn_semantics_verified": True,
                "integrity": "INVALID" if invalid_evidence else "VALID_WITHIN_PROFILE",
                "artifacts_verified": len(checkpoint.required_artifacts),
                "scope": "N04_PUBLIC_EVIDENCE_ONLY",
            },
        )
    # This bundle/export contract has no witness START receipt. Public checks may
    # succeed, but the required independent start authority is unavailable, so it
    # cannot return a full-verification PASS.
    return VerificationResult(
        status="AUTHENTIC_INVALID_INCOMPLETE"
        if invalid_evidence
        else "INCOMPLETE_START_PROOF",
        exit_code=4 if not invalid_evidence else 5,
        message=(
            "Public signatures, hash chain, and ciphertext integrity are valid; the authentic run is INVALID/UNKNOWN and witness START is unavailable."
            if invalid_evidence
            else "Available public signatures, hash chain, and ciphertext checks are valid; witness START proof is absent, so verification is incomplete."
        ),
        event_count=len(events),
        final_root=checkpoint.final_root,
        diagnostics={
            "domain_id": str(expected_context.domain_id),
            "experiment_id": str(expected_context.experiment_id),
            "epoch": expected_context.epoch,
            "manifest_digest": expected_manifest_digest,
            "artifacts_verified": len(checkpoint.required_artifacts),
            "witness_start_verified": False,
            "integrity": "INVALID" if invalid_evidence else "NOT_ESTABLISHED",
        },
    )
