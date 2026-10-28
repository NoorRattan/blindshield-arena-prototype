"""Evidence bundle export utility packaging checkpoint, witness close, events, and artifacts into standard ZIP."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Dict, List
import zipfile

from ..contracts.common import Context
from ..contracts.evidence import (
    Event,
    SignedCheckpoint,
    SignedWitnessClose,
    SignedWitnessStart,
    SignedTurnReceipt,
)
from ..ports import DependencyUnavailable
from .archive import MAX_TOTAL_UNCOMPRESSED_BYTES


_FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _is_symlink_or_reparse_point(path: Path) -> bool:
    """Detect symlinks and Windows junctions without following the path."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & reparse_point)


def _validated_output_path(output_zip_path: Path) -> Path:
    """Return a lexical absolute path after rejecting links and existing targets."""
    output_zip_path = Path(os.path.abspath(Path(output_zip_path)))
    for ancestor in reversed(output_zip_path.parents):
        if _is_symlink_or_reparse_point(ancestor):
            raise DependencyUnavailable(
                "BUNDLE_EXPORT_ERROR: symlink or reparse-point ancestor is not allowed"
            )
    if _is_symlink_or_reparse_point(output_zip_path):
        raise DependencyUnavailable(
            "BUNDLE_EXPORT_ERROR: symlink or reparse-point destination is not allowed"
        )
    if os.path.lexists(output_zip_path):
        raise DependencyUnavailable("BUNDLE_EXPORT_ERROR: destination already exists")
    return output_zip_path


def _zip_info(name: str, *, is_directory: bool = False) -> zipfile.ZipInfo:
    """Build a ZIP entry with stable timestamp, platform, and mode metadata."""
    info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIMESTAMP)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = ((0o40755 if is_directory else 0o100644) << 16)
    if is_directory:
        info.external_attr |= 0x10
    return info


def _write_zip_entry(archive: zipfile.ZipFile, name: str, data: bytes, *, is_directory: bool = False) -> None:
    archive.writestr(
        _zip_info(name, is_directory=is_directory),
        data,
        compress_type=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    )


def _publish_no_clobber(temp_zip: Path, output_zip_path: Path) -> None:
    """Atomically add the completed archive under a new name, never replacing."""
    try:
        os.link(temp_zip, output_zip_path)
    except FileExistsError as exc:
        raise DependencyUnavailable(
            "BUNDLE_EXPORT_ERROR: destination already exists"
        ) from exc
    except OSError as exc:
        raise DependencyUnavailable(
            "BUNDLE_EXPORT_ERROR: no-clobber archive publication failed"
        ) from exc


def export_evidence_bundle(
    output_zip_path: Path,
    signed_checkpoint: SignedCheckpoint,
    signed_witness_close: SignedWitnessClose,
    events: List[Event],
    artifacts: Dict[str, bytes],
    *,
    signed_witness_start: SignedWitnessStart | None = None,
    turn_receipts: tuple[SignedTurnReceipt, ...] = (),
) -> Path:
    """Export complete evidence package into an offline-verifiable ZIP archive.

    Ensures strict containment, sorted JSON, and valid artifact checksums before writing.
    """
    output_zip_path = _validated_output_path(Path(output_zip_path))

    checkpoint = signed_checkpoint.checkpoint

    # 1. Structural preflight check
    if len(events) != checkpoint.event_count:
        raise DependencyUnavailable(
            f"BUNDLE_EXPORT_ERROR: event count mismatch ({len(events)} != {checkpoint.event_count})"
        )
    if not events or events[-1].event_type != "CLOSED":
        raise DependencyUnavailable(
            "BUNDLE_EXPORT_ERROR: terminal event must be CLOSED"
        )

    refs = {
        str(ref.artifact_id).lower(): ref.ciphertext_sha256.lower()
        for ref in checkpoint.required_artifacts
    }
    event_refs: Dict[str, str] = {}
    for event in events:
        for ref in event.artifact_ciphertext_refs:
            artifact_id = str(ref.artifact_id).lower()
            digest = ref.ciphertext_sha256.lower()
            if artifact_id in event_refs and event_refs[artifact_id] != digest:
                raise DependencyUnavailable(
                    "BUNDLE_EXPORT_ERROR: conflicting event artifact digests"
                )
            event_refs[artifact_id] = digest
    normalized_artifacts = {key.lower(): value for key, value in artifacts.items()}
    if refs != event_refs:
        raise DependencyUnavailable(
            "BUNDLE_EXPORT_ERROR: checkpoint and event artifact sets differ"
        )
    missing = set(refs) - set(normalized_artifacts)
    if missing:
        raise DependencyUnavailable(
            f"BUNDLE_EXPORT_ERROR: missing required artifact {sorted(missing)[0]}"
        )
    extras = set(normalized_artifacts) - set(refs)
    if extras:
        raise DependencyUnavailable("BUNDLE_EXPORT_ERROR: unexpected artifact inputs")
    if any(key != key.lower() for key in artifacts):
        raise DependencyUnavailable(
            "BUNDLE_EXPORT_ERROR: artifact IDs must be canonical lowercase UUIDs"
        )
    total_bytes = sum(len(blob) for blob in normalized_artifacts.values())
    metadata_bytes = (
        len(signed_checkpoint.model_dump_json().encode("utf-8"))
        + len(signed_witness_close.model_dump_json().encode("utf-8"))
        + sum(len(event.model_dump_json().encode("utf-8")) + 1 for event in events)
    )
    if signed_witness_start is not None:
        metadata_bytes += len(signed_witness_start.model_dump_json().encode())
        metadata_bytes += (
            sum(len(item.model_dump_json().encode()) + 1 for item in turn_receipts) + 1
        )
    if total_bytes + metadata_bytes > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise DependencyUnavailable(
            "BUNDLE_EXPORT_ERROR: evidence exceeds archive resource bound"
        )

    # 2. Artifact preflight check
    for ref in checkpoint.required_artifacts:
        art_id = str(ref.artifact_id).lower()
        computed_sha = hashlib.sha256(normalized_artifacts[art_id]).hexdigest().lower()
        if computed_sha != ref.ciphertext_sha256.lower():
            raise DependencyUnavailable(
                f"BUNDLE_EXPORT_ERROR: artifact checksum mismatch on {art_id} ({computed_sha} != {ref.ciphertext_sha256})"
            )

    # 3. Create a deterministic archive and publish it without replacing any path.
    output_zip_path.parent.mkdir(parents=True, exist_ok=True)
    output_zip_path = _validated_output_path(output_zip_path)
    with tempfile.NamedTemporaryFile(
        prefix=".arena-bundle-", suffix=".zip", dir=output_zip_path.parent, delete=False
    ) as tmp:
        temp_zip = Path(tmp.name)
    try:
        with zipfile.ZipFile(
            temp_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as zf:
            _write_zip_entry(
                zf, "checkpoint.json",
                signed_checkpoint.model_dump_json(indent=2).encode("utf-8"),
            )
            _write_zip_entry(
                zf, "witness_close.json",
                signed_witness_close.model_dump_json(indent=2).encode("utf-8"),
            )
            # Empty runs still need an explicit artifacts directory.
            _write_zip_entry(zf, "artifacts/", b"", is_directory=True)
            if signed_witness_start is not None:
                _write_zip_entry(
                    zf, "witness_start.json",
                    signed_witness_start.model_dump_json().encode(),
                )
                _write_zip_entry(
                    zf, "turn_receipts.jsonl",
                    (
                        "\n".join(item.model_dump_json() for item in turn_receipts)
                        + "\n"
                    ).encode(),
                )
            events_str = "\n".join([ev.model_dump_json() for ev in events]) + "\n"
            _write_zip_entry(zf, "events.jsonl", events_str.encode("utf-8"))
            for art_id in sorted(normalized_artifacts):
                _write_zip_entry(zf, f"artifacts/{art_id}.bin", normalized_artifacts[art_id])
        with zipfile.ZipFile(temp_zip, "r") as check:
            if (
                sum(item.file_size for item in check.infolist())
                > MAX_TOTAL_UNCOMPRESSED_BYTES
            ):
                raise DependencyUnavailable(
                    "BUNDLE_EXPORT_ERROR: exact archive resource bound exceeded"
                )
        _publish_no_clobber(temp_zip, output_zip_path)
    finally:
        try:
            temp_zip.unlink(missing_ok=True)
        except OSError:
            # A published hard link is already complete; failure to remove the
            # temporary name must not turn success into a misleading failure.
            pass
    return output_zip_path


def export_experiment_bundle(
    recorder,
    signed_checkpoint: SignedCheckpoint,
    signed_witness_close: SignedWitnessClose,
    artifacts_dir: Path,
    output_zip_path: Path,
) -> Path:
    """Export complete experiment evidence from recorder instance and artifacts directory."""
    context = Context(
        domain_id=signed_checkpoint.checkpoint.domain_id,
        experiment_id=signed_checkpoint.checkpoint.experiment_id,
        epoch=signed_checkpoint.checkpoint.epoch,
    )
    events = recorder.get_events(context)
    artifacts: Dict[str, bytes] = {}
    for ref in signed_checkpoint.checkpoint.required_artifacts:
        art_id = str(ref.artifact_id).lower()
        src_path = artifacts_dir / f"{art_id}.bin"
        if not src_path.exists():
            src_path = artifacts_dir / art_id
        if src_path.exists():
            artifacts[art_id] = src_path.read_bytes()

    return export_evidence_bundle(
        output_zip_path=output_zip_path,
        signed_checkpoint=signed_checkpoint,
        signed_witness_close=signed_witness_close,
        events=events,
        artifacts=artifacts,
    )
