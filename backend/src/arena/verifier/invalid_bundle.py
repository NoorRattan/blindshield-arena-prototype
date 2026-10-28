"""Ciphertext-only, signed forensic envelope for durably closed INVALID runs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from arena.contracts.common import Context
from arena.contracts.crypto import (
    checkpoint_digest, event_digest, verify, verify_checkpoint,
    turn_message, verify_witness_close, witness_message, validate_chain,
)
from arena.contracts.evidence import (
    Event, SignedCheckpoint, SignedTurnReceipt, SignedWitnessClose,
    SignedWitnessStart,
)
from arena.contracts.jsonwire import load_wire
from arena.recovery.feedback import FeedbackReconciliation, verify_reconciliation
from arena.ports import DependencyUnavailable
from .archive import MAX_TOTAL_UNCOMPRESSED_BYTES, safe_extract_archive
from .rules import VerificationError


GAP_PREFIX = b"arena.invalid-evidence-gap.v2\0"
SCHEMA = "arena.invalid-evidence-bundle.v2"
GAP_SCHEMA = "arena.invalid-evidence-gap.v2"
GAP_CODES = frozenset({
    "TURN_RECEIPT_MISSING", "TURN_RECEIPT_MISMATCH", "FEEDBACK_EVENT_DUPLICATE",
    "TURN_COMMIT_MISSING", "TURN_COMMIT_DUPLICATE",
    "EXECUTION_UNKNOWN", "MODEL_RESULT_MISSING_OR_NOT_OK", "SCORE_RESULT_MISSING_OR_NOT_OK",
    "INPUT_ARTIFACT_MISSING", "RESPONSE_ARTIFACT_MISSING", "ARTIFACT_OPENING_FAILED",
    "COMMITMENT_MISMATCH", "ANCHOR_RECORDS_OMITTED", "ANCHOR_UNAVAILABLE", "ANCHOR_BEHIND", "ANCHOR_AHEAD",
    "ANCHOR_BAD_SIGNATURE", "ANCHOR_EQUIVOCATION", "ANCHOR_PREPARE_UNRESOLVED",
    "QUEUE_BODY_MISSING_OR_MISMATCHED", "CHECKPOINT_MISMATCH", "WITNESS_CLOSE_UNAVAILABLE",
    "PRIOR_INVALIDITY",
})
ARTIFACT_GAP_CODES = frozenset({
    "INPUT_ARTIFACT_MISSING", "RESPONSE_ARTIFACT_MISSING", "ARTIFACT_OPENING_FAILED",
})
PER_TURN_EVENT_GAPS = frozenset({
    "TURN_RECEIPT_MISSING", "FEEDBACK_EVENT_DUPLICATE", "TURN_COMMIT_MISSING",
    "TURN_COMMIT_DUPLICATE", "EXECUTION_UNKNOWN", "MODEL_RESULT_MISSING_OR_NOT_OK",
    "SCORE_RESULT_MISSING_OR_NOT_OK", "INPUT_ARTIFACT_MISSING",
    "RESPONSE_ARTIFACT_MISSING", "QUEUE_BODY_MISSING_OR_MISMATCHED",
})
GAP_FIELDS = frozenset({
    "schema_version", "integrity_status", "domain_id", "experiment_id", "epoch",
    "public_manifest_digest", "checkpoint_digest", "event_count", "final_root",
    "witness_start_digest", "witness_close_digest", "last_verified_anchor_record_digest",
    "bundle_manifest_digest", "gaps", "gap_count", "invalid_export_key_id", "signature",
})
BASE_ALLOWED = frozenset({
    "bundle-manifest.json", "checkpoint.json", "witness_start.json", "witness_close.json",
    "events.jsonl", "turn_receipts.jsonl", "feedback-reconciliations.jsonl",
    "invalid-gap-manifest.json",
})


def _canonical(value, *, newline=False):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return raw + (b"\n" if newline else b"")


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise VerificationError("Duplicate JSON field in INVALID evidence", exit_code=2)
        value[key] = item
    return value


def _member_path(name):
    if (not isinstance(name, str) or not name.isascii() or "\\" in name
            or name.startswith("/") or ":" in name or "\x00" in name):
        return False
    path = PurePosixPath(name)
    return (bool(path.parts) and name == "/".join(path.parts)
            and all(part not in {"", ".", ".."} for part in path.parts))


def _allowed_payload_member(name):
    if name in BASE_ALLOWED - {"bundle-manifest.json", "invalid-gap-manifest.json"}:
        return True
    return (name.startswith("artifacts/") and name.endswith(".bin")
            and re.fullmatch(r"artifacts/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.bin", name) is not None)


def _gap_sort(gap):
    return (gap["gap_code"], gap.get("event_sequence", 0), gap.get("turn_id", ""))


def _validate_gap(gap):
    if not isinstance(gap, dict) or not {"gap_code", "related_members", "known_execution_status"} <= set(gap):
        raise VerificationError("INVALID gap schema rejected", exit_code=2)
    optional = {"event_sequence", "event_digest", "turn_id"}
    if set(gap) - (optional | {"gap_code", "related_members", "known_execution_status"}):
        raise VerificationError("INVALID gap has unknown fields", exit_code=2)
    if (not isinstance(gap["gap_code"], str) or gap["gap_code"] not in GAP_CODES
            or not isinstance(gap["known_execution_status"], str)
            or gap["known_execution_status"] not in {"EXECUTED", "UNKNOWN", "NOT_ESTABLISHED"}):
        raise VerificationError("INVALID gap enum rejected", exit_code=2)
    if (not isinstance(gap["related_members"], list)
            or any(not isinstance(path, str) for path in gap["related_members"])
            or len(gap["related_members"]) != len(set(gap["related_members"]))
            or gap["related_members"] != sorted(gap["related_members"])
            or any(not _member_path(path) for path in gap["related_members"])):
        raise VerificationError("INVALID gap member path rejected", exit_code=2)
    if "event_sequence" in gap and (type(gap["event_sequence"]) is not int or gap["event_sequence"] < 1):
        raise VerificationError("INVALID gap event sequence rejected", exit_code=2)
    if ("event_digest" in gap and (not isinstance(gap["event_digest"], str)
            or len(gap["event_digest"]) != 64
            or any(ch not in "0123456789abcdef" for ch in gap["event_digest"]))):
        raise VerificationError("INVALID gap event digest rejected", exit_code=2)
    if "event_sequence" in gap and "event_digest" not in gap:
        raise VerificationError("INVALID gap event reference lacks digest", exit_code=2)
    if ("turn_id" in gap and (not isinstance(gap["turn_id"], str)
            or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", gap["turn_id"]) is None)):
        raise VerificationError("INVALID gap turn reference rejected", exit_code=2)
    if gap["gap_code"] in PER_TURN_EVENT_GAPS:
        if not {"turn_id", "event_sequence", "event_digest"} <= set(gap):
            raise VerificationError("INVALID per-turn event gap is unbound", exit_code=2)
    if gap["gap_code"] == "TURN_RECEIPT_MISMATCH":
        if "turn_id" not in gap or ("event_digest" in gap and "event_sequence" not in gap):
            raise VerificationError("INVALID receipt-mismatch gap is unbound", exit_code=2)


def export_invalid_evidence_bundle(
    output_path: Path,
    payload_members: dict[str, bytes],
    gaps: list[dict],
    *,
    context: Context,
    public_manifest_digest: str,
    signed_checkpoint: SignedCheckpoint,
    signed_witness_start: SignedWitnessStart,
    signed_witness_close: SignedWitnessClose,
    last_verified_anchor_record_digest: str | None,
    key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    """Write a deterministic archive without replacing a conflicting destination."""
    output_path = Path(output_path).absolute()
    if any(parent.is_symlink() for parent in (output_path, *output_path.parents)):
        raise DependencyUnavailable("INVALID_EXPORT_DESTINATION_UNSAFE")
    if output_path.exists() or output_path.is_symlink():
        raise DependencyUnavailable("INVALID_EXPORT_DESTINATION_CONFLICT")
    if not output_path.parent.is_dir():
        raise DependencyUnavailable("INVALID_EXPORT_DESTINATION_PARENT_MISSING")
    if signed_checkpoint.checkpoint.terminal_marker != "CLOSED":
        raise DependencyUnavailable("INVALID_EXPORT_REQUIRES_TERMINAL_CHECKPOINT")
    if (signed_checkpoint.checkpoint.domain_id, signed_checkpoint.checkpoint.experiment_id,
            signed_checkpoint.checkpoint.epoch) != (context.domain_id, context.experiment_id, context.epoch):
        raise DependencyUnavailable("INVALID_EXPORT_CONTEXT_MISMATCH")
    if not gaps:
        raise DependencyUnavailable("INVALID_EXPORT_GAP_REQUIRED")
    for gap in gaps:
        _validate_gap(gap)
    gaps = sorted(gaps, key=_gap_sort)
    if len({(_gap_sort(gap), gap["gap_code"]) for gap in gaps}) != len(gaps):
        raise DependencyUnavailable("INVALID_EXPORT_DUPLICATE_GAP")

    if any(not _member_path(name) or not _allowed_payload_member(name) for name in payload_members):
        raise DependencyUnavailable("INVALID_EXPORT_MEMBER_PATH_REJECTED")
    if not {"checkpoint.json", "witness_start.json", "witness_close.json", "events.jsonl"} <= set(payload_members):
        raise DependencyUnavailable("INVALID_EXPORT_REQUIRED_MEMBER_MISSING")
    if (sum(len(value) for value in payload_members.values()) > MAX_TOTAL_UNCOMPRESSED_BYTES
            or len(payload_members) > 10000):
        raise DependencyUnavailable("INVALID_EXPORT_RESOURCE_LIMIT")

    entries = [
        {"path": name, "size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
        for name, value in sorted(payload_members.items())
    ]
    bundle_manifest = {"schema_version": SCHEMA, "members": entries}
    bundle_manifest_bytes = _canonical(bundle_manifest, newline=True)
    gap_manifest = {
        "schema_version": GAP_SCHEMA,
        "integrity_status": "INVALID",
        "domain_id": context.domain_id,
        "experiment_id": context.experiment_id,
        "epoch": context.epoch,
        "public_manifest_digest": public_manifest_digest,
        "checkpoint_digest": checkpoint_digest(signed_checkpoint.checkpoint),
        "event_count": sum(bool(line) for line in payload_members["events.jsonl"].splitlines()),
        "final_root": signed_checkpoint.checkpoint.final_root,
        "witness_start_digest": hashlib.sha256(payload_members["witness_start.json"]).hexdigest(),
        "witness_close_digest": hashlib.sha256(payload_members["witness_close.json"]).hexdigest(),
        "last_verified_anchor_record_digest": last_verified_anchor_record_digest,
        "bundle_manifest_digest": hashlib.sha256(bundle_manifest_bytes).hexdigest(),
        "gaps": gaps,
        "gap_count": len(gaps),
        "invalid_export_key_id": key_id,
    }
    gap_manifest["signature"] = key.sign(GAP_PREFIX + _canonical(gap_manifest, newline=True)).hex()
    gap_bytes = _canonical(gap_manifest, newline=True)
    members = dict(payload_members)
    members["bundle-manifest.json"] = bundle_manifest_bytes
    members["invalid-gap-manifest.json"] = gap_bytes

    with tempfile.NamedTemporaryFile(prefix=".invalid-evidence-", suffix=".zip",
                                     dir=output_path.parent, delete=False) as tmp:
        temporary = Path(tmp.name)
    linked = False
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(members.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, data)
        with zipfile.ZipFile(temporary) as archive:
            if sum(item.file_size for item in archive.infolist()) > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise DependencyUnavailable("INVALID_EXPORT_RESOURCE_LIMIT")
        try:
            os.link(temporary, output_path)
            linked = True
        except FileExistsError as exc:
            raise DependencyUnavailable("INVALID_EXPORT_DESTINATION_CONFLICT") from exc
        return output_path
    except Exception:
        if linked:
            output_path.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError("INVALID evidence JSON is malformed", exit_code=2) from exc


def verify_invalid_evidence_bundle(
    archive_path: Path,
    *,
    recorder_key: bytes,
    witness_key: bytes,
    export_key: bytes,
    expected_context: Context,
    expected_manifest_digest: str,
    recorder_key_id: str,
    witness_key_id: str,
    export_key_id: str,
    anchor_key: bytes | None = None,
    recovery_key: bytes | None = None,
    anchor_key_id: str | None = None,
    recovery_key_id: str | None = None,
) -> dict:
    """Verify the forensic envelope and return an incomplete classification, never PASS."""
    authorities = [recorder_key, witness_key, export_key]
    if (anchor_key is None) != (anchor_key_id is None) or (recovery_key is None) != (recovery_key_id is None):
        raise VerificationError("Optional anchor/recovery trust roots must include their key IDs", exit_code=2)
    if anchor_key is not None:
        authorities.append(anchor_key)
    if recovery_key is not None:
        authorities.append(recovery_key)
    if len(set(authorities)) != len(authorities):
        raise VerificationError("Independent evidence authorities must use distinct keys", exit_code=2)
    try:
        for public_key in authorities:
            Ed25519PublicKey.from_public_bytes(public_key)
    except Exception as exc:
        raise VerificationError("Invalid evidence trust root is malformed", exit_code=2) from exc
    with tempfile.TemporaryDirectory(prefix="arena-invalid-evidence-") as directory:
        root = Path(directory)
        try:
            extracted = safe_extract_archive(Path(archive_path), root)
        except Exception as exc:
            raise VerificationError("INVALID evidence archive safety check failed", exit_code=2) from exc
        with zipfile.ZipFile(Path(archive_path), "r") as source:
            infos = source.infolist()
            if any(info.is_dir() for info in infos):
                raise VerificationError("INVALID archive contains undeclared directory entries", exit_code=2)
            names = [info.filename for info in infos]
        if len(names) != len(set(names)) or len(names) != len({name.casefold() for name in names}):
            raise VerificationError("INVALID archive has duplicate member names", exit_code=2)
        files = {name: root.joinpath(*PurePosixPath(name).parts) for name in names}
        if "bundle-manifest.json" not in files or "invalid-gap-manifest.json" not in files:
            raise VerificationError("INVALID evidence envelope is incomplete", exit_code=2)
        manifest = _read_json(files["bundle-manifest.json"])
        if (not isinstance(manifest, dict) or set(manifest) != {"schema_version", "members"}
                or manifest["schema_version"] != SCHEMA or not isinstance(manifest["members"], list)):
            raise VerificationError("INVALID bundle manifest schema rejected", exit_code=2)
        listed = {}
        for entry in manifest["members"]:
            if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
                raise VerificationError("INVALID member manifest schema rejected", exit_code=2)
            name = entry["path"]
            if (not _member_path(name) or not _allowed_payload_member(name) or name in listed
                    or name in {"bundle-manifest.json", "invalid-gap-manifest.json"}):
                raise VerificationError("INVALID member path or duplicate rejected", exit_code=2)
            if (type(entry["size"]) is not int or entry["size"] < 0
                    or not isinstance(entry["sha256"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None):
                raise VerificationError("INVALID member digest or size schema rejected", exit_code=2)
            listed[name] = entry
        if list(listed) != sorted(listed):
            raise VerificationError("INVALID member manifest order rejected", exit_code=2)
        expected_files = set(listed) | {"bundle-manifest.json", "invalid-gap-manifest.json"}
        if set(files) != expected_files:
            raise VerificationError("INVALID archive has missing or extra members", exit_code=2)
        for name, entry in listed.items():
            data = files[name].read_bytes()
            if type(entry["size"]) is not int or entry["size"] != len(data) or entry["sha256"] != hashlib.sha256(data).hexdigest():
                raise VerificationError("INVALID member digest or size mismatch", exit_code=2)

        gap_bytes = files["invalid-gap-manifest.json"].read_bytes()
        gaps = _read_json(files["invalid-gap-manifest.json"])
        if not isinstance(gaps, dict) or set(gaps) != GAP_FIELDS or gaps["schema_version"] != GAP_SCHEMA:
            raise VerificationError("INVALID gap manifest schema rejected", exit_code=2)
        signature = gaps["signature"]
        unsigned = {key: value for key, value in gaps.items() if key != "signature"}
        if (gaps["integrity_status"] != "INVALID" or gaps["invalid_export_key_id"] != export_key_id
                or not verify_ed25519(export_key, signature, GAP_PREFIX + _canonical(unsigned, newline=True))):
            raise VerificationError("INVALID gap manifest signature rejected", exit_code=2)
        if gap_bytes != _canonical(gaps, newline=True):
            raise VerificationError("INVALID gap manifest bytes are not canonical", exit_code=2)
        if (gaps["domain_id"], gaps["experiment_id"], gaps["epoch"]) != (
                expected_context.domain_id, expected_context.experiment_id, expected_context.epoch):
            raise VerificationError("INVALID evidence context mismatch", exit_code=2)
        if (type(gaps["epoch"]) is not int or type(gaps["event_count"]) is not int
                or gaps["event_count"] < 0
                or re.fullmatch(r"[0-9a-f]{64}", gaps["public_manifest_digest"]) is None
                or re.fullmatch(r"[0-9a-f]{64}", gaps["checkpoint_digest"]) is None
                or re.fullmatch(r"[0-9a-f]{64}", gaps["final_root"]) is None
                or re.fullmatch(r"[0-9a-f]{64}", gaps["witness_start_digest"]) is None
                or re.fullmatch(r"[0-9a-f]{64}", gaps["witness_close_digest"]) is None
                or (gaps["last_verified_anchor_record_digest"] is not None
                    and re.fullmatch(r"[0-9a-f]{64}", gaps["last_verified_anchor_record_digest"]) is None)):
            raise VerificationError("INVALID evidence digest or count schema rejected", exit_code=2)
        if (gaps["public_manifest_digest"] != expected_manifest_digest
                or not isinstance(gaps["gaps"], list) or not gaps["gaps"]
                or type(gaps["gap_count"]) is not int
                or gaps["gap_count"] != len(gaps["gaps"])):
            raise VerificationError("INVALID evidence gap binding mismatch", exit_code=2)
        for gap in gaps["gaps"]:
            _validate_gap(gap)
        if (gaps["gaps"] != sorted(gaps["gaps"], key=_gap_sort)
                or len({_canonical(gap) for gap in gaps["gaps"]}) != len(gaps["gaps"])):
            raise VerificationError("INVALID gap order rejected", exit_code=2)
        for gap in gaps["gaps"]:
            if any(path not in listed and not (
                    gap["gap_code"] in ARTIFACT_GAP_CODES
                    and re.fullmatch(
                        r"artifacts/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.bin",
                        path,
                    )
            ) for path in gap["related_members"]):
                raise VerificationError("INVALID gap refers to an absent member", exit_code=2)
        if hashlib.sha256(files["bundle-manifest.json"].read_bytes()).hexdigest() != gaps["bundle_manifest_digest"]:
            raise VerificationError("INVALID bundle manifest digest mismatch", exit_code=2)
        if gaps["last_verified_anchor_record_digest"] is not None:
            raise VerificationError("INVALID bundle claims an anchor digest without anchor records", exit_code=2)
        if not any(gap["gap_code"].startswith("ANCHOR_") for gap in gaps["gaps"]):
            raise VerificationError("INVALID bundle omits the offline anchor-record gap", exit_code=2)

        for required in ("checkpoint.json", "witness_start.json", "witness_close.json", "events.jsonl"):
            if required not in files:
                raise VerificationError("INVALID evidence required member missing", exit_code=2)
        cp = load_wire(SignedCheckpoint, files["checkpoint.json"].read_bytes())
        witness = load_wire(SignedWitnessClose, files["witness_close.json"].read_bytes())
        start = load_wire(SignedWitnessStart, files["witness_start.json"].read_bytes())
        if not verify_checkpoint(cp, recorder_key, expected_context, expected_manifest_digest, recorder_key_id):
            raise VerificationError("INVALID evidence checkpoint signature rejected", exit_code=2)
        if not verify_witness_close(witness, witness_key, cp.checkpoint, expected_context, witness_key_id):
            raise VerificationError("INVALID evidence witness signature rejected", exit_code=2)
        if (gaps["witness_start_digest"] != hashlib.sha256(files["witness_start.json"].read_bytes()).hexdigest()
                or gaps["witness_close_digest"] != hashlib.sha256(files["witness_close.json"].read_bytes()).hexdigest()):
            raise VerificationError("INVALID witness digest binding mismatch", exit_code=2)
        if ((start.receipt.domain_id, start.receipt.experiment_id, start.receipt.epoch,
             start.receipt.public_manifest_digest) != (
                expected_context.domain_id, expected_context.experiment_id,
                expected_context.epoch, expected_manifest_digest)):
            raise VerificationError("INVALID evidence witness start context mismatch", exit_code=2)
        if (start.receipt.witness_key_id != witness_key_id
                or not verify(witness_message(start.receipt), start.signature, witness_key)):
            raise VerificationError("INVALID evidence start signature rejected", exit_code=2)
        events = []
        for line in files["events.jsonl"].read_text(encoding="utf-8").splitlines():
            if line:
                events.append(load_wire(Event, line.encode("utf-8")))
        if len(events) != gaps["event_count"]:
            raise VerificationError("INVALID evidence event count binding mismatch", exit_code=2)
        if ((events and (events[-1].event_type != "CLOSED"
                         or events[-1].outcome_code != "INVALID"))
                or (not events and not any(
                    gap["gap_code"] == "CHECKPOINT_MISMATCH" for gap in gaps["gaps"]
                ))
                or cp.checkpoint.terminal_marker != "CLOSED"):
            raise VerificationError("INVALID evidence lacks an INVALID terminal close", exit_code=2)
        for gap in gaps["gaps"]:
            if "event_sequence" in gap:
                if gap["event_sequence"] > len(events):
                    raise VerificationError("INVALID gap event reference is out of range", exit_code=2)
                referenced = events[gap["event_sequence"] - 1]
                if ("event_digest" in gap and gap["event_digest"] != event_digest(referenced)
                        or "turn_id" in gap and gap["turn_id"] != referenced.turn_id):
                    raise VerificationError("INVALID gap event reference does not match", exit_code=2)
        has_checkpoint_gap = any(gap["gap_code"] == "CHECKPOINT_MISMATCH" for gap in gaps["gaps"])
        start_prefix_matches = (
            1 <= start.receipt.event_count <= len(events)
            and start.receipt.prefix_root == event_digest(events[start.receipt.event_count - 1])
        )
        if not start_prefix_matches and not has_checkpoint_gap:
            raise VerificationError("INVALID evidence witness start prefix mismatch", exit_code=2)
        if cp.checkpoint.final_root != gaps["final_root"] or checkpoint_digest(cp.checkpoint) != gaps["checkpoint_digest"]:
            raise VerificationError("INVALID evidence checkpoint binding mismatch", exit_code=2)
        checkpoint_matches = (
            cp.checkpoint.event_count == len(events)
            and cp.checkpoint.final_root == (event_digest(events[-1]) if events else "0" * 64)
        )
        try:
            validate_chain(tuple(events), cp.checkpoint)
        except Exception:
            if not has_checkpoint_gap:
                raise VerificationError("INVALID evidence chain mismatch is undeclared", exit_code=2)
        else:
            if not checkpoint_matches or has_checkpoint_gap:
                raise VerificationError("INVALID checkpoint-mismatch gap contradicts evidence", exit_code=2)

        if any(gap["gap_code"] == "WITNESS_CLOSE_UNAVAILABLE" for gap in gaps["gaps"]):
            raise VerificationError("INVALID witness-close gap contradicts included signed close", exit_code=2)
        anchor_codes = [gap["gap_code"] for gap in gaps["gaps"] if gap["gap_code"].startswith("ANCHOR_")]
        if anchor_codes != ["ANCHOR_RECORDS_OMITTED"]:
            raise VerificationError("INVALID evidence must declare only the omitted anchor-record gap", exit_code=2)

        feedback = {}
        for event in events:
            if event.event_type == "FEEDBACK_AUTHORIZED":
                feedback.setdefault(event.turn_id, []).append(event)
        signed_receipts = []
        if "turn_receipts.jsonl" in files:
            for line in files["turn_receipts.jsonl"].read_text(encoding="utf-8").splitlines():
                if not line:
                    continue
                try:
                    signed_receipts.append(load_wire(SignedTurnReceipt, line.encode("utf-8")))
                except Exception as exc:
                    raise VerificationError("INVALID evidence receipt is not parseable", exit_code=2) from exc
        recovery_proofs = []
        if "feedback-reconciliations.jsonl" in files:
            for line in files["feedback-reconciliations.jsonl"].read_text(encoding="utf-8").splitlines():
                if not line:
                    continue
                try:
                    recovery_proofs.append(load_wire(FeedbackReconciliation, line.encode("utf-8")))
                except Exception as exc:
                    raise VerificationError("INVALID recovery reconciliation is not parseable", exit_code=2) from exc
        recovery_signature_verified = False
        for proof in recovery_proofs:
            if (proof.domain_id, proof.experiment_id, proof.epoch) != (
                    expected_context.domain_id, expected_context.experiment_id, expected_context.epoch):
                raise VerificationError("INVALID recovery reconciliation context mismatch", exit_code=2)
            if (proof.feedback_event_sequence > len(events)
                    or proof.feedback_event_sequence < 1):
                raise VerificationError("INVALID recovery reconciliation event is absent", exit_code=2)
            feedback_event = events[proof.feedback_event_sequence - 1]
            if (feedback_event.event_type != "FEEDBACK_AUTHORIZED"
                    or feedback_event.turn_id != proof.turn_id
                    or event_digest(feedback_event) != proof.feedback_event_digest
                    or proof.prefix_root != proof.feedback_event_digest
                    or proof.reservation_id != proof.turn_id
                    or proof.queue_job_id != proof.turn_id
                    or (feedback_event.session_id, feedback_event.turn_index) != (
                        proof.session_id, proof.turn_index)
                    or feedback_event.artifact_ciphertext_refs != (
                        proof.input_artifact, proof.response_artifact)):
                raise VerificationError("INVALID recovery reconciliation event binding rejected", exit_code=2)
            related_events = [event for event in events if event.turn_id == proof.turn_id]
            model_events = [event for event in related_events if event.event_type == "MODEL_RESULT"]
            score_events = [event for event in related_events if event.event_type == "SCORE_RESULT"]
            if (len(model_events) != 1 or model_events[0].outcome_code != "OK"
                    or event_digest(model_events[0]) != proof.model_result_digest
                    or len(score_events) != 1 or score_events[0].outcome_code != "OK"
                    or event_digest(score_events[0]) != proof.score_result_digest):
                raise VerificationError("INVALID recovery reconciliation result binding rejected", exit_code=2)
            for ref in (proof.input_artifact, proof.response_artifact):
                entry = listed.get(f"artifacts/{ref.artifact_id}.bin")
                if entry is None or entry["sha256"] != ref.ciphertext_sha256:
                    raise VerificationError("INVALID recovery reconciliation artifact is absent", exit_code=2)
            if recovery_key is not None:
                if proof.recovery_key_id != recovery_key_id or not verify_reconciliation(
                        proof, recovery_key, proof.recovery_authority_id, recovery_key_id):
                    raise VerificationError("INVALID recovery reconciliation signature rejected", exit_code=2)
                recovery_signature_verified = True
        receipts_by_turn = {}
        valid_receipts_by_turn = {}
        for signed in signed_receipts:
            receipt = signed.receipt
            receipts_by_turn.setdefault(receipt.turn_id, []).append(signed)
            matches = feedback.get(receipt.turn_id, [])
            valid = (
                receipt.signer_key_id == recorder_key_id
                and (receipt.domain_id, receipt.experiment_id, receipt.epoch) == (
                    expected_context.domain_id, expected_context.experiment_id,
                    expected_context.epoch)
                and len(matches) == 1
                and (receipt.session_id, receipt.turn_index, receipt.event_count,
                     receipt.prefix_root) == (
                    matches[0].session_id, matches[0].turn_index, matches[0].sequence,
                    event_digest(matches[0]))
                and verify(turn_message(receipt), signed.signature, recorder_key)
            )
            if not valid and not any(
                    gap["gap_code"] == "TURN_RECEIPT_MISMATCH"
                    and gap.get("turn_id") == receipt.turn_id for gap in gaps["gaps"]):
                raise VerificationError("INVALID evidence receipt mismatch gap undeclared", exit_code=2)
            if valid:
                valid_receipts_by_turn.setdefault(receipt.turn_id, []).append(signed)
        committed_by_turn = {}
        for event in events:
            if event.event_type == "TURN_COMMITTED":
                committed_by_turn.setdefault(event.turn_id, []).append(event)
        for turn_id, events_for_turn in feedback.items():
            def has_event_gap(code, event, execution):
                digest = event_digest(event)
                return any(
                    gap["gap_code"] == code
                    and gap.get("turn_id") == turn_id
                    and gap.get("event_sequence") == event.sequence
                    and gap.get("event_digest") == digest
                    and gap["known_execution_status"] == execution
                    for gap in gaps["gaps"]
                )

            related = [event for event in events if event.turn_id == turn_id]
            model_events = [event for event in related if event.event_type == "MODEL_RESULT"]
            score_events = [event for event in related if event.event_type == "SCORE_RESULT"]
            if len(model_events) == 1 and model_events[0].outcome_code == "OK":
                execution = "EXECUTED"
            elif any(event.outcome_code == "UNKNOWN" for event in model_events):
                execution = "UNKNOWN"
            else:
                execution = "NOT_ESTABLISHED"

            for duplicate in events_for_turn[1:]:
                if not has_event_gap("FEEDBACK_EVENT_DUPLICATE", duplicate, execution):
                    raise VerificationError("INVALID evidence duplicate event gap undeclared", exit_code=2)
            commits = committed_by_turn.get(turn_id, [])
            if not commits and not has_event_gap("TURN_COMMIT_MISSING", events_for_turn[0], execution):
                raise VerificationError("INVALID evidence missing turn-commit gap undeclared", exit_code=2)
            for duplicate in commits[1:]:
                if not has_event_gap("TURN_COMMIT_DUPLICATE", duplicate, execution):
                    raise VerificationError("INVALID evidence duplicate turn-commit gap undeclared", exit_code=2)
            receipt_list = receipts_by_turn.get(turn_id, [])
            valid_receipt_list = valid_receipts_by_turn.get(turn_id, [])
            if len(valid_receipt_list) == 0 and not has_event_gap(
                    "TURN_RECEIPT_MISSING", events_for_turn[0], execution):
                raise VerificationError("INVALID evidence missing receipt gap undeclared", exit_code=2)
            if len(receipt_list) > 1 and not any(
                    gap["gap_code"] == "TURN_RECEIPT_MISMATCH"
                    and gap.get("turn_id") == turn_id for gap in gaps["gaps"]):
                raise VerificationError("INVALID evidence duplicate receipt gap undeclared", exit_code=2)
            if len(model_events) != 1 or model_events[0].outcome_code != "OK":
                if not has_event_gap("MODEL_RESULT_MISSING_OR_NOT_OK", events_for_turn[0], execution):
                    raise VerificationError("INVALID evidence model result gap undeclared", exit_code=2)
            if execution == "UNKNOWN" and not has_event_gap("EXECUTION_UNKNOWN", events_for_turn[0], execution):
                raise VerificationError("INVALID evidence unknown execution gap undeclared", exit_code=2)
            if len(score_events) != 1 or score_events[0].outcome_code != "OK":
                if not has_event_gap("SCORE_RESULT_MISSING_OR_NOT_OK", events_for_turn[0], execution):
                    raise VerificationError("INVALID evidence score result gap undeclared", exit_code=2)
            refs_for_feedback = events_for_turn[0].artifact_ciphertext_refs
            if len(refs_for_feedback) < 2:
                code = "INPUT_ARTIFACT_MISSING" if not refs_for_feedback else "RESPONSE_ARTIFACT_MISSING"
                if not has_event_gap(code, events_for_turn[0], execution):
                    raise VerificationError("INVALID evidence feedback artifact gap undeclared", exit_code=2)
            for index, ref in enumerate(refs_for_feedback[:2]):
                member = f"artifacts/{ref.artifact_id}.bin"
                entry = listed.get(member)
                if entry is None or entry["sha256"] != ref.ciphertext_sha256:
                    code = "INPUT_ARTIFACT_MISSING" if index == 0 else "RESPONSE_ARTIFACT_MISSING"
                    if not has_event_gap(code, events_for_turn[0], execution):
                        raise VerificationError("INVALID evidence referenced feedback artifact gap undeclared", exit_code=2)

        for gap in gaps["gaps"]:
            if gap["gap_code"] != "TURN_RECEIPT_MISMATCH":
                continue
            turn_id = gap["turn_id"]
            receipts = receipts_by_turn.get(turn_id, [])
            valid_receipts = valid_receipts_by_turn.get(turn_id, [])
            if not receipts:
                raise VerificationError("INVALID receipt-mismatch gap has no receipt evidence", exit_code=2)
            if len(receipts) == 1 and len(valid_receipts) == 1:
                raise VerificationError("INVALID receipt-mismatch gap contradicts valid receipt", exit_code=2)
            if feedback.get(turn_id) and "event_sequence" not in gap:
                raise VerificationError("INVALID receipt-mismatch gap omits its feedback event", exit_code=2)

        for turn_id, committed_events in committed_by_turn.items():
            committed = committed_events[0]
            related = [event for event in events if event.turn_id == turn_id]
            model_events = [event for event in related if event.event_type == "MODEL_RESULT"]
            score_events = [event for event in related if event.event_type == "SCORE_RESULT"]
            execution = (
                "EXECUTED" if len(model_events) == 1 and model_events[0].outcome_code == "OK"
                else "UNKNOWN" if any(event.outcome_code == "UNKNOWN" for event in model_events)
                else "NOT_ESTABLISHED"
            )
            for duplicate in committed_events[1:]:
                if not any(
                    gap["gap_code"] == "TURN_COMMIT_DUPLICATE"
                    and gap.get("turn_id") == turn_id
                    and gap.get("event_sequence") == duplicate.sequence
                    and gap.get("event_digest") == event_digest(duplicate)
                    and gap["known_execution_status"] == execution
                    for gap in gaps["gaps"]
                ):
                    raise VerificationError("INVALID evidence duplicate turn-commit gap undeclared", exit_code=2)
            if feedback.get(turn_id):
                continue
            def has_commit_gap(code):
                return any(
                    gap["gap_code"] == code
                    and gap.get("turn_id") == turn_id
                    and gap.get("event_sequence") == committed.sequence
                    and gap.get("event_digest") == event_digest(committed)
                    and gap["known_execution_status"] == execution
                    for gap in gaps["gaps"]
                )
            if not has_commit_gap("TURN_RECEIPT_MISSING"):
                raise VerificationError("INVALID evidence missing feedback event gap undeclared", exit_code=2)
            if execution == "UNKNOWN" and not has_commit_gap("EXECUTION_UNKNOWN"):
                raise VerificationError("INVALID evidence unknown execution gap undeclared", exit_code=2)
            if len(model_events) != 1 or model_events[0].outcome_code != "OK":
                if not has_commit_gap("MODEL_RESULT_MISSING_OR_NOT_OK"):
                    raise VerificationError("INVALID evidence model result gap undeclared", exit_code=2)
            if len(score_events) != 1 or score_events[0].outcome_code != "OK":
                if not has_commit_gap("SCORE_RESULT_MISSING_OR_NOT_OK"):
                    raise VerificationError("INVALID evidence score result gap undeclared", exit_code=2)
            if not has_commit_gap("RESPONSE_ARTIFACT_MISSING"):
                raise VerificationError("INVALID evidence response artifact gap undeclared", exit_code=2)

        event_gaps = {
            "TURN_RECEIPT_MISSING", "TURN_RECEIPT_MISMATCH", "FEEDBACK_EVENT_DUPLICATE",
            "TURN_COMMIT_MISSING", "TURN_COMMIT_DUPLICATE",
            "EXECUTION_UNKNOWN", "MODEL_RESULT_MISSING_OR_NOT_OK",
            "SCORE_RESULT_MISSING_OR_NOT_OK", "INPUT_ARTIFACT_MISSING",
            "RESPONSE_ARTIFACT_MISSING", "QUEUE_BODY_MISSING_OR_MISMATCHED",
        }
        for gap in gaps["gaps"]:
            if gap["gap_code"] == "PRIOR_INVALIDITY":
                if "event_sequence" not in gap:
                    raise VerificationError("INVALID prior-invalidity gap lacks event reference", exit_code=2)
                event = events[gap["event_sequence"] - 1]
                if not (
                    event.event_type == "INTEGRITY_VIOLATION"
                    or (event.event_type in {"CLOSE_REQUESTED", "CLOSED"}
                        and event.outcome_code == "INVALID")
                ):
                    raise VerificationError("INVALID prior-invalidity gap contradicts evidence", exit_code=2)
                related = [item for item in events if event.turn_id is not None and item.turn_id == event.turn_id]
                model_events = [item for item in related if item.event_type == "MODEL_RESULT"]
                execution = (
                    "EXECUTED" if len(model_events) == 1 and model_events[0].outcome_code == "OK"
                    else "UNKNOWN" if any(item.outcome_code == "UNKNOWN" for item in model_events)
                    else "NOT_ESTABLISHED"
                )
                if gap["known_execution_status"] != execution:
                    raise VerificationError("INVALID prior-invalidity execution status contradicts evidence", exit_code=2)
                continue
            if gap["gap_code"] not in event_gaps or "event_sequence" not in gap:
                continue
            event = events[gap["event_sequence"] - 1]
            turn_id = gap.get("turn_id")
            if turn_id is None:
                continue
            related = [item for item in events if item.turn_id == turn_id]
            model_events = [item for item in related if item.event_type == "MODEL_RESULT"]
            score_events = [item for item in related if item.event_type == "SCORE_RESULT"]
            execution = (
                "EXECUTED" if len(model_events) == 1 and model_events[0].outcome_code == "OK"
                else "UNKNOWN" if any(item.outcome_code == "UNKNOWN" for item in model_events)
                else "NOT_ESTABLISHED"
            )
            if gap["known_execution_status"] != execution:
                raise VerificationError("INVALID event gap execution status contradicts evidence", exit_code=2)
            if gap["gap_code"] == "TURN_RECEIPT_MISSING" and valid_receipts_by_turn.get(turn_id):
                raise VerificationError("INVALID missing-receipt gap contradicts evidence", exit_code=2)
            if gap["gap_code"] == "FEEDBACK_EVENT_DUPLICATE" and len(feedback.get(turn_id, [])) < 2:
                raise VerificationError("INVALID duplicate-feedback gap contradicts evidence", exit_code=2)
            if gap["gap_code"] in {
                "TURN_RECEIPT_MISSING", "TURN_RECEIPT_MISMATCH",
                "TURN_COMMIT_MISSING", "TURN_COMMIT_DUPLICATE",
                "EXECUTION_UNKNOWN", "MODEL_RESULT_MISSING_OR_NOT_OK",
                "SCORE_RESULT_MISSING_OR_NOT_OK", "INPUT_ARTIFACT_MISSING",
                "RESPONSE_ARTIFACT_MISSING", "QUEUE_BODY_MISSING_OR_MISMATCHED",
            } and (event.turn_id != turn_id
                  or event.event_type not in {"TURN_COMMITTED", "FEEDBACK_AUTHORIZED"}):
                raise VerificationError("INVALID event gap does not identify its turn", exit_code=2)
            if gap["gap_code"] == "TURN_COMMIT_MISSING" and committed_by_turn.get(turn_id):
                raise VerificationError("INVALID missing-turn-commit gap contradicts evidence", exit_code=2)
            if gap["gap_code"] == "TURN_COMMIT_MISSING" and event.event_type != "FEEDBACK_AUTHORIZED":
                raise VerificationError("INVALID missing-turn-commit gap references unrelated event", exit_code=2)
            if gap["gap_code"] == "TURN_COMMIT_DUPLICATE":
                commits = committed_by_turn.get(turn_id, [])
                if len(commits) < 2 or event.event_type != "TURN_COMMITTED" or event.sequence == commits[0].sequence:
                    raise VerificationError("INVALID duplicate-turn-commit gap contradicts evidence", exit_code=2)
            if gap["gap_code"] == "EXECUTION_UNKNOWN" and execution != "UNKNOWN":
                raise VerificationError("INVALID unknown-execution gap contradicts evidence", exit_code=2)
            if gap["gap_code"] == "MODEL_RESULT_MISSING_OR_NOT_OK" and len(model_events) == 1 and model_events[0].outcome_code == "OK":
                raise VerificationError("INVALID model-result gap contradicts evidence", exit_code=2)
            if gap["gap_code"] == "SCORE_RESULT_MISSING_OR_NOT_OK" and len(score_events) == 1 and score_events[0].outcome_code == "OK":
                raise VerificationError("INVALID score-result gap contradicts evidence", exit_code=2)
            if gap["gap_code"] in {"INPUT_ARTIFACT_MISSING", "RESPONSE_ARTIFACT_MISSING"}:
                if event.event_type == "TURN_COMMITTED":
                    if gap["gap_code"] != "RESPONSE_ARTIFACT_MISSING" or feedback.get(turn_id):
                        raise VerificationError("INVALID artifact gap contradicts evidence", exit_code=2)
                    continue
                if event.event_type != "FEEDBACK_AUTHORIZED":
                    raise VerificationError("INVALID artifact gap references unrelated event", exit_code=2)
                index = 0 if gap["gap_code"] == "INPUT_ARTIFACT_MISSING" else 1
                if len(event.artifact_ciphertext_refs) > index:
                    ref = event.artifact_ciphertext_refs[index]
                    entry = listed.get(f"artifacts/{ref.artifact_id}.bin")
                    if entry and entry["sha256"] == ref.ciphertext_sha256:
                        raise VerificationError("INVALID artifact gap contradicts evidence", exit_code=2)

        refs = {ref.artifact_id: ref.ciphertext_sha256 for ref in cp.checkpoint.required_artifacts}
        for gap in gaps["gaps"]:
            for path in gap["related_members"]:
                if path not in listed:
                    artifact_id = Path(path).stem if path.startswith("artifacts/") else None
                    if (gap["gap_code"] not in ARTIFACT_GAP_CODES
                            or artifact_id not in refs
                            or path in listed):
                        raise VerificationError("INVALID missing-artifact gap binding rejected", exit_code=2)
                    if "event_sequence" in gap:
                        event = events[gap["event_sequence"] - 1]
                        if not any(ref.artifact_id == artifact_id
                                   and ref.ciphertext_sha256 == refs[artifact_id]
                                   for ref in event.artifact_ciphertext_refs):
                            raise VerificationError("INVALID missing-artifact event binding rejected", exit_code=2)
        for name, entry in listed.items():
            if name.startswith("artifacts/"):
                artifact_id = Path(name).stem
                if refs.get(artifact_id) != entry["sha256"]:
                    raise VerificationError("INVALID ciphertext member is unbound", exit_code=2)
        missing = set(refs) - {Path(name).stem for name in listed if name.startswith("artifacts/")}
        missing_codes = ARTIFACT_GAP_CODES
        for artifact_id in missing:
            path = f"artifacts/{artifact_id}.bin"
            if not any(gap["gap_code"] in missing_codes and path in gap["related_members"]
                       for gap in gaps["gaps"]):
                raise VerificationError("INVALID evidence omits an undeclared artifact", exit_code=2)
        unverified_claims = {
            "QUEUE_BODY_MISSING_OR_MISMATCHED": "SIGNER_ASSERTION_ONLY",
            "COMMITMENT_MISMATCH": "NOT_INDEPENDENTLY_CHECKED",
            "ARTIFACT_OPENING_FAILED": "CIPHERTEXT_CUSTODY_ONLY_PRIVATE_OPENING_NOT_CHECKED",
        }
        return {
            "status": "AUTHENTIC_INVALID_INCOMPLETE",
            "exit_code": 2,
            "integrity_status": "INVALID",
            "event_count": len(events),
            "final_root": cp.checkpoint.final_root,
            "gap_count": len(gaps["gaps"]),
            "gaps": gaps["gaps"],
            "gap_verification": [
                {
                    "gap_code": gap["gap_code"],
                    "event_sequence": gap.get("event_sequence"),
                    "turn_id": gap.get("turn_id"),
                    "status": unverified_claims.get(gap["gap_code"], "GAP_BINDING_CHECKED"),
                }
                for gap in gaps["gaps"]
            ],
            "participant_release_authorized": False,
            "safety_finding": False,
            "anchor_evidence_included": False,
            "anchor_signature_verified": False,
            "recovery_signature_verified": recovery_signature_verified,
            "recovery_evidence_included": bool(recovery_proofs),
            "recovery_event_binding_verified": bool(recovery_proofs),
            "recovery_anchor_record_verified": False,
            "recovery_commitment_openings_verified": False,
        }


def verify_ed25519(public_key, signature, message):
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(signature), message)
        return True
    except Exception:
        return False
