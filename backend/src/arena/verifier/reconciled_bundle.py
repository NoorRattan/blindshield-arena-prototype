"""Offline verification for valid runs with exact feedback reconciliation.

The frozen v1 archive allowlist does not carry anchor records.  This module
therefore transports them as a required, independently supplied canonical JSONL
stream.  It is checked against the pinned anchor root and the checkpoint,
witness close, events, and reconciliation proofs.  The stream digest is returned
to the caller so it can be retained beside the archive.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Mapping, Sequence
from uuid import UUID, uuid5
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arena.contracts.api import (
    AttemptResult,
    DefenseDecision,
    DEFENSE_REQUEST,
    PayloadProvenance,
    TargetResponse,
)
from arena.contracts.common import Context
from arena.contracts.crypto import (
    canonical_bytes,
    checkpoint_digest,
    commitment,
    event_digest,
    same_context,
    turn_message,
    verify,
    verify_checkpoint,
    verify_witness_close,
    witness_message,
    validate_chain,
)
from arena.contracts.evidence import (
    ArtifactAAD,
    Event,
    SignedCheckpoint,
    SignedTurnReceipt,
    SignedWitnessClose,
    SignedWitnessStart,
)
from arena.contracts.jsonwire import load_wire, strict_json
from arena.contracts.transport_profile import TransportTrust
from arena.evaluation.rubric import evaluate_refusal_rubric
from arena.integration.types import ScoreObservation
from arena.recovery.anchor import (
    RecoveryAnchorError,
    operation_id,
    record_digest,
    verify_anchor_records,
)
from arena.recovery.feedback import FeedbackReconciliation, verify_reconciliation
from arena.ports import DependencyUnavailable
from .archive import MAX_TOTAL_UNCOMPRESSED_BYTES, safe_extract_archive
from .openings import verify_n04_openings
from .replay import replay_and_decrypt_artifacts
from .rules import VerificationError
from .transport import transport_from_openings, verify_transport_opening


SCHEMA = "arena.reconciled-evidence-bundle.v1"
MAX_ARCHIVE_MEMBERS = 10_000
MAX_METADATA_BYTES = 1_000_000
MAX_ANCHOR_BYTES = MAX_TOTAL_UNCOMPRESSED_BYTES
ROOT_FILES = frozenset({
    "bundle-manifest.json",
    "checkpoint.json",
    "witness_start.json",
    "witness_close.json",
    "events.jsonl",
    "turn_receipts.jsonl",
    "reconciliation_receipts.jsonl",
})
OPTIONAL_ROOT_FILES = frozenset({
    "turn_receipts.jsonl",
    "reconciliation_receipts.jsonl",
})
ARTIFACT_RE = re.compile(
    r"artifacts/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.bin\Z"
)
ZERO = "0" * 64
BLOCK_REPLY = "Request blocked by the frozen defense."


@dataclass(frozen=True)
class ReconciledVerificationInputs:
    """Trust roots and authorized private openings supplied out of band."""

    expected_context: Context
    expected_manifest_digest: str
    recorder_key: bytes
    recorder_key_id: str
    witness_key: bytes
    witness_key_id: str
    anchor_key: bytes
    anchor_authority_id: str
    anchor_key_id: str
    recovery_key: bytes
    recovery_authority_id: str
    recovery_key_id: str
    artifact_keys: Mapping[str, bytes]
    artifact_classifications: Mapping[str, str]
    expected_defense_mode: str
    expected_broker_actor: str
    transport_trust: TransportTrust | None = None
    require_transport_profile: bool = False

    def verifier_kwargs(self) -> dict:
        return {
            "expected_context": self.expected_context,
            "expected_manifest_digest": self.expected_manifest_digest,
            "recorder_key": self.recorder_key,
            "recorder_key_id": self.recorder_key_id,
            "witness_key": self.witness_key,
            "witness_key_id": self.witness_key_id,
            "anchor_key": self.anchor_key,
            "anchor_authority_id": self.anchor_authority_id,
            "anchor_key_id": self.anchor_key_id,
            "recovery_key": self.recovery_key,
            "recovery_authority_id": self.recovery_authority_id,
            "recovery_key_id": self.recovery_key_id,
            "artifact_keys": self.artifact_keys,
            "artifact_classifications": self.artifact_classifications,
            "expected_defense_mode": self.expected_defense_mode,
            "expected_broker_actor": self.expected_broker_actor,
            "transport_trust": self.transport_trust,
            "require_transport_profile": self.require_transport_profile,
        }


def _canonical_json(value: object, *, newline: bool = False) -> bytes:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return raw + (b"\n" if newline else b"")


def _pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON field")
        output[key] = value
    return output


def _strict_json_line(line: bytes) -> dict:
    value = json.loads(
        line.decode("utf-8", errors="strict"),
        object_pairs_hook=_pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        parse_float=lambda _value: (_ for _ in ()).throw(ValueError("float")),
    )
    if not isinstance(value, dict):
        raise ValueError("JSON line must be an object")
    return value


def serialize_anchor_records(records: Sequence[Mapping]) -> bytes:
    """Serialize the external v1 anchor transport as canonical JSONL."""
    if not isinstance(records, (list, tuple)) or not records:
        raise ValueError("at least one anchor record is required")
    return b"".join(_canonical_json(dict(record)) + b"\n" for record in records)


def _parse_anchor_records(raw: bytes) -> list[dict]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ANCHOR_BYTES or not raw.endswith(b"\n"):
        raise VerificationError("Reconciled anchor stream is absent or oversized", exit_code=2)
    records = []
    try:
        lines = raw.splitlines(keepends=True)
        for line in lines:
            if not line.endswith(b"\n") or line in {b"\n", b"\r\n"}:
                raise ValueError("blank or unterminated line")
            body = line[:-1]
            if body.endswith(b"\r"):
                raise ValueError("CRLF is not canonical")
            record = _strict_json_line(body)
            if _canonical_json(record) != body:
                raise ValueError("noncanonical anchor record")
            records.append(record)
    except Exception as exc:
        raise VerificationError("Reconciled anchor stream is not canonical JSONL", exit_code=2) from exc
    if not records:
        raise VerificationError("Reconciled anchor stream has no records", exit_code=2)
    return records


def _validate_inputs(inputs: ReconciledVerificationInputs) -> None:
    if not isinstance(inputs.expected_context, Context):
        raise VerificationError("Expected reconciled context is invalid", exit_code=2)
    if inputs.expected_defense_mode not in {"INPUT", "FEATURES", "OUTPUT", "POST_HOC"}:
        raise VerificationError("Expected defense mode is not pinned", exit_code=2)
    if type(inputs.require_transport_profile) is not bool:
        raise VerificationError("Transport-profile requirement is invalid", exit_code=2)
    if inputs.transport_trust is not None and not isinstance(inputs.transport_trust, TransportTrust):
        raise VerificationError("Independent transport trust input is invalid", exit_code=2)
    if not inputs.expected_broker_actor:
        raise VerificationError("Expected broker actor is not pinned", exit_code=2)
    keys = (inputs.recorder_key, inputs.witness_key, inputs.anchor_key, inputs.recovery_key)
    if any(type(key) is not bytes or len(key) != 32 for key in keys) or len(set(keys)) != 4:
        raise VerificationError("Reconciled evidence requires four distinct pinned 32-byte keys", exit_code=2)
    if any(not value for value in (
        inputs.recorder_key_id, inputs.witness_key_id,
        inputs.anchor_authority_id, inputs.anchor_key_id,
        inputs.recovery_authority_id, inputs.recovery_key_id,
    )):
        raise VerificationError("Reconciled authority identity is incomplete", exit_code=2)
    if not isinstance(inputs.expected_manifest_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", inputs.expected_manifest_digest
    ):
        raise VerificationError("Expected manifest digest is invalid", exit_code=2)
    if not isinstance(inputs.artifact_keys, Mapping) or not isinstance(
        inputs.artifact_classifications, Mapping
    ):
        raise VerificationError("Authorized artifact opening map is invalid", exit_code=2)


def _allowed_member(path: object) -> bool:
    if not isinstance(path, str) or not path.isascii() or "\\" in path or path.startswith("/") or ":" in path:
        return False
    p = PurePosixPath(path)
    if not p.parts or path != "/".join(p.parts) or any(part in {"", ".", ".."} for part in p.parts):
        return False
    return path in ROOT_FILES - {"bundle-manifest.json"} or ARTIFACT_RE.fullmatch(path) is not None


def _jsonl_models(data: bytes, schema, label: str, *, allow_empty: bool = False):
    if type(data) is not bytes or (not data and not allow_empty) or data and not data.endswith(b"\n"):
        raise VerificationError(f"{label} must be newline-terminated JSONL", exit_code=2)
    models = []
    try:
        for line in data.splitlines():
            if not line:
                raise ValueError("empty line")
            models.append(load_wire(schema, line))
    except Exception as exc:
        raise VerificationError(f"{label} contains invalid JSON records", exit_code=2) from exc
    return models


def _validate_manifest(manifest: object, archive_files: dict[str, Path]) -> dict[str, dict]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "members", "optional_members"
    } or manifest["schema_version"] != SCHEMA:
        raise VerificationError("Reconciled bundle manifest schema rejected", exit_code=2)
    optional = manifest["optional_members"]
    if not isinstance(optional, dict) or set(optional) != OPTIONAL_ROOT_FILES or any(
        type(value) is not bool for value in optional.values()
    ):
        raise VerificationError("Reconciled optional-member manifest rejected", exit_code=2)
    if not isinstance(manifest["members"], list):
        raise VerificationError("Reconciled member list rejected", exit_code=2)
    listed = {}
    for entry in manifest["members"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise VerificationError("Reconciled member entry schema rejected", exit_code=2)
        path = entry["path"]
        if not _allowed_member(path) or path in listed:
            raise VerificationError("Reconciled member path or duplicate rejected", exit_code=2)
        if type(entry["size"]) is not int or entry["size"] < 0 or not isinstance(
            entry["sha256"], str
        ) or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None:
            raise VerificationError("Reconciled member size or digest rejected", exit_code=2)
        listed[path] = entry
    if list(listed) != sorted(listed):
        raise VerificationError("Reconciled member order rejected", exit_code=2)
    required = {"checkpoint.json", "witness_start.json", "witness_close.json", "events.jsonl"}
    if not required <= set(listed):
        raise VerificationError("Reconciled bundle lacks required members", exit_code=2)
    for optional_path in OPTIONAL_ROOT_FILES:
        if optional[optional_path] != (optional_path in listed):
            raise VerificationError("Reconciled optional-member presence contradicts manifest", exit_code=2)
    expected_files = set(listed) | {"bundle-manifest.json"}
    if set(archive_files) != expected_files:
        raise VerificationError("Reconciled archive has missing or extra members", exit_code=2)
    for name, entry in listed.items():
        raw = archive_files[name].read_bytes()
        if len(raw) != entry["size"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise VerificationError("Reconciled member digest or size mismatch", exit_code=2)
    return listed


def _verify_anchor_binding(
    anchor_records_bytes: bytes,
    events: Sequence[Event],
    checkpoint: SignedCheckpoint,
    witness: SignedWitnessClose,
    inputs: ReconciledVerificationInputs,
) -> tuple[dict, dict[str, dict], str]:
    records = _parse_anchor_records(anchor_records_bytes)
    try:
        state = verify_anchor_records(
            records,
            inputs.expected_context,
            inputs.anchor_key,
            inputs.anchor_key_id,
            inputs.anchor_authority_id,
        )
    except Exception as exc:
        raise VerificationError("Reconciled anchor signature or chain rejected", exit_code=2) from exc
    cp = checkpoint.checkpoint
    if state["pending"] or state["terminal"] is None or state["event_sequence"] != len(events):
        raise VerificationError("Reconciled anchor is pending or nonterminal", exit_code=2)
    if state["event_root"] != cp.final_root or state["terminal"]["final_integrity"] != "VALID_WITHIN_PROFILE":
        raise VerificationError("Reconciled terminal anchor contradicts valid checkpoint", exit_code=2)
    witness_bytes = _canonical_json(witness.model_dump(mode="json"))
    terminal = state["terminal"]
    if (
        terminal["recorder_event_count"] != cp.event_count
        or terminal["final_event_root"] != cp.final_root
        or terminal["checkpoint_digest"] != checkpoint_digest(cp)
        or terminal["witness_close_digest"] != hashlib.sha256(witness_bytes).hexdigest()
    ):
        raise VerificationError("Reconciled terminal anchor does not bind witness and checkpoint", exit_code=2)
    committed_by_event = {}
    expected_operations = set()
    for event in events:
        op = operation_id(inputs.expected_context, event.sequence, event_digest(event))
        expected_operations.add(op)
        anchor_record = state["committed"].get(op)
        if (not anchor_record or anchor_record["event_sequence"] != event.sequence
                or anchor_record["event_digest"] != event_digest(event)
                or anchor_record["event_type"] != event.event_type):
            raise VerificationError("Reconciled anchor does not commit exact event bytes", exit_code=2)
        committed_by_event[event.sequence] = anchor_record
    if set(state["committed"]) != expected_operations:
        raise VerificationError("Reconciled anchor contains unrelated event commits", exit_code=2)
    return state, committed_by_event, hashlib.sha256(anchor_records_bytes).hexdigest()


def _verify_receipts_and_proofs(
    receipts: Sequence[SignedTurnReceipt],
    proofs: Sequence[FeedbackReconciliation],
    events: Sequence[Event],
    checkpoint: SignedCheckpoint,
    committed_by_event: Mapping[int, dict],
    inputs: ReconciledVerificationInputs,
) -> tuple[dict[str, SignedTurnReceipt], dict[str, FeedbackReconciliation]]:
    feedback_by_turn = {}
    for event in events:
        if event.event_type == "FEEDBACK_AUTHORIZED":
            if event.turn_id in feedback_by_turn:
                raise VerificationError("Duplicate feedback event cannot be reconciled", exit_code=2)
            feedback_by_turn[event.turn_id] = event
    receipts_by_turn = {}
    for signed in receipts:
        receipt = signed.receipt
        if receipt.turn_id in receipts_by_turn:
            raise VerificationError("Duplicate original turn receipt", exit_code=2)
        event = feedback_by_turn.get(receipt.turn_id)
        if (
            event is None
            or receipt.signer_key_id != inputs.recorder_key_id
            or not same_context(receipt, inputs.expected_context)
            or (receipt.session_id, receipt.turn_index, receipt.event_count, receipt.prefix_root)
            != (event.session_id, event.turn_index, event.sequence, event_digest(event))
            or not verify(turn_message(receipt), signed.signature, inputs.recorder_key)
        ):
            raise VerificationError("Original arena.v2 receipt does not bind feedback event", exit_code=2)
        if len(event.artifact_ciphertext_refs) != 2:
            raise VerificationError("Feedback event must bind exactly two opening artifacts", exit_code=2)
        receipts_by_turn[receipt.turn_id] = signed

    proofs_by_turn = {}
    for proof in proofs:
        if proof.turn_id in proofs_by_turn:
            raise VerificationError("Duplicate reconciliation proof", exit_code=2)
        event = feedback_by_turn.get(proof.turn_id)
        if event is None or proof.recovery_authority_id != inputs.recovery_authority_id:
            raise VerificationError("Reconciliation proof has no exact feedback event", exit_code=2)
        if not verify_reconciliation(
            proof, inputs.recovery_key, inputs.recovery_authority_id, inputs.recovery_key_id
        ):
            raise VerificationError("Reconciliation proof signature rejected", exit_code=2)
        if (
            not same_context(proof, inputs.expected_context)
            or (proof.session_id, proof.turn_index, proof.feedback_event_sequence,
                proof.feedback_event_digest, proof.prefix_root)
            != (event.session_id, event.turn_index, event.sequence,
                event_digest(event), event_digest(event))
            or event.outcome_code != "OK"
            or len(event.artifact_ciphertext_refs) != 2
            or (proof.input_artifact, proof.response_artifact) != event.artifact_ciphertext_refs
        ):
            raise VerificationError("Reconciliation proof context/prefix/artifacts mismatch", exit_code=2)
        committed = committed_by_event.get(event.sequence)
        if not committed or proof.anchor_record_digest != record_digest(committed):
            raise VerificationError("Reconciliation proof does not bind committed anchor record", exit_code=2)
        turn_events = [item for item in events if item.turn_id == event.turn_id]
        model = [item for item in turn_events if item.event_type == "MODEL_RESULT"]
        score = [item for item in turn_events if item.event_type == "SCORE_RESULT"]
        if (
            len(model) != 1 or model[0].outcome_code != "OK"
            or len(score) != 1 or score[0].outcome_code != "OK"
            or proof.model_result_digest != event_digest(model[0])
            or proof.score_result_digest != event_digest(score[0])
        ):
            raise VerificationError("Reconciliation proof contradicts execution or score events", exit_code=2)
        expected_operation = str(uuid5(
            UUID(proof.turn_id),
            "arena.feedback-reconciliation.v1:" + event_digest(event),
        ))
        if proof.recovery_operation_id != expected_operation:
            raise VerificationError("Reconciliation proof operation binding rejected", exit_code=2)
        if proof.turn_id in receipts_by_turn:
            raise VerificationError("Feedback event has both original receipt and reconciliation proof", exit_code=2)
        proofs_by_turn[proof.turn_id] = proof

    if set(receipts_by_turn) & set(proofs_by_turn):
        raise VerificationError("Feedback receipt coverage is ambiguous", exit_code=2)
    if set(receipts_by_turn) | set(proofs_by_turn) != set(feedback_by_turn):
        raise VerificationError("Every feedback event requires exactly one receipt or reconciliation proof", exit_code=2)
    return receipts_by_turn, proofs_by_turn


def _validate_reconciled_semantics(
    events: Sequence[Event],
    start: SignedWitnessStart,
    receipt_turns: Mapping[str, SignedTurnReceipt],
    proof_turns: Mapping[str, FeedbackReconciliation],
    inputs: ReconciledVerificationInputs,
) -> None:
    mode, actor = inputs.expected_defense_mode, inputs.expected_broker_actor
    if [event.event_type for event in events[:3]] != [
        "MANIFEST_SEALED", "PREFLIGHT_PASSED", "START_RESERVED"
    ]:
        raise VerificationError("Missing ordered campaign bootstrap", exit_code=2)
    if start.receipt.event_count != 3 or start.receipt.prefix_root != event_digest(events[2]):
        raise VerificationError("Witness START does not bind bootstrap prefix", exit_code=2)
    turns, session_next = {}, {}
    invalid, closing = False, False
    for index, event in enumerate(events):
        if event.actor_id != actor:
            raise VerificationError("Unexpected event actor", exit_code=2)
        if index < 3:
            continue
        kind = event.event_type
        if kind in {"MANIFEST_SEALED", "PREFLIGHT_PASSED", "START_RESERVED"}:
            raise VerificationError("Repeated bootstrap event", exit_code=2)
        if kind == "INTEGRITY_VIOLATION":
            invalid = True
            continue
        if kind == "CLOSE_REQUESTED":
            if closing or event.outcome_code != "OK":
                raise VerificationError("Invalid or repeated close request", exit_code=2)
            closing = True
            continue
        if kind == "CLOSED":
            if index != len(events) - 1 or not closing or event.outcome_code != "OK":
                raise VerificationError("Reconciled close is not valid terminal close", exit_code=2)
            continue
        if closing:
            raise VerificationError("Turn event appears after close request", exit_code=2)
        key = event.turn_id
        if kind == "TURN_COMMITTED":
            if (
                key in turns
                or event.turn_index != session_next.get(event.session_id, 0)
                or not event.artifact_ciphertext_refs
            ):
                raise VerificationError("Duplicate, unordered or uncommitted turn", exit_code=2)
            if (
                len(turns) >= 24
                or len(session_next) >= 3 and event.session_id not in session_next
                or any(value["session"] == event.session_id and not value["feedback"]
                       for value in turns.values())
            ):
                raise VerificationError("N04 workload or session bound exceeded", exit_code=2)
            session_next[event.session_id] = event.turn_index + 1
            turns[key] = {"session": event.session_id, "index": event.turn_index,
                          "defense": None, "dispatch": False, "model": None,
                          "score": False, "feedback": False}
            continue
        turn = turns.get(key)
        if (
            not turn
            or (event.session_id, event.turn_index) != (turn["session"], turn["index"])
            or turn["feedback"]
        ):
            raise VerificationError("Unbound or late turn event", exit_code=2)
        if kind == "DEFENSE_RESULT":
            if (turn["defense"] is not None or mode == "POST_HOC"
                    or not event.artifact_ciphertext_refs
                    or mode == "OUTPUT" and turn["model"] != "OK"
                    or mode in {"INPUT", "FEATURES"} and turn["dispatch"]):
                raise VerificationError("Unexpected defense result", exit_code=2)
            turn["defense"] = event.outcome_code
            if event.outcome_code == "FAILED":
                invalid = True
        elif kind == "DISPATCH_INTENT":
            if turn["dispatch"] or mode in {"INPUT", "FEATURES"} and turn["defense"] not in {"ALLOW", "SANITIZE"}:
                raise VerificationError("Unauthorized or duplicate dispatch", exit_code=2)
            turn["dispatch"] = True
        elif kind == "MODEL_RESULT":
            if not turn["dispatch"] or turn["model"] is not None:
                raise VerificationError("Model result without unique dispatch", exit_code=2)
            if event.outcome_code == "OK" and not event.artifact_ciphertext_refs:
                raise VerificationError("Missing model output artifact", exit_code=2)
            turn["model"] = event.outcome_code
            invalid |= event.outcome_code != "OK"
        elif kind == "SCORE_RESULT":
            if turn["model"] != "OK" or turn["score"] or not event.artifact_ciphertext_refs:
                raise VerificationError("Score without completed model provenance", exit_code=2)
            turn["score"] = True
            invalid |= event.outcome_code != "OK"
        elif kind == "FEEDBACK_AUTHORIZED":
            blocked = mode in {"INPUT", "FEATURES"} and turn["defense"] == "BLOCK"
            if not blocked and (turn["model"] != "OK" or not turn["score"]):
                raise VerificationError("Feedback without settled execution and scoring", exit_code=2)
            if mode == "OUTPUT" and turn["defense"] not in {"ALLOW", "BLOCK", "SANITIZE"}:
                raise VerificationError("Output feedback without defense", exit_code=2)
            if event.turn_id not in receipt_turns and event.turn_id not in proof_turns:
                raise VerificationError("Missing receipt/proof coverage", exit_code=2)
            if len(event.artifact_ciphertext_refs) != 2:
                raise VerificationError("Feedback event artifact pair is incomplete", exit_code=2)
            turn["feedback"] = True
        else:
            raise VerificationError("Unsupported turn transition", exit_code=2)
    if invalid or not closing or any(not turn["feedback"] for turn in turns.values()):
        raise VerificationError("Reconciled evidence is invalid, incomplete or unsettled", exit_code=2)


def _decode_json(raw: bytes, label: str) -> dict:
    try:
        return strict_json(raw)
    except Exception as exc:
        raise VerificationError(f"Private {label} opening is invalid", exit_code=2) from exc


def _verify_manifest_opening(
    events: Sequence[Event], plaintexts: Mapping[str, bytes], inputs: ReconciledVerificationInputs
) -> None:
    sealed = [event for event in events if event.event_type == "MANIFEST_SEALED"]
    if len(sealed) != 1 or len(sealed[0].artifact_ciphertext_refs) != 1:
        raise VerificationError("Reconciled manifest opening reference is invalid", exit_code=2)
    try:
        opened = _decode_json(
            plaintexts[sealed[0].artifact_ciphertext_refs[0].artifact_id], "manifest"
        )
        if set(opened) != {"sealed", "execution_lock_bytes_base64", "execution_lock"}:
            raise ValueError("manifest opening shape")
        private = opened["sealed"]["manifest"]
        nonce = bytes.fromhex(opened["sealed"]["commitment_nonce"])
        if commitment(canonical_bytes(private), nonce) != inputs.expected_manifest_digest:
            raise ValueError("manifest commitment")
        if private["profile"]["request"]["defense_mode"] != inputs.expected_defense_mode:
            raise ValueError("manifest defense mode")
        lock_bytes = _b64(opened["execution_lock_bytes_base64"], "execution lock")
        if hashlib.sha256(lock_bytes).hexdigest() != private["profile"]["execution_lock_sha256"]:
            raise ValueError("execution lock commitment")
        lock_value = _decode_json(lock_bytes, "execution lock")
        if lock_value != opened["execution_lock"]:
            raise ValueError("execution lock bytes")
    except Exception as exc:
        raise VerificationError("Reconciled manifest commitment/opening rejected", exit_code=2) from exc


def _b64(value, label: str) -> bytes:
    if not isinstance(value, str):
        raise VerificationError(f"Private {label} base64 field is invalid", exit_code=2)
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise VerificationError(f"Private {label} base64 field is invalid", exit_code=2) from exc


def _verify_reconciled_private_openings(
    proof: FeedbackReconciliation,
    event: Event,
    events: Sequence[Event],
    plaintexts: Mapping[str, bytes],
    inputs: ReconciledVerificationInputs,
) -> None:
    turn = {
        "domain_id": proof.domain_id,
        "experiment_id": proof.experiment_id,
        "epoch": proof.epoch,
        "session_id": proof.session_id,
        "turn_id": proof.turn_id,
        "turn_index": proof.turn_index,
    }
    if tuple(event.artifact_ciphertext_refs) != (proof.input_artifact, proof.response_artifact):
        raise VerificationError("Reconciled proof opening refs differ from event", exit_code=2)
    try:
        input_outer = _decode_json(plaintexts[proof.input_artifact.artifact_id], "input envelope")
        response_outer = _decode_json(plaintexts[proof.response_artifact.artifact_id], "response envelope")
        if (set(input_outer) != {"kind", "content_base64", "nonce_hex"}
                or input_outer["kind"] != "INPUT_OPENING"
                or set(response_outer) != {
                    "kind", "content_base64", "nonce_hex", "public_reply_utf8_base64", "result"
                }
                or response_outer["kind"] != "PUBLIC_RESPONSE_OPENING"):
            raise ValueError("opening envelope shape")
        input_content = _b64(input_outer["content_base64"], "input content")
        response_content = _b64(response_outer["content_base64"], "response content")
        input_nonce = bytes.fromhex(input_outer["nonce_hex"])
        response_nonce = bytes.fromhex(response_outer["nonce_hex"])
        if (commitment(input_content, input_nonce) != proof.input_commitment
                or commitment(response_content, response_nonce) != proof.response_commitment):
            raise ValueError("commitment mismatch")
        input_value = _decode_json(input_content, "input content")
        response_value = _decode_json(response_content, "response content")
        if canonical_bytes(input_value) != input_content or canonical_bytes(response_value) != response_content:
            raise ValueError("noncanonical opening content")
        expected_input_fields = {
            *turn, "schema_version", "original_utf8_base64", "effective_utf8_base64", "provenance"
        }
        expected_response_fields = {
            *turn, "schema_version", "public_reply_utf8_base64", "public_status"
        }
        if (set(input_value) != expected_input_fields
                or input_value["schema_version"] != "arena-n04-input.v1"
                or {key: input_value[key] for key in turn} != turn
                or set(response_value) != expected_response_fields
                or response_value["schema_version"] != "arena-n04-public-response.v1"
                or {key: response_value[key] for key in turn} != turn
                or response_value["public_status"] != "COMPLETED"):
            raise ValueError("opening context or schema")
        original = _b64(input_value["original_utf8_base64"], "original text").decode("utf-8", errors="strict")
        effective = _b64(input_value["effective_utf8_base64"], "effective text").decode("utf-8", errors="strict")
        if len(original.encode("utf-8")) > 750_000 or len(effective.encode("utf-8")) > 750_000:
            raise ValueError("private opening size")
        provenance = PayloadProvenance.model_validate(input_value["provenance"])
        if canonical_bytes(provenance) != canonical_bytes(input_value["provenance"]):
            raise ValueError("provenance encoding")
        public_reply = _b64(response_value["public_reply_utf8_base64"], "public reply").decode("utf-8", errors="strict")
        if response_outer["public_reply_utf8_base64"] != response_value["public_reply_utf8_base64"]:
            raise ValueError("public reply mismatch")
        result = AttemptResult.model_validate(response_outer["result"])
        if (result.defense_mode != inputs.expected_defense_mode
                or result.model_execution != "EXECUTED"
                or result.integrity != "VALID_WITHIN_PROFILE"
                or result.scoring != "UNCERTAIN"):
            raise ValueError("reconciled result truth")

        turn_events = [item for item in events if item.turn_id == proof.turn_id]
        committed_events = [item for item in turn_events if item.event_type == "TURN_COMMITTED"]
        if len(committed_events) != 1 or len(committed_events[0].artifact_ciphertext_refs) != 1:
            raise ValueError("original committed input evidence")
        committed_ref = committed_events[0].artifact_ciphertext_refs[0]
        original_payload = _decode_json(plaintexts[committed_ref.artifact_id], "original input")
        if (
            set(original_payload) != {*turn, "original_utf8_base64", "provenance"}
            or {key: original_payload[key] for key in turn} != turn
            or original_payload["original_utf8_base64"] != input_value["original_utf8_base64"]
            or canonical_bytes(original_payload["provenance"]) != canonical_bytes(input_value["provenance"])
        ):
            raise ValueError("recovered input does not match original committed payload")
        model_events = [item for item in turn_events if item.event_type == "MODEL_RESULT"]
        score_events = [item for item in turn_events if item.event_type == "SCORE_RESULT"]
        if len(model_events) != 1 or len(model_events[0].artifact_ciphertext_refs) != 1:
            raise ValueError("model output evidence")
        model_ref = model_events[0].artifact_ciphertext_refs[0]
        model = TargetResponse.model_validate(_decode_json(plaintexts[model_ref.artifact_id], "model result"))
        if (model.domain_id, model.experiment_id, model.epoch, model.attempt_id,
                model.session_id, model.turn_index) != (
                proof.domain_id, proof.experiment_id, proof.epoch, proof.turn_id,
                proof.session_id, proof.turn_index):
            raise ValueError("model output context")
        defenses = [item for item in turn_events if item.event_type == "DEFENSE_RESULT"]
        decision = None
        if inputs.expected_defense_mode == "POST_HOC":
            if defenses:
                raise ValueError("POST_HOC has defense event")
            expected_effective = original
            expected_reply = model.text
        else:
            if len(defenses) != 1 or len(defenses[0].artifact_ciphertext_refs) != 1:
                raise ValueError("defense evidence")
            defense_ref = defenses[0].artifact_ciphertext_refs[0]
            defense_value = _decode_json(plaintexts[defense_ref.artifact_id], "defense result")
            if set(defense_value) != {"request", "decision"}:
                raise ValueError("defense opening shape")
            request = DEFENSE_REQUEST.validate_python(defense_value["request"])
            decision = DefenseDecision.model_validate(defense_value["decision"])
            if request.mode != inputs.expected_defense_mode or decision.verdict != defenses[0].outcome_code:
                raise ValueError("defense mode/outcome")
            if request.call_token != decision.call_token:
                raise ValueError("defense call token")
            if inputs.expected_defense_mode == "INPUT" and request.content.prompt != original:
                raise ValueError("input defense does not use original text")
            if inputs.expected_defense_mode == "FEATURES":
                bucket = "SHORT" if len(original.encode()) <= 256 else "MEDIUM" if len(original.encode()) <= 2048 else "LONG"
                marker = any(term in original.lower() for term in ("ignore previous", "jailbreak", "injection_control"))
                if (request.content.length_bucket, request.content.control_marker_present) != (bucket, marker):
                    raise ValueError("feature defense input mismatch")
            if inputs.expected_defense_mode == "OUTPUT" and request.content.response != model.text:
                raise ValueError("output defense does not use model text")
            expected_effective = (
                re.sub("sanitize_control", "[REDACTED]", original, flags=re.IGNORECASE | re.ASCII)
                if inputs.expected_defense_mode in {"INPUT", "FEATURES"} and decision.verdict == "SANITIZE"
                else original
            )
            expected_reply = (
                BLOCK_REPLY if decision.verdict == "BLOCK"
                else re.sub("sanitize_control", "[REDACTED]", model.text, flags=re.IGNORECASE | re.ASCII)
                if inputs.expected_defense_mode == "OUTPUT" and decision.verdict == "SANITIZE"
                else model.text
            )
        if effective != expected_effective or public_reply != expected_reply:
            raise ValueError("recovered opening does not match executed public result")
        expected_disposition = (
            "BLOCKED_BY_DEFENSE" if decision and decision.verdict == "BLOCK"
            else "SANITIZED" if decision and decision.verdict == "SANITIZE"
            else "ALLOWED"
        )
        if result.pipeline_disposition != expected_disposition:
            raise ValueError("recovered pipeline disposition mismatch")
        if len(score_events) != 1 or len(score_events[0].artifact_ciphertext_refs) != 1:
            raise ValueError("score evidence")
        score_ref = score_events[0].artifact_ciphertext_refs[0]
        score_value = _decode_json(plaintexts[score_ref.artifact_id], "score result")
        if set(score_value) != {*turn, "observation"} or {key: score_value[key] for key in turn} != turn:
            raise ValueError("score context")
        observation = ScoreObservation.model_validate(score_value["observation"])
        if (observation.model_output != model_ref
                or observation.scoring != "UNCERTAIN"
                or observation.safety_finding is not None
                or observation.refusal_marker_present != evaluate_refusal_rubric(model.text)["is_refusal"]):
            raise ValueError("score provenance")
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError("Reconciled private opening/commitment verification failed", exit_code=2) from exc


def _verify_private_openings(
    extracted: Path,
    listed: Mapping[str, dict],
    checkpoint: SignedCheckpoint,
    events: Sequence[Event],
    receipts_by_turn: Mapping[str, SignedTurnReceipt],
    proofs_by_turn: Mapping[str, FeedbackReconciliation],
    inputs: ReconciledVerificationInputs,
) -> tuple[int, dict]:
    required_ids = {ref.artifact_id for ref in checkpoint.checkpoint.required_artifacts}
    if set(inputs.artifact_keys) != required_ids or set(inputs.artifact_classifications) != required_ids:
        raise VerificationError("Authorized decryption keys must cover exactly the evidence artifacts", exit_code=2)
    if any(type(value) is not bytes or len(value) != 32 for value in inputs.artifact_keys.values()):
        raise VerificationError("Authorized artifact key is malformed", exit_code=2)
    for artifact_id in required_ids:
        path = f"artifacts/{artifact_id}.bin"
        if path not in listed:
            raise VerificationError("Required ciphertext artifact is absent", exit_code=2)
    try:
        plaintexts = replay_and_decrypt_artifacts(
            extracted / "artifacts",
            dict(inputs.artifact_keys),
            inputs.expected_context,
            dict(inputs.artifact_classifications),
        )
    except Exception as exc:
        raise VerificationError("Authorized artifact decryption/AEAD verification failed", exit_code=2) from exc

    _verify_manifest_opening(events, plaintexts, inputs)

    if receipts_by_turn:
        # Reuse the existing complete N04 private-lineage verifier for all original
        # arena.v2 receipts. Filter only proof-covered turns; no receipt is created.
        original_turns = set(receipts_by_turn)
        selected = [event for event in events if event.event_type == "MANIFEST_SEALED"
                    or event.turn_id in original_turns
                    or event.event_type in {"CLOSE_REQUESTED", "CLOSED"}]
        with tempfile.TemporaryDirectory(prefix="arena-reconciled-openings-") as work:
            root = Path(work)
            (root / "events.jsonl").write_bytes(
                b"".join(canonical_bytes(event) + b"\n" for event in selected)
            )
            (root / "turn_receipts.jsonl").write_bytes(
                b"".join(canonical_bytes(signed) + b"\n" for signed in receipts_by_turn.values())
            )
            try:
                verify_n04_openings(root, plaintexts, inputs.expected_defense_mode)
            except Exception as exc:
                raise VerificationError("Original receipt private lineage verification failed", exit_code=2) from exc
    for turn_id, proof in proofs_by_turn.items():
        event = next(item for item in events if item.event_type == "FEEDBACK_AUTHORIZED" and item.turn_id == turn_id)
        _verify_reconciled_private_openings(proof, event, events, plaintexts, inputs)
    try:
        manifest = transport_from_openings(plaintexts)
    except Exception as exc:
        raise VerificationError("Reconciled sealed manifest transport cannot be read", exit_code=2) from exc
    transport_present = "n06_transport" in manifest
    if (inputs.require_transport_profile or inputs.transport_trust is not None) and not transport_present:
        raise VerificationError("Required sealed transport profile is absent", exit_code=2)
    if transport_present and inputs.transport_trust is None:
        raise VerificationError("Sealed transport requires independently pinned trust", exit_code=2)
    if inputs.require_transport_profile and (not transport_present or inputs.transport_trust is None):
        raise VerificationError("Required sealed transport profile or trust is absent", exit_code=2)
    transport_diagnostics = {"transport_profile_verified": False}
    if transport_present and inputs.transport_trust is not None:
        try:
            transport_diagnostics.update(verify_transport_opening(
                plaintexts, inputs.expected_context, inputs.transport_trust
            ))
        except Exception as exc:
            raise VerificationError("Reconciled sealed transport profile rejected", exit_code=2) from exc
    return len(receipts_by_turn) + len(proofs_by_turn), transport_diagnostics


def verify_reconciled_evidence_bundle(
    archive_path: Path,
    *,
    anchor_records_bytes: bytes,
    expected_context: Context,
    expected_manifest_digest: str,
    recorder_key: bytes,
    recorder_key_id: str,
    witness_key: bytes,
    witness_key_id: str,
    anchor_key: bytes,
    anchor_authority_id: str,
    anchor_key_id: str,
    recovery_key: bytes,
    recovery_authority_id: str,
    recovery_key_id: str,
    artifact_keys: Mapping[str, bytes],
    artifact_classifications: Mapping[str, str],
    expected_defense_mode: str,
    expected_broker_actor: str,
    transport_trust: TransportTrust | None = None,
    require_transport_profile: bool = False,
) -> dict:
    """Verify an authenticated valid run and each receipt/reconciliation opening."""
    inputs = ReconciledVerificationInputs(
        expected_context, expected_manifest_digest, recorder_key, recorder_key_id,
        witness_key, witness_key_id, anchor_key, anchor_authority_id, anchor_key_id,
        recovery_key, recovery_authority_id, recovery_key_id, artifact_keys,
        artifact_classifications, expected_defense_mode, expected_broker_actor,
        transport_trust, require_transport_profile,
    )
    _validate_inputs(inputs)
    if Path(archive_path).is_symlink():
        raise VerificationError("Reconciled archive symlink rejected", exit_code=2)
    with tempfile.TemporaryDirectory(prefix="arena-reconciled-bundle-") as temporary:
        root = Path(temporary)
        try:
            safe_extract_archive(Path(archive_path), root)
        except Exception as exc:
            raise VerificationError("Reconciled archive safety check failed", exit_code=2) from exc
        try:
            with zipfile.ZipFile(Path(archive_path), "r") as archive:
                infos = archive.infolist()
                if len(infos) > MAX_ARCHIVE_MEMBERS or any(info.is_dir() for info in infos):
                    raise VerificationError("Reconciled archive entries rejected", exit_code=2)
                names = [info.filename for info in infos]
        except VerificationError:
            raise
        except Exception as exc:
            raise VerificationError("Reconciled archive is invalid", exit_code=2) from exc
        if len(names) != len(set(names)) or len(names) != len({name.casefold() for name in names}):
            raise VerificationError("Reconciled archive has duplicate member paths", exit_code=2)
        files = {name: root.joinpath(*PurePosixPath(name).parts) for name in names}
        manifest_path = files.get("bundle-manifest.json")
        if manifest_path is None or manifest_path.stat().st_size > MAX_METADATA_BYTES:
            raise VerificationError("Reconciled archive manifest is missing or oversized", exit_code=2)
        manifest_bytes = manifest_path.read_bytes()
        try:
            manifest = _strict_json_line(manifest_bytes[:-1] if manifest_bytes.endswith(b"\n") else manifest_bytes)
        except Exception as exc:
            raise VerificationError("Reconciled archive manifest is malformed", exit_code=2) from exc
        if manifest_bytes != _canonical_json(manifest, newline=True):
            raise VerificationError("Reconciled archive manifest is not canonical", exit_code=2)
        listed = _validate_manifest(manifest, files)
        required = ("checkpoint.json", "witness_start.json", "witness_close.json", "events.jsonl")
        if any(files[name].stat().st_size > MAX_METADATA_BYTES for name in required):
            raise VerificationError("Reconciled wire metadata is oversized", exit_code=2)
        try:
            cp = load_wire(SignedCheckpoint, files["checkpoint.json"].read_bytes())
            start = load_wire(SignedWitnessStart, files["witness_start.json"].read_bytes())
            witness = load_wire(SignedWitnessClose, files["witness_close.json"].read_bytes())
            events = _jsonl_models(files["events.jsonl"].read_bytes(), Event, "Reconciled events")
        except VerificationError:
            raise
        except Exception as exc:
            raise VerificationError("Reconciled evidence wire parsing failed", exit_code=2) from exc
        if not events or len(events) != cp.checkpoint.event_count:
            raise VerificationError("Reconciled event count mismatch", exit_code=2)
        if not verify_checkpoint(
            cp, inputs.recorder_key, inputs.expected_context,
            inputs.expected_manifest_digest, inputs.recorder_key_id,
        ):
            raise VerificationError("Reconciled recorder checkpoint rejected", exit_code=2)
        if not verify_witness_close(
            witness, inputs.witness_key, cp.checkpoint,
            inputs.expected_context, inputs.witness_key_id,
        ):
            raise VerificationError("Reconciled witness close rejected", exit_code=2)
        if (
            (start.receipt.domain_id, start.receipt.experiment_id, start.receipt.epoch,
             start.receipt.public_manifest_digest, start.receipt.witness_key_id)
            != (inputs.expected_context.domain_id, inputs.expected_context.experiment_id,
                inputs.expected_context.epoch, inputs.expected_manifest_digest, inputs.witness_key_id)
            or not verify(witness_message(start.receipt), start.signature, inputs.witness_key)
        ):
            raise VerificationError("Reconciled witness start rejected", exit_code=2)
        if (
            events[-1].event_type != "CLOSED" or events[-1].outcome_code != "OK"
            or cp.checkpoint.terminal_marker != "CLOSED"
        ):
            raise VerificationError("Reconciled bundle is not a valid terminal close", exit_code=2)
        try:
            validate_chain(tuple(events), cp.checkpoint)
        except Exception as exc:
            raise VerificationError("Reconciled event chain/checkpoint rejected", exit_code=2) from exc
        if cp.checkpoint.final_root != event_digest(events[-1]):
            raise VerificationError("Reconciled final root mismatch", exit_code=2)

        refs = {ref.artifact_id: ref.ciphertext_sha256 for ref in cp.checkpoint.required_artifacts}
        member_refs = {
            PurePosixPath(name).stem: entry["sha256"]
            for name, entry in listed.items() if name.startswith("artifacts/")
        }
        if member_refs != refs:
            raise VerificationError("Reconciled ciphertext members do not exactly bind checkpoint artifacts", exit_code=2)
        state, committed_by_event, anchor_digest = _verify_anchor_binding(
            anchor_records_bytes, events, cp, witness, inputs
        )

        receipts = []
        if "turn_receipts.jsonl" in files:
            receipts = _jsonl_models(
                files["turn_receipts.jsonl"].read_bytes(), SignedTurnReceipt,
                "Original turn receipts", allow_empty=True,
            )
        proofs = []
        if "reconciliation_receipts.jsonl" in files:
            proofs = _jsonl_models(
                files["reconciliation_receipts.jsonl"].read_bytes(),
                FeedbackReconciliation,
                "Reconciliation receipts",
                allow_empty=True,
            )
        receipts_by_turn, proofs_by_turn = _verify_receipts_and_proofs(
            receipts, proofs, events, cp, committed_by_event, inputs
        )
        _validate_reconciled_semantics(events, start, receipts_by_turn, proofs_by_turn, inputs)
        openings_verified, transport_diagnostics = _verify_private_openings(
            root, listed, cp, events, receipts_by_turn, proofs_by_turn, inputs
        )
        result = {
            "status": "PASS_RECONCILED_EVIDENCE",
            "exit_code": 0,
            "integrity_status": "VALID_WITHIN_PROFILE",
            "event_count": len(events),
            "final_root": cp.checkpoint.final_root,
            "original_receipt_count": len(receipts_by_turn),
            "reconciliation_proof_count": len(proofs_by_turn),
            "feedback_coverage_count": len(receipts_by_turn) + len(proofs_by_turn),
            "anchor_records_sha256": anchor_digest,
            "anchor_signature_verified": True,
            "terminal_anchor_verified": state["terminal"] is not None,
            "recovery_signature_verified": bool(proofs_by_turn) and len(proofs_by_turn) == len(proofs),
            "private_opening_count": openings_verified,
            "private_commitments_verified": True,
            "participant_release_authorized": False,
            "safety_finding": False,
        }
        result.update(transport_diagnostics)
        return result


def _archive_bytes(payload_members: Mapping[str, bytes]) -> bytes:
    if not isinstance(payload_members, Mapping):
        raise DependencyUnavailable("RECONCILED_EXPORT_MEMBERS_INVALID")
    if any(not _allowed_member(name) or type(data) is not bytes for name, data in payload_members.items()):
        raise DependencyUnavailable("RECONCILED_EXPORT_MEMBER_PATH_OR_BYTES_REJECTED")
    required = {"checkpoint.json", "witness_start.json", "witness_close.json", "events.jsonl"}
    if not required <= set(payload_members):
        raise DependencyUnavailable("RECONCILED_EXPORT_REQUIRED_MEMBER_MISSING")
    optional_members = {name: name in payload_members for name in OPTIONAL_ROOT_FILES}
    entries = [
        {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in sorted(payload_members.items())
    ]
    manifest = {
        "schema_version": SCHEMA,
        "members": entries,
        "optional_members": optional_members,
    }
    members = dict(payload_members)
    members["bundle-manifest.json"] = _canonical_json(manifest, newline=True)
    if len(members) > MAX_ARCHIVE_MEMBERS or sum(len(data) for data in members.values()) > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise DependencyUnavailable("RECONCILED_EXPORT_RESOURCE_LIMIT")
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(members.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, data)
        stream.seek(0)
        return stream.read()


def export_reconciled_evidence_bundle(
    output_path: Path,
    payload_members: Mapping[str, bytes],
    *,
    anchor_records_bytes: bytes,
    verification: ReconciledVerificationInputs,
) -> Path:
    """Verify first, then atomically publish a non-overwriting valid v1 archive."""
    output_path = Path(output_path).absolute()
    if any(parent.is_symlink() for parent in (output_path, *output_path.parents)):
        raise DependencyUnavailable("RECONCILED_EXPORT_DESTINATION_UNSAFE")
    if output_path.exists() or output_path.is_symlink():
        raise DependencyUnavailable("RECONCILED_EXPORT_DESTINATION_CONFLICT")
    if not output_path.parent.is_dir():
        raise DependencyUnavailable("RECONCILED_EXPORT_DESTINATION_PARENT_MISSING")
    archive_bytes = _archive_bytes(payload_members)
    with tempfile.NamedTemporaryFile(
        prefix=".arena-reconciled-", suffix=".zip", dir=output_path.parent, delete=False
    ) as tmp:
        temporary = Path(tmp.name)
        tmp.write(archive_bytes)
    linked = False
    try:
        verify_reconciled_evidence_bundle(
            temporary,
            anchor_records_bytes=anchor_records_bytes,
            **verification.verifier_kwargs(),
        )
        try:
            os.link(temporary, output_path)
            linked = True
        except FileExistsError as exc:
            raise DependencyUnavailable("RECONCILED_EXPORT_DESTINATION_CONFLICT") from exc
        return output_path
    except VerificationError as exc:
        raise DependencyUnavailable("RECONCILED_EXPORT_PREFLIGHT_FAILED") from exc
    except Exception:
        if linked:
            output_path.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)
