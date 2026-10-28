"""Offline verification of separately linked, post-release observations."""

import base64
import json
from arena.contracts.api import DEFENSE_REQUEST, DefenseDecision, TargetResponse
from arena.contracts.crypto import checkpoint_digest, same_context, sha256, verify
from arena.contracts.evidence import Event, SignedCheckpoint
from arena.contracts.jsonwire import load_wire
from arena.integration.types import SignedPostHocReceipt, post_hoc_message
from .replay import replay_and_decrypt_artifacts
from .rules import VerificationError


def verify_post_hoc_directory(
    directory,
    original,
    expected_context,
    expected_release_id,
    recorder_key,
    recorder_key_id,
    original_plaintexts,
    analysis_keys,
    original_integrity,
):
    """Original evidence/plaintexts must already pass public and private verification.

    Expected context, release ID and keys arrive independently of either bundle.
    Return only metadata; never display prompt/output/defense content.
    """
    try:
        if {path.name for path in directory.iterdir()} != {
            "analysis.json",
            "artifacts",
        }:
            raise ValueError()
        metadata = directory / "analysis.json"
        if (
            metadata.is_symlink()
            or not metadata.is_file()
            or metadata.stat().st_size > 70000
        ):
            raise ValueError()
        signed = load_wire(SignedPostHocReceipt, metadata.read_bytes())
        receipt = signed.receipt
        checkpoint = load_wire(
            SignedCheckpoint, (original / "checkpoint.json").read_bytes()
        ).checkpoint
        if (
            not same_context(receipt, expected_context)
            or receipt.signer_key_id != recorder_key_id
            or receipt.release_receipt_id != expected_release_id
            or receipt.terminal_checkpoint_digest != checkpoint_digest(checkpoint)
            or receipt.aggregate_integrity != original_integrity
            or not verify(post_hoc_message(receipt), signed.signature, recorder_key)
        ):
            raise ValueError()
        events = [
            load_wire(Event, line.encode())
            for line in (original / "events.jsonl").read_text().splitlines()
            if line
        ]
        own = [
            event
            for event in events
            if event.turn_id == receipt.turn_id
            and (event.session_id, event.turn_index)
            == (receipt.session_id, receipt.turn_index)
        ]
        feedback = next(
            event for event in own if event.event_type == "FEEDBACK_AUTHORIZED"
        )
        model = next(
            event
            for event in own
            if event.event_type == "MODEL_RESULT" and event.outcome_code == "OK"
        )
        if (
            receipt.source_input not in feedback.artifact_ciphertext_refs
            or receipt.source_output not in model.artifact_ciphertext_refs
        ):
            raise ValueError()
        refs = (receipt.source_input, receipt.source_output, receipt.analysis_artifact)
        folder = directory / "artifacts"
        if (
            folder.is_symlink()
            or not folder.is_dir()
            or {path.name for path in folder.iterdir()}
            != {ref.artifact_id + ".bin" for ref in refs}
        ):
            raise ValueError()
        for ref in refs:
            path = folder / (ref.artifact_id + ".bin")
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > 1_000_000
                or sha256(path.read_bytes()) != ref.ciphertext_sha256
            ):
                raise ValueError()
        if (
            receipt.source_input not in checkpoint.required_artifacts
            or receipt.source_output not in checkpoint.required_artifacts
        ):
            raise ValueError()
        input_opening = json.loads(
            original_plaintexts[receipt.source_input.artifact_id]
        )
        if input_opening.get("kind") != "INPUT_OPENING":
            raise ValueError()
        input_value = json.loads(
            base64.b64decode(input_opening["content_base64"], validate=True)
        )
        model_output = TargetResponse.model_validate(
            json.loads(original_plaintexts[receipt.source_output.artifact_id])
        )
        prompt = base64.b64decode(
            input_value["original_utf8_base64"], validate=True
        ).decode("utf-8")
        secret = analysis_keys[receipt.analysis_artifact.artifact_id]
        if secret["classification"] != "PRIVATE_DEFENSE":
            raise ValueError()
        plaintexts = replay_and_decrypt_artifacts(
            folder,
            {receipt.analysis_artifact.artifact_id: bytes.fromhex(secret["key"])},
            expected_context,
            {receipt.analysis_artifact.artifact_id: "PRIVATE_DEFENSE"},
        )
        artifact = json.loads(plaintexts[receipt.analysis_artifact.artifact_id])
        if set(artifact) != {"request", "decision"}:
            raise ValueError()
        request = DEFENSE_REQUEST.validate_python(artifact["request"])
        decision = DefenseDecision.model_validate(artifact["decision"])
        if (
            request.mode != "POST_HOC"
            or request.call_token != decision.call_token
            or request.content.prompt != prompt
            or request.content.response != model_output.text
        ):
            raise ValueError()
        return {
            "turn_id": receipt.turn_id,
            "analysis_artifact_id": receipt.analysis_artifact.artifact_id,
            "analysis_kind": "POST_RELEASE_ONLY",
            "prior_integrity": receipt.aggregate_integrity,
        }
    except Exception as exc:
        raise VerificationError(
            "Post-release signature/context/release/source/lineage verification failed",
            exit_code=1,
        ) from exc
