"""Canonical arena.v2 bytes and maintained-library crypto. No signing keys in source."""

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel

from .common import Context, SAFE_INT
from .evidence import (ArtifactAAD, Checkpoint, Event, SignedCheckpoint,
                       SignedWitnessClose, TurnReceipt, WitnessClose, WitnessStart)
from .jsonwire import ContractError


PREFIXES = {name: f"arena.v2/{name}\x00".encode("ascii") for name in ("event", "checkpoint", "witness", "turn", "commitment")}


def canonical_bytes(value: BaseModel | dict) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")

    def check(item: Any) -> None:
        if item is None or type(item) is bool:
            return
        if type(item) is int and -SAFE_INT <= item <= SAFE_INT:
            return
        if type(item) is str and item.isascii():
            return
        if type(item) in (list, tuple):
            for child in item:
                check(child)
            return
        if type(item) is dict and all(type(key) is str and key.isascii() for key in item):
            for child in item.values():
                check(child)
            return
        raise ContractError()

    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def commitment(content: bytes, nonce: bytes) -> str:
    if type(content) is not bytes or type(nonce) is not bytes or len(nonce) != 32:
        raise ContractError()
    return sha256(PREFIXES["commitment"] + nonce + len(content).to_bytes(8, "big") + content)


def event_digest(event: Event) -> str:
    return sha256(PREFIXES["event"] + bytes.fromhex(event.previous_digest) + canonical_bytes(event))


def checkpoint_message(checkpoint: Checkpoint) -> bytes:
    return PREFIXES["checkpoint"] + canonical_bytes(checkpoint)


def checkpoint_digest(checkpoint: Checkpoint) -> str:
    return sha256(checkpoint_message(checkpoint))


def witness_message(receipt: WitnessStart | WitnessClose) -> bytes:
    return PREFIXES["witness"] + canonical_bytes(receipt)


def turn_message(receipt: TurnReceipt) -> bytes:
    return PREFIXES["turn"] + canonical_bytes(receipt)


def sign(message: bytes, private_key: bytes) -> str:
    if type(private_key) is not bytes or len(private_key) != 32:
        raise ContractError()
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(message).hex()


def verify(message: bytes, signature: str, pinned_public_key: bytes) -> bool:
    try:
        if type(pinned_public_key) is not bytes or len(pinned_public_key) != 32:
            return False
        if type(signature) is not str or len(signature) != 128:
            return False
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(bytes.fromhex(signature), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def same_context(left: Context, right: Context) -> bool:
    return (left.domain_id, left.experiment_id, left.epoch) == (right.domain_id, right.experiment_id, right.epoch)


def verify_checkpoint(signed: SignedCheckpoint, pinned_key: bytes, expected: Context,
                      manifest_digest: str, expected_signer_key_id: str) -> bool:
    checkpoint = signed.checkpoint
    return (same_context(checkpoint, expected) and checkpoint.public_manifest_digest == manifest_digest
            and checkpoint.signer_key_id == expected_signer_key_id
            and verify(checkpoint_message(checkpoint), signed.signature, pinned_key))


def verify_witness_close(signed: SignedWitnessClose, pinned_key: bytes, checkpoint: Checkpoint,
                         expected: Context, expected_witness_key_id: str) -> bool:
    """Verify separately after verifying the recorder checkpoint; never fetch keys from a bundle."""
    receipt = signed.receipt
    return (same_context(checkpoint, expected) and same_context(receipt, expected)
            and receipt.witness_key_id == expected_witness_key_id
            and receipt.witness_key_id != checkpoint.signer_key_id
            and receipt.public_manifest_digest == checkpoint.public_manifest_digest
            and receipt.checkpoint_digest == checkpoint_digest(checkpoint)
            and receipt.event_count == checkpoint.event_count and receipt.final_root == checkpoint.final_root
            and verify(witness_message(receipt), signed.signature, pinned_key))


def validate_chain(events: tuple[Event, ...], checkpoint: Checkpoint) -> None:
    """Structural/context/artifact binding helper; Monu still implements semantic verification."""
    previous = "0" * 64
    artifacts = {}
    if not events or len(events) != checkpoint.event_count or events[-1].event_type != "CLOSED":
        raise ContractError()
    for number, event in enumerate(events, 1):
        if event.sequence != number or event.previous_digest != previous or not same_context(event, checkpoint):
            raise ContractError()
        if event.public_manifest_digest != checkpoint.public_manifest_digest:
            raise ContractError()
        if event.event_type == "CLOSED" and number != len(events):
            raise ContractError()
        for ref in event.artifact_ciphertext_refs:
            if ref.artifact_id in artifacts and artifacts[ref.artifact_id] != ref.ciphertext_sha256:
                raise ContractError()
            artifacts[ref.artifact_id] = ref.ciphertext_sha256
        previous = event_digest(event)
    expected = {ref.artifact_id: ref.ciphertext_sha256 for ref in checkpoint.required_artifacts}
    if previous != checkpoint.final_root or artifacts != expected:
        raise ContractError()


def request_digest(request: BaseModel) -> str:
    # Exact text bytes, including Unicode/newlines, are never normalized or exposed.
    def transform(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: ({"utf8_base64": base64.b64encode(item.encode("utf-8")).decode("ascii")}
                          if key == "text" and isinstance(item, str) else transform(item))
                    for key, item in value.items()}
        if isinstance(value, list):
            return [transform(item) for item in value]
        return value
    return sha256(canonical_bytes(transform(request.model_dump(mode="json", exclude_unset=True))))


def encrypt_artifact(plaintext: bytes, aad: ArtifactAAD) -> tuple[bytes, bytes]:
    """Fresh per-artifact AES-256 key and 96-bit nonce; return secret key and nonce||ciphertext+tag."""
    if type(plaintext) is not bytes:
        raise ContractError()
    key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    return key, nonce + AESGCM(key).encrypt(nonce, plaintext, canonical_bytes(aad))


def decrypt_artifact(blob: bytes, key: bytes, aad: ArtifactAAD) -> bytes:
    if type(blob) is not bytes or len(blob) < 28 or type(key) is not bytes or len(key) != 32:
        raise ContractError()
    return AESGCM(key).decrypt(blob[:12], blob[12:], canonical_bytes(aad))
