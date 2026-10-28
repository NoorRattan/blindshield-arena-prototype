"""Ed25519 terminal checkpoint creation and signing."""

from __future__ import annotations

from typing import List, Sequence

from ..contracts.common import Context
from ..contracts.crypto import checkpoint_message, sign
from ..contracts.evidence import ArtifactRef, Checkpoint, SignedCheckpoint


def build_and_sign_checkpoint(
    context: Context,
    public_manifest_digest: str,
    event_count: int,
    final_root: str,
    artifacts: Sequence[ArtifactRef],
    signer_key_id: str,
    private_key: bytes,
) -> SignedCheckpoint:
    """Build canonical terminal Checkpoint and sign with Ed25519 private key."""
    # Deduplicate and sort artifacts strictly by artifact_id per contract requirement
    unique_map = {ref.artifact_id: ref for ref in artifacts}
    sorted_artifacts = tuple(sorted(unique_map.values(), key=lambda ref: ref.artifact_id))

    checkpoint = Checkpoint(
        domain_id=context.domain_id,
        experiment_id=context.experiment_id,
        epoch=context.epoch,
        schema_version="arena.v2",
        public_manifest_digest=public_manifest_digest,
        event_count=event_count,
        final_root=final_root,
        terminal_marker="CLOSED",
        required_artifacts=sorted_artifacts,
        signer_key_id=signer_key_id,
    )

    msg = checkpoint_message(checkpoint)
    signature = sign(msg, private_key)
    return SignedCheckpoint(checkpoint=checkpoint, signature=signature)
