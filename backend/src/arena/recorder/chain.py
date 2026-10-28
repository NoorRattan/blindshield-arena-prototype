"""SHA-256 event chaining logic and chain verification."""

from __future__ import annotations

from typing import List, Tuple

from ..contracts.crypto import event_digest
from ..contracts.evidence import Event
from ..ports import DependencyUnavailable

GENESIS_PREVIOUS_DIGEST = "0" * 64


def compute_event_digest(event: Event) -> str:
    """Compute the SHA-256 digest of an event chained with its previous_digest."""
    return event_digest(event)


def verify_event_chain(events: List[Event]) -> Tuple[bool, str]:
    """Verify that a sequence of events forms a contiguous valid hash chain.
    
    Returns (True, final_root) or raises DependencyUnavailable.
    """
    if not events:
        return True, GENESIS_PREVIOUS_DIGEST

    expected_previous = GENESIS_PREVIOUS_DIGEST
    last_digest = GENESIS_PREVIOUS_DIGEST

    for idx, ev in enumerate(events, start=1):
        if ev.sequence != idx:
            raise DependencyUnavailable(f"CHAIN_SEQUENCE_GAP: expected {idx}, got {ev.sequence}")
        if ev.previous_digest != expected_previous:
            raise DependencyUnavailable(f"CHAIN_DIGEST_MISMATCH at seq {ev.sequence}")
        current_digest = event_digest(ev)
        expected_previous = current_digest
        last_digest = current_digest

    return True, last_digest
