"""Deterministic mock model adapter for testing and fallback plumbing."""

from __future__ import annotations

import hashlib
from typing import Dict, List

from ..contracts.api import TargetRequest, TargetResponse
from ..contracts.common import Uuid
from ..ports import DependencyUnavailable, validate_target_binding


class MockModelAdapter:
    """Deterministic mock target adapter.
    
    Generates deterministic responses derived from SHA-256 digests of input text.
    Maintains session isolation state to verify reset behaviour.
    """

    def __init__(self, simulate_latency_us: int = 10_000) -> None:
        self.simulate_latency_us = simulate_latency_us
        self._sessions: Dict[str, List[TargetRequest]] = {}

    async def infer(self, request: TargetRequest) -> TargetResponse:
        """Deterministically infer response text and token counts."""
        session_key = str(request.session_id)
        if session_key not in self._sessions:
            self._sessions[session_key] = []
        self._sessions[session_key].append(request)

        # Generate deterministic pseudo-response text from input hash
        input_bytes = request.text.encode("utf-8")
        h = hashlib.sha256(input_bytes).hexdigest()
        
        # Approximate tokens
        input_tokens = max(1, len(request.text.split()))
        
        # Produce response bounded strictly by request.max_output_tokens
        # Ensure output_tokens is strictly <= max_output_tokens
        desired_tokens = min(request.max_output_tokens, max(1, int(h[:2], 16) % request.max_output_tokens + 1))
        response_words = [f"token_{h[i:i+4]}" for i in range(0, min(len(h), desired_tokens * 4), 4)]
        if not response_words:
            response_words = ["token_mock"]
        output_tokens = len(response_words)
        response_text = " ".join(response_words)

        response = TargetResponse(
            domain_id=request.domain_id,
            experiment_id=request.experiment_id,
            epoch=request.epoch,
            attempt_id=request.attempt_id,
            session_id=request.session_id,
            turn_index=request.turn_index,
            text=response_text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duration_us=self.simulate_latency_us,
        )

        # Self-verify target binding before returning
        validate_target_binding(request, response)
        return response

    async def reset(self, session_id: Uuid) -> None:
        """Reset session context, clearing cached conversation history."""
        session_key = str(session_id)
        if session_key in self._sessions:
            del self._sessions[session_key]

    def has_session(self, session_id: Uuid) -> bool:
        """Query if session has existing context (used for reset tests)."""
        return str(session_id) in self._sessions

    def session_history(self, session_id: Uuid) -> List[TargetRequest]:
        """Return history for session."""
        return list(self._sessions.get(str(session_id), []))
