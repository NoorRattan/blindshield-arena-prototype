"""Strict 9-symbol defense adapter implementing the frozen broker policy."""

from __future__ import annotations

from typing import Optional, Set, Tuple

from ..contracts.api import (
    DefenseDecision,
    DefenseRequest,
    FeaturesDefenseRequest,
    InputDefenseRequest,
    OutputDefenseRequest,
    PostHocDefenseRequest,
)
from ..ports import DependencyUnavailable

# The exactly nine valid (verdict, reason_code, transform_id) tuples from canonical contract
VALID_DEFENSE_TUPLES: Set[Tuple[str, str, Optional[str]]] = {
    ("ALLOW", "NONE", None),
    ("BLOCK", "INJECTION_PATTERN", None),
    ("BLOCK", "TOXICITY_PATTERN", None),
    ("BLOCK", "SCHEMA_POLICY", None),
    ("BLOCK", "UNSUPPORTED", None),
    ("BLOCK", "BUDGET_POLICY", None),
    ("SANITIZE", "INJECTION_PATTERN", "REDACT_REGISTERED_MATCHES_V1"),
    ("SANITIZE", "TOXICITY_PATTERN", "REDACT_REGISTERED_MATCHES_V1"),
    ("SANITIZE", "SCHEMA_POLICY", "REDACT_REGISTERED_MATCHES_V1"),
}


class MockDefenseAdapter:
    """Evaluates defense requests strictly producing one of the 9 valid symbols."""

    def __init__(
        self,
        default_verdict: str = "ALLOW",
        default_reason: str = "NONE",
        default_transform: Optional[str] = None,
    ) -> None:
        self.set_forced_decision(default_verdict, default_reason, default_transform)
        self.pattern_rules = {
            "injection": ("BLOCK", "INJECTION_PATTERN", None),
            "sanitize_injection": ("SANITIZE", "INJECTION_PATTERN", "REDACT_REGISTERED_MATCHES_V1"),
            "toxic": ("BLOCK", "TOXICITY_PATTERN", None),
            "sanitize_toxic": ("SANITIZE", "TOXICITY_PATTERN", "REDACT_REGISTERED_MATCHES_V1"),
            "schema_violation": ("BLOCK", "SCHEMA_POLICY", None),
            "budget_exceeded": ("BLOCK", "BUDGET_POLICY", None),
            "unsupported_feature": ("BLOCK", "UNSUPPORTED", None),
        }
        self.dynamic_mode = False

    def set_forced_decision(self, verdict: str, reason_code: str, transform_id: Optional[str]) -> None:
        """Force a specific decision tuple, validating against the 9 allowed symbols."""
        symbol = (verdict, reason_code, transform_id)
        if symbol not in VALID_DEFENSE_TUPLES:
            raise DependencyUnavailable(f"INVALID_DEFENSE_SYMBOL: {symbol}")
        self._forced = symbol
        self.dynamic_mode = False

    def enable_dynamic_evaluation(self) -> None:
        """Switch to dynamic content matching mode."""
        self.dynamic_mode = True

    async def evaluate(self, request: DefenseRequest) -> DefenseDecision:
        """Evaluate defense request and return verified DefenseDecision."""
        call_token = request.call_token

        if not self.dynamic_mode:
            verdict, reason_code, transform_id = self._forced
            return DefenseDecision(
                call_token=call_token,
                verdict=verdict,  # type: ignore[arg-type]
                reason_code=reason_code,  # type: ignore[arg-type]
                transform_id=transform_id,  # type: ignore[arg-type]
            )

        # Dynamic inspection mode
        text_to_check = ""
        if isinstance(request, InputDefenseRequest):
            text_to_check = request.content.prompt.lower()
        elif isinstance(request, OutputDefenseRequest):
            text_to_check = request.content.response.lower()
        elif isinstance(request, PostHocDefenseRequest):
            text_to_check = f"{request.content.prompt} {request.content.response}".lower()
        elif isinstance(request, FeaturesDefenseRequest):
            if request.content.control_marker_present:
                return DefenseDecision(
                    call_token=call_token,
                    verdict="BLOCK",
                    reason_code="SCHEMA_POLICY",
                    transform_id=None,
                )
            if request.content.length_bucket == "LONG":
                return DefenseDecision(
                    call_token=call_token,
                    verdict="BLOCK",
                    reason_code="BUDGET_POLICY",
                    transform_id=None,
                )
            return DefenseDecision(
                call_token=call_token,
                verdict="ALLOW",
                reason_code="NONE",
                transform_id=None,
            )

        # Keyword based decisions for text content
        harmful_keywords = (
            "toxic", "harmful", "cyberattack", "disinformation", "fraud",
            "hate speech", "harassment", "physical harm", "privacy violation", "weapons"
        )
        if "sanitize injection" in text_to_check:
            verdict, reason_code, transform_id = self.pattern_rules["sanitize_injection"]
        elif "injection" in text_to_check or "jailbreak" in text_to_check or "ignore previous" in text_to_check:
            verdict, reason_code, transform_id = self.pattern_rules["injection"]
        elif "sanitize toxic" in text_to_check:
            verdict, reason_code, transform_id = self.pattern_rules["sanitize_toxic"]
        elif any(kw in text_to_check for kw in harmful_keywords):
            verdict, reason_code, transform_id = self.pattern_rules["toxic"]
        elif "schema violation" in text_to_check:
            verdict, reason_code, transform_id = self.pattern_rules["schema_violation"]
        elif "budget exceeded" in text_to_check:
            verdict, reason_code, transform_id = self.pattern_rules["budget_exceeded"]
        elif "unsupported" in text_to_check:
            verdict, reason_code, transform_id = self.pattern_rules["unsupported_feature"]
        else:
            verdict, reason_code, transform_id = ("ALLOW", "NONE", None)

        return DefenseDecision(
            call_token=call_token,
            verdict=verdict,  # type: ignore[arg-type]
            reason_code=reason_code,  # type: ignore[arg-type]
            transform_id=transform_id,  # type: ignore[arg-type]
        )
