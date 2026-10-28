"""Arena evaluation, rubrics, baselines, and statistical analysis package."""

from .rubric import (
    validate_defense_symbol_channel,
    evaluate_refusal_rubric,
    MAX_COVERT_CHANNEL_BITS_PER_CALL,
)
from .baseline import (
    run_benign_utility_evaluation,
    run_deny_all_negative_control,
    BaselineEvaluationResult,
)
from .analysis import (
    wilson_score_interval,
    compute_latency_percentiles,
    compute_contention_shift_pct,
)

__all__ = [
    "validate_defense_symbol_channel",
    "evaluate_refusal_rubric",
    "MAX_COVERT_CHANNEL_BITS_PER_CALL",
    "run_benign_utility_evaluation",
    "run_deny_all_negative_control",
    "BaselineEvaluationResult",
    "wilson_score_interval",
    "compute_latency_percentiles",
    "compute_contention_shift_pct",
]
