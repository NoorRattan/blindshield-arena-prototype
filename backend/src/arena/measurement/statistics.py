"""Timing-only rank score and campaign-block bootstrap, no numerical dependency."""

import math
import random


def auc(rows, direction=1):
    if direction not in (-1, 1) or not rows or any(type(r["label"]) is not int or r["label"] not in (0, 1)
        or type(r["latency_ns"]) is not int or r["latency_ns"] < 0 for r in rows):
        raise ValueError("INVALID_TIMING_SAMPLES")
    ordered = sorted((direction*r["latency_ns"], r["label"]) for r in rows)
    positive = sum(label for _, label in ordered)
    negative = len(ordered) - positive
    if not positive or not negative:
        raise ValueError("BOTH_TIMING_CLASSES_REQUIRED")
    u, below, i = 0.0, 0, 0
    while i < len(ordered):
        j = i
        while j < len(ordered) and ordered[j][0] == ordered[i][0]: j += 1
        pos = sum(label for _, label in ordered[i:j]); neg = j-i-pos
        u += pos * (below + .5*neg)
        below += neg; i = j
    return u / (positive*negative)


def block_interval(rows, direction, *, seed, repetitions=1000):
    """Resample whole balanced campaigns, preserving their internal correlation."""
    blocks = {}
    for row in rows: blocks.setdefault(row["campaign"], []).append(row)
    groups = list(blocks.values())
    if len(groups) < 2 or any({r["label"] for r in group} != {0, 1} for group in groups):
        raise ValueError("BALANCED_INDEPENDENT_CAMPAIGN_BLOCKS_REQUIRED")
    if type(repetitions) is not int or repetitions < 100:
        raise ValueError("BOOTSTRAP_REPETITIONS_TOO_SMALL")
    rng = random.Random(seed)
    scores = sorted(auc([row for _ in groups for row in rng.choice(groups)], direction) for _ in range(repetitions))
    return [scores[math.floor(.025*(repetitions-1))], scores[math.ceil(.975*(repetitions-1))]]


def analyze_timing(rows):
    if len(rows) != 672:
        raise ValueError("PREDECLARED_TIMING_COUNTS_REQUIRED")
    results = {}
    for arm in ("UNSHAPED_SYNTHETIC_CONTROL", "SHAPED"):
        selection = [r for r in rows if r["arm"] == arm and r["phase"] == "selection"]
        validation = [r for r in rows if r["arm"] == arm and r["phase"] == "validation"]
        if len(selection) != 96 or len(validation) != 240:
            raise ValueError("PREDECLARED_TIMING_COUNTS_REQUIRED")
        for phase_rows, expected_blocks in ((selection, 4), (validation, 10)):
            blocks = {}
            for row in phase_rows: blocks.setdefault(row["campaign"], []).append(row)
            if len(blocks) != expected_blocks or any(len(group) != 24 or sum(r["label"] for r in group) != 12
                or sorted(r["index"] for r in group) != list(range(24)) for group in blocks.values()):
                raise ValueError("PREDECLARED_BALANCED_UNIQUE_CAMPAIGNS_REQUIRED")
        direction = 1 if auc(selection) >= .5 else -1
        point = auc(validation, direction)
        interval = block_interval(validation, direction, seed=260622)
        errors = sum(r["status"] != 200 or r["body_bytes"] != 4096 for r in selection+validation)
        results[arm] = {"selection_samples": len(selection), "held_out_samples": len(validation),
            "direction_frozen_from_selection": direction, "held_out_timing_auc": point, "campaign_bootstrap_95": interval,
            "transport_or_pipeline_failures": errors, "early_publications": sum(r["early_publication"] for r in validation),
            "held_out_campaigns": len({r["campaign"] for r in validation})}
    control, shaped = results["UNSHAPED_SYNTHETIC_CONTROL"], results["SHAPED"]
    detectable = control["held_out_timing_auc"] >= .8 and control["campaign_bootstrap_95"][0] > .65 and control["early_publications"] > 0 and not control["transport_or_pipeline_failures"]
    within = .4 <= shaped["held_out_timing_auc"] <= .6 and shaped["campaign_bootstrap_95"][0] >= .35 and shaped["campaign_bootstrap_95"][1] <= .65
    result = "WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE" if detectable and within and not shaped["transport_or_pipeline_failures"] and not shaped["early_publications"] else "INCONCLUSIVE_OR_OUTSIDE_ENVELOPE"
    return {"scope": "SYNTHETIC_LOOPBACK_TIMING_ONLY_NOT_REAL_MODEL_OR_CHANNEL_CAPACITY", "result": result, "arms": results,
        "negative_control_detectable": detectable, "envelope_predeclared": {"point": [.4, .6], "bootstrap_95": [.35, .65]},
        "campaign_independence_established": False, "real_model_timing_auc_measured": False,
        "p99_certified": False, "zero_leakage_proven": False, "public_admission": False}
