"""Protocol-bound analysis. No failed admission, poll or observation is dropped."""

from .statistics import auc, block_interval


def analyze(rows, protocol):
    arms = ("UNSHAPED_SYNTHETIC_CONTROL", "SHAPED")
    size = protocol["turns_per_campaign"]
    expected = size * (protocol["selection_campaigns_per_arm"]+protocol["validation_campaigns_per_arm"]) * 2
    if len(rows) != expected:
        raise ValueError("EXACT_PROTOCOL_OBSERVATIONS_REQUIRED")
    results = {}
    for arm in arms:
        phases = {}
        for phase in ("selection", "validation"):
            subset = [r for r in rows if r["arm"] == arm and r["phase"] == phase]
            campaigns = protocol[phase+"_campaigns_per_arm"]
            if len(subset) != campaigns*size:
                raise ValueError("EXACT_PROTOCOL_PHASE_REQUIRED")
            for campaign in range(campaigns):
                block = [r for r in subset if r["campaign"] == campaign]
                if (sorted(r["index"] for r in block) != list(range(size))
                    or sum(r["label"] for r in block) != size//2):
                    raise ValueError("UNIQUE_BALANCED_CAMPAIGN_REQUIRED")
            phases[phase] = subset
        direction = 1 if auc(phases["selection"]) >= .5 else -1
        observed = phases["selection"] + phases["validation"]
        failures = sum(r["status"] != 200 or r["body_bytes"] != protocol["body_bytes"] or r["error_type"] is not None for r in observed)
        retry_errors = sum(any(a["status"] != 202 for a in r["admission_attempts"]) or bool(r["poll_errors"]) for r in observed)
        results[arm] = {"selection_samples": len(phases["selection"]), "held_out_samples": len(phases["validation"]),
            "direction_frozen_from_selection": direction, "held_out_timing_auc": auc(phases["validation"], direction),
            "campaign_bootstrap_95": block_interval(phases["validation"], direction, seed=protocol["seed"]),
            "transport_or_pipeline_failures": failures, "observations_with_retries_or_transport_errors": retry_errors,
            "early_publications": sum(r["early_publication"] for r in phases["validation"]),
            "held_out_campaigns": protocol["validation_campaigns_per_arm"]}
    control, shaped = (results[a] for a in arms)
    detected = (control["held_out_timing_auc"] >= .8 and control["campaign_bootstrap_95"][0] > .65
        and control["early_publications"] > 0 and not control["transport_or_pipeline_failures"]
        and not control["observations_with_retries_or_transport_errors"])
    point, ci = protocol["shaped_envelope"]["point"], protocol["shaped_envelope"]["bootstrap_95"]
    within = (point[0] <= shaped["held_out_timing_auc"] <= point[1] and shaped["campaign_bootstrap_95"][0] >= ci[0]
        and shaped["campaign_bootstrap_95"][1] <= ci[1] and not shaped["transport_or_pipeline_failures"]
        and not shaped["observations_with_retries_or_transport_errors"] and not shaped["early_publications"])
    return {"scope": protocol["scope"], "result": "WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE" if detected and within else "INCONCLUSIVE_OR_OUTSIDE_ENVELOPE",
        "negative_control_detectable": detected, "arms": results, "envelope_predeclared": protocol["shaped_envelope"],
        "campaign_independence_established": False, "p99_certified": False, "zero_leakage_proven": False,
        "real_model": protocol["real_model"], "public_admission": False}
