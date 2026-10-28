"""Frozen finite-symbol demonstration defense. No safety-classifier accuracy claim."""

import json
import sys

# Bounded literal rules, identical to the broker's sealed transform policy.
BLOCK = ("ignore previous", "jailbreak", "injection_control")
SANITIZE = ("sanitize_control",)


def main():
    raw = sys.stdin.buffer.read(70001)
    if len(raw) > 70000:
        return 2
    request = json.loads(raw)
    if set(request) != {"call_token", "mode", "content"}:
        return 2
    mode, content = request["mode"], request["content"]
    if mode == "FEATURES":
        if set(content) != {"length_bucket", "control_marker_present"}:
            return 2
        verdict = "BLOCK" if content["control_marker_present"] else "ALLOW"
    else:
        expected = {
            "INPUT": {"prompt"},
            "OUTPUT": {"response"},
            "POST_HOC": {"prompt", "response"},
        }
        if (
            mode not in expected
            or set(content) != expected[mode]
            or any(type(value) is not str for value in content.values())
        ):
            return 2
        text = "\n".join(content.values()).lower()
        verdict = (
            "BLOCK"
            if any(rule in text for rule in BLOCK)
            else "SANITIZE"
            if any(rule in text for rule in SANITIZE)
            else "ALLOW"
        )
    print(
        json.dumps(
            {
                "call_token": request["call_token"],
                "verdict": verdict,
                "reason_code": "NONE" if verdict == "ALLOW" else "INJECTION_PATTERN",
                "transform_id": "REDACT_REGISTERED_MATCHES_V1"
                if verdict == "SANITIZE"
                else None,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
