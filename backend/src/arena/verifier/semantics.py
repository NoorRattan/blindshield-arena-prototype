"""N04 single-run semantic checks, independent of broker state and APIs."""

from arena.contracts.crypto import event_digest, turn_message, verify


def validate_run_semantics(
    events, start, turn_receipts, mode, actor, recorder_key, key_id
):
    if mode not in {"INPUT", "FEATURES", "OUTPUT", "POST_HOC"} or not actor:
        raise ValueError("Independently supplied verification policy is required")
    if [event.event_type for event in events[:3]] != [
        "MANIFEST_SEALED",
        "PREFLIGHT_PASSED",
        "START_RESERVED",
    ]:
        raise ValueError("Missing ordered campaign bootstrap")
    if start.event_count != 3 or start.prefix_root != event_digest(events[2]):
        raise ValueError("Witness START does not bind bootstrap prefix")
    turns, session_next, roots = {}, {}, {}
    invalid, closing = False, False
    receipts = {}
    for signed in turn_receipts:
        receipt = signed.receipt
        if receipt.turn_id in receipts:
            raise ValueError("Duplicate turn receipt")
        if receipt.signer_key_id != key_id or not verify(
            turn_message(receipt), signed.signature, recorder_key
        ):
            raise ValueError("Bad turn signature")
        receipts[receipt.turn_id] = receipt
    for index, event in enumerate(events):
        roots[event.sequence] = event_digest(event)
        if event.actor_id != actor:
            raise ValueError("Unexpected event actor")
        if index < 3:
            continue
        kind = event.event_type
        if kind in {"MANIFEST_SEALED", "PREFLIGHT_PASSED", "START_RESERVED"}:
            raise ValueError("Repeated bootstrap event")
        if kind == "INTEGRITY_VIOLATION":
            invalid = True
            continue
        if kind == "CLOSE_REQUESTED":
            if closing:
                raise ValueError("Repeated close request")
            closing = True
            if event.outcome_code == "INVALID":
                invalid = True
            continue
        if kind == "CLOSED":
            if (
                index != len(events) - 1
                or not closing
                or (invalid and event.outcome_code != "INVALID")
            ):
                raise ValueError("Invalid terminal outcome/order")
            invalid |= event.outcome_code == "INVALID"
            continue
        if closing:
            raise ValueError("Turn event after admission closed")
        key = event.turn_id
        if kind == "TURN_COMMITTED":
            if (
                key in turns
                or event.turn_index != session_next.get(event.session_id, 0)
                or not event.artifact_ciphertext_refs
            ):
                raise ValueError("Duplicate, unordered or uncommitted turn")
            if (
                len(turns) >= 24
                or len(session_next) >= 3
                and event.session_id not in session_next
            ):
                raise ValueError("N04 workload bound exceeded")
            if any(
                t["session"] == event.session_id and not t["feedback"]
                for t in turns.values()
            ):
                raise ValueError("Overlapping turns in one session")
            session_next[event.session_id] = event.turn_index + 1
            turns[key] = {
                "session": event.session_id,
                "index": event.turn_index,
                "defense": None,
                "dispatch": False,
                "model": None,
                "score": False,
                "feedback": False,
            }
            continue
        turn = turns.get(key)
        if (
            not turn
            or (event.session_id, event.turn_index) != (turn["session"], turn["index"])
            or turn["feedback"]
        ):
            raise ValueError("Unbound/late turn event")
        if kind == "DEFENSE_RESULT":
            if (
                turn["defense"] is not None
                or mode == "POST_HOC"
                or not event.artifact_ciphertext_refs
            ):
                raise ValueError("Unexpected defense result")
            if (
                mode == "OUTPUT"
                and turn["model"] != "OK"
                or mode in {"INPUT", "FEATURES"}
                and turn["dispatch"]
            ):
                raise ValueError("Defense executed in wrong mode order")
            turn["defense"] = event.outcome_code
            if event.outcome_code == "FAILED":
                invalid = True
        elif kind == "DISPATCH_INTENT":
            if (
                turn["dispatch"]
                or mode in {"INPUT", "FEATURES"}
                and turn["defense"] not in {"ALLOW", "SANITIZE"}
            ):
                raise ValueError("Unauthorized/duplicate dispatch")
            turn["dispatch"] = True
        elif kind == "MODEL_RESULT":
            if not turn["dispatch"] or turn["model"] is not None:
                raise ValueError("Model result without unique dispatch")
            if event.outcome_code == "OK" and not event.artifact_ciphertext_refs:
                raise ValueError("Missing model output artifact")
            turn["model"] = event.outcome_code
            invalid |= event.outcome_code != "OK"
        elif kind == "SCORE_RESULT":
            if (
                turn["model"] != "OK"
                or turn["score"]
                or not event.artifact_ciphertext_refs
            ):
                raise ValueError("Score without completed model/provenance")
            turn["score"] = True
            invalid |= event.outcome_code != "OK"
        elif kind == "FEEDBACK_AUTHORIZED":
            blocked = mode in {"INPUT", "FEATURES"} and turn["defense"] == "BLOCK"
            if not blocked and (turn["model"] != "OK" or not turn["score"]):
                raise ValueError("Feedback without settled execution/scoring")
            if mode == "OUTPUT" and turn["defense"] not in {
                "ALLOW",
                "BLOCK",
                "SANITIZE",
            }:
                raise ValueError("Output feedback without defense")
            receipt = receipts.pop(key, None)
            if (
                receipt is None
                or receipt.event_count != event.sequence
                or receipt.prefix_root != roots[event.sequence]
                or (
                    receipt.domain_id,
                    receipt.experiment_id,
                    receipt.epoch,
                    receipt.session_id,
                    receipt.turn_index,
                )
                != (
                    event.domain_id,
                    event.experiment_id,
                    event.epoch,
                    event.session_id,
                    event.turn_index,
                )
                or len(event.artifact_ciphertext_refs) != 2
            ):
                raise ValueError("Missing/mismatched feedback receipt")
            turn["feedback"] = True
        else:
            raise ValueError("Unsupported turn transition")
    if (
        receipts
        or not closing
        or (not invalid and any(not turn["feedback"] for turn in turns.values()))
    ):
        raise ValueError("Unsettled or extra feedback evidence")
    return invalid
