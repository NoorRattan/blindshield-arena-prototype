"""Bounded HTTP observation; retries preserve one logical admission identity."""

import asyncio
import json
import time


async def observe_turn(send, *, floor_ms, admission_timeout_ms=12000, clock=time.monotonic_ns, sleep=asyncio.sleep):
    """send(method, turn_id) closes over an immutable POST body and key.

    ACK uncertainty permits only that exact POST retry. A caller must not advance
    its turn index until accepted=True, or reuse an uncertain lane for new work.
    Every failed attempt stays visible; no sample is silently replaced.
    """
    start = clock()
    admissions, poll_errors, counts = [], [], {}
    accepted, turn, status, size, error = False, None, 0, 0, None
    admission_end = start + admission_timeout_ms * 1_000_000
    while clock() < admission_end and len(admissions) < 200:
        try:
            status, body, _ = await send("POST", None)
            value = json.loads(body)
            admissions.append({"status": status, "body_bytes": len(body)})
            if status == 202 and value.get("status") == "ACCEPTED":
                turn = value["turn_id"]
                accepted = True
                break
            if status != 429 or value.get("status") != "RETRY_LATER":
                error = "ADMISSION_REJECTED"
                break
        except Exception as exc:
            admissions.append({"status": 0, "error_type": type(exc).__name__})
        await sleep(.05)
    if not accepted and error is None:
        error, status = "ACK_UNCERTAIN_OR_ADMISSION_TIMEOUT", 0
    if accepted:
        limit = clock() + (floor_ms + 5000) * 1_000_000
        while clock() < limit:
            try:
                status, body, _ = await send("GET", turn)
                size = len(body)
                counts[str(status)] = counts.get(str(status), 0) + 1
                if status != 202:
                    break
            except Exception as exc:
                poll_errors.append(type(exc).__name__)
            await sleep(.025)
        else:
            status, error = 0, "FEEDBACK_OBSERVER_TIMEOUT"
    return {"latency_ns": clock()-start, "status": status, "body_bytes": size,
        "accepted": accepted, "turn_id": turn, "admission_attempts": admissions,
        "poll_status_counts": counts, "poll_errors": poll_errors, "error_type": error}
