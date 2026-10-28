"""Async controller consumer. A valid signature alone cannot authorize swapped text."""

import asyncio
import base64
from contextlib import closing
from uuid import uuid4

from arena.contracts.api import AttemptResult
from arena.contracts.crypto import commitment, event_digest, turn_message, verify
from arena.contracts.evidence import ArtifactRef, SignedTurnReceipt, TurnFeedback
from arena.integration.controller import response_bytes
from arena.ports import DependencyUnavailable, TargetNotDispatched
from .policy import padded_json


def authorized_body(controller, job, result, size):
    """Bind signed prefix, actual encrypted opening, exact text and known outcome."""
    with closing(controller.store.connect()) as conn:
        stored = conn.execute("SELECT * FROM n04_turns WHERE turn_id=? AND state='DONE'", (job["turn_id"],)).fetchone()
        turn = conn.execute("SELECT * FROM turns WHERE id=? AND state='COMPLETED'", (job["turn_id"],)).fetchone()
    if not stored or not turn:
        raise DependencyUnavailable("FEEDBACK_COMPLETION_AUTHORITY_MISSING")
    signed = SignedTurnReceipt.model_validate_json(stored["receipt_json"])
    outcome = AttemptResult.model_validate_json(stored["result_json"])
    receipt = signed.receipt
    bound = {**controller.ctx.model_dump(), "session_id": job["session_id"], "turn_id": job["turn_id"], "turn_index": turn["turn_index"]}
    if (result.receipt != signed or result.turn_id != job["turn_id"] or result.result != outcome
        or outcome.integrity != "VALID_WITHIN_PROFILE"
        or any(getattr(receipt, name) != value for name, value in bound.items())
        or receipt.signer_key_id != controller.recorder.signer_key_id
        or not verify(turn_message(receipt), signed.signature, controller.recorder_public_key)):
        raise DependencyUnavailable("FEEDBACK_RECEIPT_BINDING_REJECTED")
    ref = ArtifactRef.model_validate_json(stored["feedback_ref"])
    value = controller.vault.get(ref)
    content = base64.b64decode(value["content_base64"], validate=True)
    expected = response_bytes(bound, result.public_reply, "COMPLETED")
    if (content != expected or commitment(content, bytes.fromhex(value["nonce_hex"])) != receipt.public_response_commitment
        or base64.b64decode(value["public_reply_utf8_base64"], validate=True).decode("utf-8") != result.public_reply
        or AttemptResult.model_validate(value["result"]) != outcome):
        raise DependencyUnavailable("FEEDBACK_PRIVATE_OPENING_REJECTED")
    events = controller.recorder.get_events(controller.ctx)
    if receipt.event_count > len(events):
        raise DependencyUnavailable("FEEDBACK_PREFIX_MISSING")
    event = events[receipt.event_count - 1]
    if (event.event_type != "FEEDBACK_AUTHORIZED" or event.turn_id != job["turn_id"]
        or event_digest(event) != receipt.prefix_root or ref not in event.artifact_ciphertext_refs):
        raise DependencyUnavailable("FEEDBACK_AUTHORIZATION_PREFIX_REJECTED")
    feedback = TurnFeedback(turn_id=job["turn_id"], session_id=job["session_id"], turn_index=turn["turn_index"],
                            public_reply=result.public_reply, public_status="COMPLETED", feedback_receipt=signed, padding="")
    return padded_json(feedback.model_dump(), size)


class AsyncTurnWorker:
    def __init__(self, queue, controller, resolve_payload):
        self.queue, self.controller, self.resolve_payload = queue, controller, resolve_payload
        self.worker_id = str(uuid4())
        self.tasks = set()
        self.failure_audit_acknowledged = []  # Private diagnostics, never participant counters.

    async def _failure(self, job, fallback="UNKNOWN"):
        try:
            self.queue.fail_claim(job, self.worker_id, fallback=fallback)
        except Exception:
            # Poll/explicit recovery may already have failed it; never authorize a late result.
            pass
        acknowledged = False
        try:
            with closing(self.controller.store.connect()) as conn:
                turn = conn.execute("SELECT turn_index FROM turns WHERE id=?", (job["turn_id"],)).fetchone()
            await self.controller._event("INTEGRITY_VIOLATION", "FAILED", turn={**self.controller.ctx.model_dump(),
                                          "session_id": job["session_id"], "turn_id": job["turn_id"], "turn_index": turn[0]})
            acknowledged = True
        except Exception:
            pass  # This cannot become a signed public failure/finding or successful close.
        self.failure_audit_acknowledged.append(acknowledged)
        self.controller.store.operator_alert("AUDIT_UNAVAILABLE", 503)

    async def run_once(self):
        if len(self.tasks) >= 3:
            raise DependencyUnavailable("WORKER_CONCURRENCY_CAPACITY_EXCEEDED")
        job = self.queue.claim(self.controller.ctx, self.worker_id)
        if job is None:
            return False
        task = None
        entered_controller = False
        try:
            principal, request = self.queue.request_for(job)
            # Resolution and controller work share the original admission deadline.
            async def execute():
                nonlocal entered_controller
                payload = await self.resolve_payload(request, job)
                self.queue.dispatch_ready(job, self.worker_id)
                entered_controller = True
                return await self.controller.turn(principal, job["session_id"], request, job["client_key"], payload)
            remaining = (job["deadline_ns"] - self.queue.clock_ns()) / 1_000_000_000
            if remaining <= 0:
                raise DependencyUnavailable("ADMISSION_DEADLINE_EXCEEDED")
            task = asyncio.create_task(execute())
            self.tasks.add(task)
            def settled(future):
                self.tasks.discard(future)
                if not future.cancelled():
                    future.exception()  # Retrieve diagnostics without emitting untrusted error text.
            task.add_done_callback(settled)
            done, _ = await asyncio.wait({task}, timeout=remaining)
            if not done:
                raise DependencyUnavailable("EXECUTION_DEADLINE_EXCEEDED")
            result = task.result()
            with closing(self.queue.store.connect()) as conn:
                run = conn.execute("SELECT * FROM experiments WHERE id=?", (job["experiment_id"],)).fetchone()
                policy = self.queue._policy(conn, run)
            body = authorized_body(self.controller, job, result, policy.body_bytes)
            if not self.queue._save_authorized(job, self.worker_id, body):
                await self._failure(job)
        except BaseException as error:
            if task is not None and not task.done():
                task.cancel()
            known_before_dispatch = not entered_controller or isinstance(error, TargetNotDispatched)
            await self._failure(job, "NOT_EVALUATED" if known_before_dispatch else "UNKNOWN")
            if isinstance(error, asyncio.CancelledError):
                raise
        return True

    async def drain(self, timeout=1):
        """Bounded shutdown; False means tasks remain quarantined, not stopped."""
        remaining = set(self.tasks)
        for task in remaining:
            task.cancel()
        if not remaining:
            return True
        _, pending = await asyncio.wait(remaining, timeout=timeout)
        return not pending
