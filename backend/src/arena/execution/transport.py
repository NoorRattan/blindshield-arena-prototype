"""Opt-in loopback mTLS measurement profile; never general public admission.

An admission round closes BEFORE any payload resolver/defense/model runs. New
admissions then remain closed until the latest frozen release time, independently
of private success/failure. HTTP threads never wait for inference or recorder I/O.
"""

import asyncio
from contextlib import closing
import json
import re
import threading
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import Field, TypeAdapter, model_validator

from arena.broker.config import Profile
from arena.broker.store import BrokerError
from arena.contracts.api import EpochRequest, TurnSubmission
from arena.contracts.common import ClientKey, Context, Digest, ErrorCode, Opaque, Signature, Uuid, WireModel
from arena.contracts.crypto import canonical_bytes, sha256, verify
from arena.contracts.jsonwire import load_wire
from arena.contracts.evidence import ArtifactRef
from arena.ports import DependencyUnavailable
from .policy import disclosure_id, padded_json
from arena.contracts.transport_profile import LabProfile, SignedLabProfile, lab_message


class ExecutionEnvelope(WireModel):
    schema_version: Literal["arena.execution.v1"] = "arena.execution.v1"
    status: Literal["ACCEPTED", "PENDING", "RETRY_LATER", "CANCEL_REQUESTED", "EMBARGOED", "CONTROLLED", "UNAVAILABLE", "ERROR"]
    turn_id: Uuid | None = None
    session_id: Uuid | None = None
    code: ErrorCode | None = None
    padding: str

    @model_validator(mode="after")
    def alphabet(self):
        if (self.status == "ACCEPTED") != (self.turn_id is not None and self.session_id is not None):
            raise ValueError("ACCEPTANCE_IDENTIFIERS_REQUIRED")
        if self.status != "ACCEPTED" and (self.turn_id is not None or self.session_id is not None):
            raise ValueError("UNEXPECTED_RESPONSE_IDENTIFIER")
        if (self.status == "ERROR") != (self.code is not None):
            raise ValueError("ERROR_CODE_REQUIRED")
        return self


SCHEMA = """
CREATE TABLE IF NOT EXISTS n06_lab_runs(
 experiment_id TEXT PRIMARY KEY REFERENCES experiments(id), owner TEXT NOT NULL,
 clock_id TEXT NOT NULL, state TEXT NOT NULL, profile_json TEXT NOT NULL,
 opens_ns INTEGER, closes_ns INTEGER, unblocks_ns INTEGER);
CREATE TABLE IF NOT EXISTS n06_lab_actions(
 operation_id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
 session_id TEXT NOT NULL REFERENCES sessions(id), detail_ref TEXT NOT NULL REFERENCES payloads(artifact_id),
 artifact_ref TEXT, acknowledged INTEGER NOT NULL DEFAULT 0,
 UNIQUE(experiment_id,session_id));
"""


class ParticipantGateway:
    def __init__(self, operator, worker, signed, public_key, key_id, *, admission=None):
        signed = SignedLabProfile.model_validate(signed.model_dump())
        if signed.signer_key_id != key_id or not verify(lab_message(signed.profile, key_id), signed.signature, public_key):
            raise DependencyUnavailable("LOCAL_PROFILE_SIGNATURE_REJECTED")
        self.worker, self.controller = worker, worker.controller
        self.queue, self.broker, self.store = worker.queue, worker.queue.broker, worker.queue.store
        self.ctx, self.profile = self.controller.ctx, signed.profile
        self.owner = str(uuid4())
        self.lock = threading.RLock()
        self.accepting = True
        self.stopped = False
        self.draining = False
        self.active = set()
        self.pump_error = False
        self.broker._role(operator, "operator")
        with closing(self.store.connect()) as conn:
            conn.executescript(SCHEMA)
        with self.store.transaction() as conn:
            run = self.broker._object(conn, operator, self.ctx.experiment_id, self.ctx.epoch)
            profile = Profile.model_validate_json(run["config_json"])
            policy = self.queue._policy(conn, run)
            manifest = self.store.read_payload(run["manifest_id"])["manifest"]
            if "n06_transport" in manifest or admission is not None:
                if admission is None:
                    raise DependencyUnavailable("SEALED_TRANSPORT_TRUST_REQUIRED")
                plan = admission.check_manifest(manifest, self.ctx)
                if (plan.transport != signed or admission.trust.transport_public_key != public_key
                    or admission.trust.transport_key_id != key_id or plan.feedback != self._signed_policy(conn)):
                    raise DependencyUnavailable("SEALED_TRANSPORT_RUNTIME_MISMATCH")
            binding = {key: getattr(self.profile, key) for key in self.ctx.model_dump()}
            n04 = conn.execute("SELECT state,start_json FROM n04_runs WHERE experiment_id=?", (self.ctx.experiment_id,)).fetchone()
            sessions = list(conn.execute("SELECT owner,lane FROM sessions WHERE experiment_id=?", (self.ctx.experiment_id,)))
            if (binding != self.ctx.model_dump() or profile.execution_lock_sha256 != self.profile.execution_lock_sha256
                or sha256(policy.model_dump_json().encode()) != self.profile.feedback_policy_sha256
                or profile.request.disclosure_profile_id != disclosure_id(self._signed_policy(conn))
                or profile.request.interaction_mode != "INTERACTIVE"
                or run["phase"] != "RUNNING" or run["integrity"] == "INVALID"
                or not n04 or n04["state"] != "RUNNING" or not n04["start_json"]
                or len(sessions) != profile.session_limit or not 1 <= len(sessions) <= 3
                or {s["lane"] for s in sessions} != set(range(len(sessions)))
                or any(s["owner"] != profile.red_subject_id for s in sessions)
                or policy.execution_deadline_ms <= self.profile.admission_window_ms
                or conn.execute("SELECT 1 FROM n06_jobs WHERE experiment_id=?", (self.ctx.experiment_id,)).fetchone()
                or conn.execute("SELECT 1 FROM n06_lab_runs WHERE experiment_id=?", (self.ctx.experiment_id,)).fetchone()):
                raise DependencyUnavailable("FRESH_AUTHORITATIVE_LOCAL_RUN_REQUIRED")
            self.size = policy.body_bytes
            conn.execute("INSERT INTO n06_lab_runs(experiment_id,owner,clock_id,state,profile_json) VALUES(?,?,?,'ACTIVE',?)",
                         (self.ctx.experiment_id, self.owner, self.queue.clock_id, signed.model_dump_json()))

    def _signed_policy(self, conn):
        from .policy import SignedPolicy
        return SignedPolicy.model_validate_json(conn.execute("SELECT signed_json FROM n06_policies WHERE experiment_id=?", (self.ctx.experiment_id,)).fetchone()[0])

    def envelope(self, status, name, **fields):
        value = ExecutionEnvelope(status=name, padding="", **fields).model_dump(exclude_none=True)
        return status, padded_json(value, self.size)

    def error(self, status, code):
        # No exception text, phase, worker state, elapsed time or request-derived values.
        return self.envelope(status, "ERROR", code=code)

    def _access(self, principal, identifier, session=None, epoch=None):
        if identifier != self.ctx.experiment_id:
            raise BrokerError("NOT_FOUND", 404)
        with closing(self.store.connect()) as conn:
            run = self.broker._object(conn, principal, identifier, epoch)
            if session is not None:
                self.broker._role(principal, "red")
                self.broker._session(conn, run, session, principal.subject_id)

    def submit(self, principal, session, request, key):
        self.broker._role(principal, "red")
        TypeAdapter(ClientKey).validate_python(key)
        with self.lock:
            self._access(principal, self.ctx.experiment_id, session, request.epoch)
            with closing(self.store.connect()) as conn:
                # Test presence only. The broker still validates the exact HMAC body+route
                # and owner/epoch scope, including replays after failure/phase advance.
                replay = conn.execute("SELECT 1 FROM idempotency WHERE subject_id=? AND domain_id=? AND experiment_id=? AND epoch=? AND action='turns' AND client_key=?",
                    (principal.subject_id, principal.domain_id, self.ctx.experiment_id, request.epoch, key)).fetchone()
                state = conn.execute("SELECT * FROM n06_lab_runs WHERE experiment_id=?", (self.ctx.experiment_id,)).fetchone()
                outstanding = conn.execute("SELECT 1 FROM n06_jobs WHERE experiment_id=? AND published=0", (self.ctx.experiment_id,)).fetchone()
            now = self.queue.clock_ns()
            if not replay:
                if (not self.accepting or self.pump_error or state["owner"] != self.owner or state["clock_id"] != self.queue.clock_id
                    or state["state"] != "ACTIVE"):
                    return self.envelope(429, "RETRY_LATER")
                if state["closes_ns"] is not None and now >= state["closes_ns"]:
                    if now < state["unblocks_ns"] or outstanding or self.active or self.worker.tasks:
                        return self.envelope(429, "RETRY_LATER")
                    with self.store.transaction() as conn:
                        conn.execute("UPDATE n06_lab_runs SET opens_ns=NULL,closes_ns=NULL,unblocks_ns=NULL WHERE experiment_id=?", (self.ctx.experiment_id,))
                    state = dict(state) | {"opens_ns": None, "closes_ns": None}
            def round_admission(conn, run, turn_id):
                job = conn.execute("SELECT admitted_ns,release_ns FROM n06_jobs WHERE turn_id=?", (turn_id,)).fetchone()
                opens = state["opens_ns"] if state["opens_ns"] is not None else job["admitted_ns"]
                closes = state["closes_ns"] if state["closes_ns"] is not None else opens + self.profile.admission_window_ms * 1_000_000
                if job["admitted_ns"] >= closes:
                    raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
                conn.execute("UPDATE n06_lab_runs SET opens_ns=?,closes_ns=?,unblocks_ns=max(coalesce(unblocks_ns,0),?) WHERE experiment_id=?",
                             (opens, closes, job["release_ns"], self.ctx.experiment_id))
            _, receipt = self.queue.submit(principal, self.ctx.experiment_id, session, request, key, on_enqueued=round_admission)
            return self.envelope(202, "ACCEPTED", turn_id=receipt["turn_id"], session_id=session)

    def cancel(self, principal, session, request, key):
        self.broker._role(principal, "red")
        TypeAdapter(ClientKey).validate_python(key)
        with self.lock:
            self._access(principal, self.ctx.experiment_id, session, request.epoch)
            if self.draining or self.stopped:
                with closing(self.store.connect()) as conn:
                    old = conn.execute("SELECT 1 FROM n06_lab_actions WHERE experiment_id=? AND session_id=?", (self.ctx.experiment_id, session)).fetchone()
                # Known durable intent may be acknowledged again; a late HTTP
                # handler cannot create fresh control work after quiescence.
                return self.envelope(202, "CANCEL_REQUESTED") if old else self.envelope(503, "UNAVAILABLE")
            def operation(conn, run):
                old = conn.execute("SELECT operation_id FROM n06_lab_actions WHERE experiment_id=? AND session_id=?", (self.ctx.experiment_id, session)).fetchone()
                if old:
                    return 202, {"operation_id": old[0]}
                operation_id = str(uuid4())
                # Intent invalidates the campaign, but cannot erase already known execution
                # or rewrite a previously published signed response. No refund or requeue.
                jobs = conn.execute("SELECT * FROM n06_jobs WHERE experiment_id=? AND session_id=? AND published=0", (self.ctx.experiment_id, session)).fetchall()
                for job in jobs:
                    self.queue._fail(conn, job, "NOT_EVALUATED" if job["state"] == "QUEUED" else "UNKNOWN")
                detail = {"kind": "N06_CANCEL_INTENT", "operation_id": operation_id, "context": self.ctx.model_dump(),
                    "session_id": session, "worker_stopped_proven": False,
                    "affected_turns": [{"turn_id": j["turn_id"], "state_before_cancel": j["state"],
                        "known_execution": self.queue._known(conn, j["turn_id"], "NOT_EVALUATED" if j["state"] == "QUEUED" else "UNKNOWN")}
                        for j in jobs]}
                ref = self.store.put_payload(conn, run, "n06-cancel-intent", detail)
                conn.execute("INSERT INTO n06_lab_actions(operation_id,experiment_id,session_id,detail_ref) VALUES(?,?,?,?)",
                    (operation_id, self.ctx.experiment_id, session, ref))
                conn.execute("UPDATE sessions SET quarantined=1 WHERE id=?", (session,))
                conn.execute("UPDATE experiments SET phase='INVALID',integrity='INVALID' WHERE id=? AND phase NOT IN ('CLOSED','RELEASED')", (self.ctx.experiment_id,))
                conn.execute("UPDATE n04_runs SET state='INVALID' WHERE experiment_id=? AND state NOT IN ('CLOSED','RELEASED')", (self.ctx.experiment_id,))
                return 202, {"operation_id": operation_id}
            self.broker._mutate(principal, self.ctx.experiment_id, request, "n06-cancel", key,
                f"/v1/experiments/{self.ctx.experiment_id}/sessions/{session}/cancel", operation)
            return self.envelope(202, "CANCEL_REQUESTED")

    def dispatch(self, principal, method, path, headers, body):
        if any(c in path for c in ("?", "%", "#")):
            raise BrokerError("NOT_FOUND", 404)
        matched = re.fullmatch(r"/v1/experiments/([^/]+)/(status|feedback|sessions/([^/]+)/(turns(?:/([^/]+))?|cancel))", path)
        if not matched:
            raise BrokerError("NOT_FOUND", 404)
        identifier, action, session, subaction, turn = matched.groups()
        for value in (identifier, session, turn):
            if value is not None:
                try:
                    TypeAdapter(Uuid).validate_python(value)
                except ValueError:
                    raise BrokerError("NOT_FOUND", 404) from None
        self._access(principal, identifier)
        if method == "GET" and action in {"status", "feedback"}:
            self.broker._role(principal, "red", "blue-human")
            return self.envelope(200, "EMBARGOED" if principal.role == "blue-human" else "CONTROLLED")
        self.broker._role(principal, "red")
        if method == "POST" and session and subaction == "turns" and turn is None:
            return self.submit(principal, session, load_wire(TurnSubmission, body), headers.get("idempotency-key"))
        if method == "POST" and session and subaction == "cancel":
            return self.cancel(principal, session, load_wire(EpochRequest, body), headers.get("idempotency-key"))
        if method == "GET" and session and turn:
            with self.lock:
                projection = self.queue.project(principal, self.ctx, session, turn)
            if projection.status != 200:
                return self.envelope(projection.status, json.loads(projection.body)["status"])
            return projection.status, projection.body
        raise BrokerError("NOT_FOUND", 404)

    async def flush_actions(self):
        with closing(self.store.connect()) as conn:
            rows = list(conn.execute("SELECT * FROM n06_lab_actions WHERE experiment_id=? AND acknowledged=0", (self.ctx.experiment_id,)))
        for row in rows:
            # A signed integrity-violation ACK records the cancellation intent. It is
            # neither a completed turn receipt nor proof that a worker has stopped.
            if row["artifact_ref"] is None:
                artifact = self.controller._artifact(self.store.read_payload(row["detail_ref"]), "PRIVATE_MANIFEST")
                with self.store.transaction() as conn:
                    conn.execute("UPDATE n06_lab_actions SET artifact_ref=? WHERE operation_id=?", (artifact.model_dump_json(), row["operation_id"]))
            else:
                artifact = ArtifactRef.model_validate_json(row["artifact_ref"])
            await self.controller._event("INTEGRITY_VIOLATION", "FAILED", refs=(artifact,), operation="n06-cancel-" + row["operation_id"])
            with self.store.transaction() as conn:
                conn.execute("UPDATE n06_lab_actions SET acknowledged=1 WHERE operation_id=?", (row["operation_id"],))

    async def pump(self):
        try:
            while not self.stopped:
                await self.flush_actions()
                with self.lock:
                    with closing(self.store.connect()) as conn:
                        state = conn.execute("SELECT closes_ns FROM n06_lab_runs WHERE experiment_id=?", (self.ctx.experiment_id,)).fetchone()
                        jobs = list(conn.execute("SELECT turn_id FROM n06_jobs WHERE experiment_id=? AND state='QUEUED'", (self.ctx.experiment_id,)))
                    if not self.draining and state[0] is not None and self.queue.clock_ns() >= state[0]:
                        for _ in range(min(len(jobs), 3 - len(self.active) - len(self.worker.tasks))):
                            task = asyncio.create_task(self.worker.run_once())
                            self.active.add(task)
                            def settled(future):
                                self.active.discard(future)
                                if not future.cancelled() and future.exception() is not None:
                                    self.pump_error = True
                            task.add_done_callback(settled)
                await asyncio.sleep(0.01)
        except BaseException:
            self.pump_error = True
            self.accepting = False
            raise

    async def quiesce(self):
        """Private operator gate before authoritative close; False is close-pending."""
        with self.lock:
            self.accepting = False
            self.draining = True
        if self.active:
            await asyncio.gather(*tuple(self.active), return_exceptions=True)
        drained = await self.worker.drain()
        await self.flush_actions()
        if drained:
            # A dispatched model may finish after cancellation. The public failure
            # stays a failure, while actual later EXECUTED evidence must survive.
            with self.store.transaction() as conn:
                for job in conn.execute("SELECT * FROM n06_jobs WHERE experiment_id=? AND state='FAILED'", (self.ctx.experiment_id,)).fetchall():
                    if self.queue._known(conn, job["turn_id"], job["known_execution"]) == "EXECUTED" and job["known_execution"] != "EXECUTED":
                        self.queue._fail(conn, job, "UNKNOWN")
        with closing(self.store.connect()) as conn:
            unsettled = conn.execute("SELECT 1 FROM n06_jobs WHERE experiment_id=? AND state IN ('QUEUED','CLAIMED')", (self.ctx.experiment_id,)).fetchone()
        if not drained or unsettled or self.pump_error or not all(self.worker.failure_audit_acknowledged):
            return False
        self.stopped = True
        with self.store.transaction() as conn:
            conn.execute("UPDATE n06_lab_runs SET state='QUIESCED' WHERE experiment_id=? AND owner=?", (self.ctx.experiment_id, self.owner))
        return True
