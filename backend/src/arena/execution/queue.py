"""Durable internal queue, separate from HTTP and external inference transactions.

Existing broker authority/reservations remain canonical. A claimed job is never
leased back to QUEUED, including after cancellation, deadline or process death.
"""

import base64
from contextlib import closing
from dataclasses import dataclass
import json
import time
from uuid import uuid4

from pydantic import TypeAdapter

from arena.broker.config import Profile
from arena.broker.store import BrokerError
from arena.contracts.api import AttemptResult, TurnSubmission
from arena.contracts.common import Context, Uuid
from .policy import SignedPolicy, disclosure_id, padded_json, validate_policy


PROCESS_CLOCK_ID = str(uuid4())
SCHEMA = """
CREATE TABLE IF NOT EXISTS n06_policies(
 experiment_id TEXT PRIMARY KEY REFERENCES experiments(id), signed_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS n06_jobs(
 turn_id TEXT PRIMARY KEY REFERENCES turns(id), experiment_id TEXT NOT NULL REFERENCES experiments(id),
 session_id TEXT NOT NULL REFERENCES sessions(id), owner TEXT NOT NULL, client_key TEXT NOT NULL,
 clock_id TEXT NOT NULL, admitted_ns INTEGER NOT NULL, deadline_ns INTEGER NOT NULL, release_ns INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('QUEUED','CLAIMED','AUTHORIZED','FAILED')),
 worker_id TEXT, body_ref TEXT REFERENCES payloads(artifact_id), known_execution TEXT NOT NULL DEFAULT 'NOT_EVALUATED',
 published INTEGER NOT NULL DEFAULT 0 CHECK(published IN (0,1)));
CREATE UNIQUE INDEX IF NOT EXISTS n06_one_unpublished ON n06_jobs(session_id) WHERE published=0;
"""


@dataclass(frozen=True)
class Projection:
    status: int
    body: bytes


class ExecutionQueue:
    def __init__(self, broker, policy_public_key, policy_key_id, *, clock_ns=time.monotonic_ns, clock_id=PROCESS_CLOCK_ID):
        self.broker, self.store = broker, broker.store
        self.policy_key, self.policy_key_id = policy_public_key, policy_key_id
        self.clock_ns = clock_ns
        self.clock_id = TypeAdapter(Uuid).validate_python(clock_id)
        # Initialization is a separate schema operation, never inside admission.
        with closing(self.store.connect()) as conn:
            conn.executescript(SCHEMA)

    def _policy(self, conn, row):
        stored = conn.execute("SELECT signed_json FROM n06_policies WHERE experiment_id=?", (row["id"],)).fetchone()
        if not stored:
            raise BrokerError("POLICY_NOT_READY", 503)
        signed = SignedPolicy.model_validate_json(stored[0])
        policy = validate_policy(signed, self.policy_key, self.policy_key_id)
        profile = Profile.model_validate_json(row["config_json"])
        if profile.request.disclosure_profile_id != disclosure_id(signed) or profile.run_label != policy.run_label:
            raise BrokerError("POLICY_NOT_READY", 503)
        return policy

    def bind_policy(self, operator, ctx, signed):
        self.broker._role(operator, "operator")
        policy = validate_policy(signed, self.policy_key, self.policy_key_id)
        with self.store.transaction() as conn:
            row = self.broker._object(conn, operator, ctx.experiment_id, ctx.epoch)
            profile = Profile.model_validate_json(row["config_json"])
            if row["phase"] != "SEALED" or profile.request.disclosure_profile_id != disclosure_id(signed) or profile.run_label != policy.run_label:
                raise BrokerError("POLICY_NOT_READY", 503)
            old = conn.execute("SELECT signed_json FROM n06_policies WHERE experiment_id=?", (ctx.experiment_id,)).fetchone()
            raw = signed.model_dump_json()
            if old and old[0] != raw:
                raise BrokerError("IDEMPOTENCY_CONFLICT")
            conn.execute("INSERT OR IGNORE INTO n06_policies VALUES(?,?)", (ctx.experiment_id, raw))

    def submit(self, principal, identifier, session_id, request, key, *, on_enqueued=None):
        def enqueue(conn, row, turn):
            policy = self._policy(conn, row)
            profile = Profile.model_validate_json(row["config_json"])
            waiting = conn.execute("SELECT count(*) FROM n06_jobs j JOIN experiments e ON e.id=j.experiment_id "
                                   "WHERE e.domain_id=? AND j.published=0", (row["domain_id"],)).fetchone()[0]
            if waiting >= profile.domain_queue_limit:
                raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
            if conn.execute("SELECT 1 FROM n06_jobs WHERE session_id=? AND published=0", (session_id,)).fetchone():
                raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
            now = self.clock_ns()
            if type(now) is not int or now < 0:
                raise BrokerError("POLICY_NOT_READY", 503)
            conn.execute("INSERT INTO n06_jobs(turn_id,experiment_id,session_id,owner,client_key,clock_id,admitted_ns,deadline_ns,release_ns,state) "
                         "VALUES(?,?,?,?,?,?,?,?,?,'QUEUED')", (turn, identifier, session_id, principal.subject_id, key, self.clock_id,
                         now, now + policy.execution_deadline_ms * 1_000_000, now + policy.release_floor_ms * 1_000_000))
            if on_enqueued is not None:
                # Trusted local service hook; its frozen round shares reservation,
                # payload, budget, job and idempotency commit/rollback authority.
                on_enqueued(conn, row, turn)
        status, receipt = self.broker.reserve_turn(principal, identifier, session_id, request, key, on_reserved=enqueue)
        with closing(self.store.connect()) as conn:
            job = conn.execute("SELECT 1 FROM n06_jobs WHERE turn_id=?", (receipt["turn_id"],)).fetchone()
        if not job:
            # Never adopt a historical non-queued reservation through a replay.
            raise BrokerError("POLICY_NOT_READY", 503)
        return status, receipt

    def claim(self, ctx, worker_id):
        TypeAdapter(Uuid).validate_python(worker_id)
        with self.store.transaction() as conn:
            run = conn.execute("SELECT * FROM experiments WHERE id=? AND domain_id=? AND epoch=?",
                               (ctx.experiment_id, ctx.domain_id, ctx.epoch)).fetchone()
            if not run or run["phase"] != "RUNNING" or run["integrity"] == "INVALID":
                return None
            job = conn.execute("SELECT * FROM n06_jobs WHERE experiment_id=? AND state='QUEUED' ORDER BY admitted_ns,turn_id LIMIT 1",
                               (ctx.experiment_id,)).fetchone()
            if not job:
                return None
            if job["clock_id"] != self.clock_id:
                raise BrokerError("POLICY_NOT_READY", 503)
            if self.clock_ns() >= job["deadline_ns"]:
                self._fail(conn, job, "NOT_EVALUATED")
                return None
            conn.execute("UPDATE n06_jobs SET state='CLAIMED',worker_id=? WHERE turn_id=? AND state='QUEUED'", (worker_id, job["turn_id"]))
            return dict(job) | {"state": "CLAIMED", "worker_id": worker_id}

    def request_for(self, job):
        with closing(self.store.connect()) as conn:
            row = conn.execute("SELECT t.*,e.domain_id,e.epoch FROM turns t JOIN experiments e ON t.experiment_id=e.id WHERE t.id=?", (job["turn_id"],)).fetchone()
            identity = conn.execute("SELECT fingerprint FROM principals WHERE subject_id=?", (job["owner"],)).fetchone()
        if not row or not identity:
            raise BrokerError("UNAUTHORIZED", 401)
        principal = self.store.authenticate(identity[0])
        if principal.subject_id != job["owner"] or principal.domain_id != row["domain_id"] or principal.role != "red":
            raise BrokerError("UNAUTHORIZED", 401)
        stored = self.store.read_payload(row["artifact_id"])
        source = {"payload_ref": stored["payload_ref"]} if stored["payload_ref"] else {"text": stored["text"]}
        request = TurnSubmission(epoch=row["epoch"], turn_index=row["turn_index"], **source)
        return principal, request

    def _claimed(self, conn, job, worker_id):
        row = conn.execute("SELECT * FROM n06_jobs WHERE turn_id=? AND worker_id=? AND state='CLAIMED'", (job["turn_id"], worker_id)).fetchone()
        if not row:
            raise BrokerError("WRONG_PHASE")
        return row

    def _save_authorized(self, job, worker_id, body):
        """Only the worker's complete controller/evidence/opening validation calls this."""
        with self.store.transaction() as conn:
            stored = self._claimed(conn, job, worker_id)
            run = conn.execute("SELECT * FROM experiments WHERE id=?", (job["experiment_id"],)).fetchone()
            policy = self._policy(conn, run)
            if stored["clock_id"] != self.clock_id or self.clock_ns() >= stored["deadline_ns"] or run["phase"] != "RUNNING" or run["integrity"] == "INVALID":
                self._fail(conn, stored, "UNKNOWN")
                return False
            if type(body) is not bytes or len(body) != policy.body_bytes:
                raise ValueError("FIXED_FEEDBACK_BYTES_REQUIRED")
            ref = self.store.put_payload(conn, run, "n06-feedback", {"body_base64": base64.b64encode(body).decode("ascii")})
            conn.execute("UPDATE n06_jobs SET state='AUTHORIZED',body_ref=?,known_execution=? WHERE turn_id=?", (ref, self._known(conn, job["turn_id"], "UNKNOWN"), job["turn_id"]))
            return True

    def dispatch_ready(self, job, worker_id):
        with self.store.transaction() as conn:
            stored = self._claimed(conn, job, worker_id)
            run = conn.execute("SELECT * FROM experiments WHERE id=?", (job["experiment_id"],)).fetchone()
            if stored["clock_id"] != self.clock_id or self.clock_ns() >= stored["deadline_ns"] or run["phase"] != "RUNNING" or run["integrity"] == "INVALID":
                raise BrokerError("POLICY_NOT_READY", 503)

    @staticmethod
    def _known(conn, turn_id, fallback):
        old = None
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='n04_turns'").fetchone():
            old = conn.execute("SELECT known_execution FROM n04_turns WHERE turn_id=?", (turn_id,)).fetchone()
            if old and old[0] == "EXECUTED":
                return "EXECUTED"
        turn = conn.execute("SELECT result_json FROM turns WHERE id=?", (turn_id,)).fetchone()
        if turn and turn[0]:
            return AttemptResult.model_validate_json(turn[0]).model_execution
        if old:
            return old[0]
        return fallback

    def _fail(self, conn, job, fallback):
        execution = self._known(conn, job["turn_id"], fallback)
        run = conn.execute("SELECT config_json FROM experiments WHERE id=?", (job["experiment_id"],)).fetchone()
        mode = Profile.model_validate_json(run[0]).request.defense_mode
        failure = AttemptResult(defense_mode=mode, pipeline_disposition="INFRASTRUCTURE_FAILED", model_execution=execution,
                                scoring="FAILED" if execution == "EXECUTED" else "NOT_EVALUATED", integrity="INVALID")
        conn.execute("UPDATE n06_jobs SET state='FAILED',known_execution=? WHERE turn_id=?", (execution, job["turn_id"]))
        conn.execute("UPDATE turns SET state=?,result_json=? WHERE id=?", ("UNKNOWN" if execution == "UNKNOWN" else "FAILED", failure.model_dump_json(), job["turn_id"]))
        conn.execute("UPDATE sessions SET quarantined=1 WHERE id=?", (job["session_id"],))
        conn.execute("UPDATE experiments SET phase='INVALID',integrity='INVALID' WHERE id=? AND phase NOT IN ('CLOSED','RELEASED')", (job["experiment_id"],))
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='n04_runs'").fetchone():
            conn.execute("UPDATE n04_runs SET state='INVALID' WHERE experiment_id=? AND state NOT IN ('CLOSED','RELEASED')", (job["experiment_id"],))

    def fail_claim(self, job, worker_id, *, fallback="UNKNOWN"):
        if fallback not in {"UNKNOWN", "NOT_EVALUATED"}:
            raise ValueError("FAILURE_EXECUTION_FALLBACK_INVALID")
        with self.store.transaction() as conn:
            row = self._claimed(conn, job, worker_id)
            self._fail(conn, row, fallback)

    def abandon(self, operator, ctx, turn_id):
        """Explicit operator invalidation, never an expired-lease retry."""
        self.broker._role(operator, "operator")
        with self.store.transaction() as conn:
            self.broker._object(conn, operator, ctx.experiment_id, ctx.epoch)
            job = conn.execute("SELECT * FROM n06_jobs WHERE turn_id=? AND experiment_id=? AND state='CLAIMED'", (turn_id, ctx.experiment_id)).fetchone()
            if not job:
                raise BrokerError("NOT_FOUND", 404)
            self._fail(conn, job, "UNKNOWN")

    def project(self, principal, ctx, session_id, turn_id):
        self.broker._role(principal, "red")
        with self.store.transaction() as conn:
            run = self.broker._object(conn, principal, ctx.experiment_id, ctx.epoch)
            if run["domain_id"] != ctx.domain_id:
                raise BrokerError("NOT_FOUND", 404)
            self.broker._session(conn, run, session_id, principal.subject_id)
            job = conn.execute("SELECT * FROM n06_jobs WHERE turn_id=? AND experiment_id=? AND session_id=? AND owner=?",
                               (turn_id, ctx.experiment_id, session_id, principal.subject_id)).fetchone()
            if not job:
                raise BrokerError("NOT_FOUND", 404)
            policy = self._policy(conn, run)
            if not job["published"]:
                if job["clock_id"] != self.clock_id:
                    raise BrokerError("POLICY_NOT_READY", 503)
                if self.clock_ns() < job["release_ns"]:
                    return Projection(202, padded_json({"status": "PENDING"}, policy.body_bytes))
                if job["state"] not in {"AUTHORIZED", "FAILED"}:
                    self._fail(conn, job, "NOT_EVALUATED" if job["state"] == "QUEUED" else "UNKNOWN")
                    job = dict(job) | {"state": "FAILED"}
                if run["integrity"] == "INVALID" and job["state"] == "AUTHORIZED":
                    self._fail(conn, job, "UNKNOWN")
                    job = dict(job) | {"state": "FAILED"}
                conn.execute("UPDATE n06_jobs SET published=1 WHERE turn_id=?", (turn_id,))
            if job["state"] != "AUTHORIZED":
                return Projection(503, padded_json({"status": "UNAVAILABLE"}, policy.body_bytes))
            raw = self.store.read_payload(job["body_ref"])
            body = base64.b64decode(raw["body_base64"], validate=True)
            if len(body) != policy.body_bytes:
                raise BrokerError("AUDIT_UNAVAILABLE", 503)
            return Projection(200, body)
