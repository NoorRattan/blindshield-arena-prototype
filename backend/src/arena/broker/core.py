"""Durable control plane. Execution/evidence gates remain closed until N04 integration.

Methods take trusted transport principals, never identity fields parsed from request bodies.
Internal reservation tests may insert synthetic RUNNING fixtures; there is no force-run API.
"""

from contextlib import closing
import hashlib
import hmac
import json
import os
from uuid import uuid4

from pydantic import TypeAdapter

from arena.contracts.api import (AttackBatch, CreateExperiment, EpochRequest,
                                 ExperimentCreated, SessionCreated, TurnSubmission, UploadReceipt)
from arena.contracts.common import ClientKey
from arena.contracts.crypto import canonical_bytes, commitment, request_digest
from arena.contracts.evidence import SealResponse
from .config import BrokerConfig, Profile
from .store import BrokerError, Store


def context(row):
    return dict(domain_id=row["domain_id"], experiment_id=row["id"], epoch=row["epoch"])


class Broker:
    def __init__(self, store: Store, config: BrokerConfig):
        self.store, self.config = store, config

    @staticmethod
    def _object(connection, principal, experiment_id, epoch=None):
        row = connection.execute("SELECT e.* FROM experiments e JOIN memberships m ON m.experiment_id=e.id "
                                 "WHERE e.id=? AND e.domain_id=? AND m.subject_id=? AND m.role=?",
                                 (experiment_id, principal.domain_id, principal.subject_id, principal.role)).fetchone()
        if row is None:
            raise BrokerError("NOT_FOUND", 404)
        if epoch is not None and row["epoch"] != epoch:
            raise BrokerError("STALE_EPOCH")
        return row

    @staticmethod
    def _role(principal, *roles):
        if principal.role not in roles:
            raise BrokerError("FORBIDDEN", 403)

    def _mutate(self, principal, experiment_id, request, action, key, route, operation):
        TypeAdapter(ClientKey).validate_python(key)
        digest = hmac.new(self.store.master_key, b"arena.v2/idempotency\x00" + canonical_bytes(
            {"request_digest": request_digest(request), "route": route}), hashlib.sha256).hexdigest()
        with self.store.transaction() as connection:
            row = self._object(connection, principal, experiment_id, request.epoch) if experiment_id else None
            scope = (principal.subject_id, principal.domain_id, experiment_id, request.epoch if row else 0, action, key)
            old = connection.execute("SELECT * FROM idempotency WHERE subject_id=? AND domain_id=? "
                                     "AND experiment_id=? AND epoch=? AND action=? AND client_key=?", scope).fetchone()
            if old:
                if old["request_digest"] != digest:
                    raise BrokerError("IDEMPOTENCY_CONFLICT")
                return old["status"], json.loads(old["response_json"])
            status, result = operation(connection, row)
            # Successful responses contain only safe metadata. Private request text is never stored here.
            connection.execute("INSERT INTO idempotency VALUES(?,?,?,?,?,?,?,?,?)",
                               (*scope, digest, json.dumps(result, separators=(",", ":")), status))
            return status, result

    def create(self, principal, request: CreateExperiment, key):
        self._role(principal, "operator")
        matches = [p for p in self.config.profiles if p.domain_id == principal.domain_id and p.request == request]
        if len(matches) != 1:
            raise BrokerError("POLICY_NOT_READY", 503)
        profile = matches[0]

        def operation(connection, _):
            members = [(principal.subject_id, "operator"), (profile.red_subject_id, "red"),
                       (profile.blue_subject_id, "blue-human"), *[(s, "auditor") for s in profile.auditor_subject_ids]]
            if len({s for s, _ in members}) != len(members):
                raise BrokerError("POLICY_NOT_READY", 503)
            for subject, role in members:
                found = connection.execute("SELECT 1 FROM principals WHERE subject_id=? AND role=? AND domain_id=? AND enabled=1",
                                           (subject, role, principal.domain_id)).fetchone()
                if not found:
                    raise BrokerError("POLICY_NOT_READY", 503)
            prior = connection.execute("SELECT value FROM epochs WHERE domain_id=?", (principal.domain_id,)).fetchone()
            epoch = prior[0] + 1 if prior else 1
            if epoch > 2_147_483_647:
                raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
            connection.execute("INSERT INTO epochs VALUES(?,?) ON CONFLICT(domain_id) DO UPDATE SET value=excluded.value",
                               (principal.domain_id, epoch))
            identifier = str(uuid4())
            connection.execute("INSERT INTO experiments(id,domain_id,epoch,owner,phase,config_json) VALUES(?,?,?,?,?,?)",
                               (identifier, principal.domain_id, epoch, principal.subject_id, "CREATED", profile.model_dump_json()))
            connection.executemany("INSERT INTO memberships VALUES(?,?,?)", [(identifier, s, r) for s, r in members])
            connection.execute("INSERT INTO budgets VALUES(?,?,0)", (identifier, profile.red_subject_id))
            result = ExperimentCreated(domain_id=principal.domain_id, experiment_id=identifier, epoch=epoch, phase="CREATED")
            return 201, result.model_dump()

        return self._mutate(principal, "", request, "create", key, "/v1/experiments", operation)

    def upload(self, principal, identifier, request: AttackBatch, key):
        self._role(principal, "red")

        def operation(connection, row):
            if row["phase"] != "CREATED":
                raise BrokerError("WRONG_PHASE")
            if connection.execute("SELECT count(*) FROM batch_items WHERE experiment_id=?", (identifier,)).fetchone()[0] + len(request.items) > 500:
                raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
            for item in request.items:
                if connection.execute("SELECT 1 FROM batch_items WHERE experiment_id=? AND item_id=?", (identifier, item.item_id)).fetchone():
                    raise BrokerError("IDEMPOTENCY_CONFLICT")
                artifact = self.store.put_payload(connection, row, "attack", {"text": item.text, "commitment_nonce": os.urandom(32).hex()})
                connection.execute("INSERT INTO batch_items VALUES(?,?,?)", (identifier, item.item_id, artifact))
            return 201, UploadReceipt(**context(row), receipt_id=str(uuid4()), accepted_items=len(request.items)).model_dump()

        return self._mutate(principal, identifier, request, "attacks", key, f"/v1/experiments/{identifier}/attacks", operation)

    def seal(self, principal, identifier, request: EpochRequest, key, *, transport_admission=None):
        self._role(principal, "operator")

        def operation(connection, row):
            if row["phase"] != "CREATED":
                raise BrokerError("WRONG_PHASE")
            profile = Profile.model_validate_json(row["config_json"])
            items = [dict(r) for r in connection.execute("SELECT item_id,artifact_id FROM batch_items WHERE experiment_id=? ORDER BY item_id", (identifier,))]
            if profile.request.interaction_mode == "SEALED_BATCH" and not items:
                raise BrokerError("POLICY_NOT_READY", 503)
            private = {"context": context(row), "profile": profile.model_dump(), "items": items}
            if transport_admission is not None:
                from arena.contracts.common import Context
                private["n06_transport"] = transport_admission.manifest_value(Context(**context(row)), profile)
            nonce = os.urandom(32)
            public = commitment(canonical_bytes(private), nonce)
            manifest = self.store.put_payload(connection, row, "manifest", {"manifest": private, "commitment_nonce": nonce.hex()})
            connection.execute("UPDATE experiments SET phase='SEALED',manifest_id=?,public_commitment=? WHERE id=?", (manifest, public, identifier))
            return 200, SealResponse(**context(row), phase="SEALED", receipt_id=str(uuid4()), public_commitment=public).model_dump()

        intent = request
        if transport_admission is not None:
            from arena.contracts.transport_profile import SealIntent, plan_digest
            intent = SealIntent(epoch=request.epoch, transport_plan_sha256=plan_digest(transport_admission.plan))
        return self._mutate(principal, identifier, intent, "seal", key, f"/v1/experiments/{identifier}/seal", operation)

    def status(self, principal, identifier, feedback=False):
        with closing(self.store.connect()) as connection:
            row = self._object(connection, principal, identifier)
            if feedback:
                self._role(principal, "red", "blue-human")
            if principal.role == "blue-human" or feedback:
                return 200, {"status": "EMBARGOED"}
            return 200, {**context(row), "phase": row["phase"], "integrity": row["integrity"]}

    def session(self, principal, identifier, request: EpochRequest, key):
        self._role(principal, "operator")

        def operation(connection, row):
            self._interactive(row)
            profile = Profile.model_validate_json(row["config_json"])
            lane = connection.execute("SELECT count(*) FROM sessions WHERE experiment_id=?", (identifier,)).fetchone()[0]
            if lane >= profile.session_limit:
                raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
            session = str(uuid4())
            connection.execute("INSERT INTO sessions(id,experiment_id,owner,lane) VALUES(?,?,?,?)", (session, identifier, profile.red_subject_id, lane))
            return 201, SessionCreated(**context(row), session_id=session).model_dump()

        return self._mutate(principal, identifier, request, "sessions", key, f"/v1/experiments/{identifier}/sessions", operation)

    @staticmethod
    def _interactive(row):
        if row["phase"] != "RUNNING":
            raise BrokerError("WRONG_PHASE")
        if Profile.model_validate_json(row["config_json"]).request.interaction_mode != "INTERACTIVE":
            raise BrokerError("WRONG_PHASE")

    def unavailable(self, principal, identifier, request, action, session_id=None):
        """No optimistic READY/start/close/release or final feedback without real authorities."""
        roles = ("red",) if action == "turns" else ("auditor",) if action == "bundle" else ("operator",)
        with closing(self.store.connect()) as connection:
            row = self._object(connection, principal, identifier, request.epoch if request else None)
            self._role(principal, *roles)
            if session_id:
                owner = principal.subject_id if action == "turns" else Profile.model_validate_json(row["config_json"]).red_subject_id
                self._session(connection, row, session_id, owner)
            if action == "turns":
                self._interactive(row)
            required = {"start": ("SEALED", "READY"), "turns": ("RUNNING",), "finish": ("RUNNING",),
                        "close": ("SCORED", "INVALID"), "release": ("CLOSED",), "bundle": ("CLOSED", "RELEASED"),
                        "cancel": ("RUNNING", "INVALID")}
            if row["phase"] not in required[action]:
                raise BrokerError("WRONG_PHASE")
            raise BrokerError("POLICY_NOT_READY", 503)

    @staticmethod
    def _session(connection, row, session_id, owner):
        session = connection.execute("SELECT * FROM sessions WHERE id=? AND experiment_id=? AND owner=?", (session_id, row["id"], owner)).fetchone()
        if not session:
            raise BrokerError("NOT_FOUND", 404)
        return session

    def reserve_turn(self, principal, identifier, session_id, request: TurnSubmission, key, *, on_reserved=None):
        """INTERNAL ONLY durable reservation; never inference permission or public final feedback.

        N04 must first obtain recorder/witness authority and then cross the dispatch boundary.
        No public route invokes this method until that integration and shaping exist.
        """
        self._role(principal, "red")

        def operation(connection, row):
            self._interactive(row)
            session = self._session(connection, row, session_id, principal.subject_id)
            if session["quarantined"] or session["next_index"] != request.turn_index:
                raise BrokerError("WRONG_PHASE")
            if connection.execute("SELECT 1 FROM turns WHERE session_id=? AND state IN ('RESERVED','DISPATCHED','UNKNOWN')", (session_id,)).fetchone():
                raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
            profile = Profile.model_validate_json(row["config_json"])
            queued = connection.execute("SELECT count(*) FROM turns t JOIN experiments e ON e.id=t.experiment_id "
                                        "WHERE e.domain_id=? AND t.state IN ('RESERVED','DISPATCHED','UNKNOWN')", (row["domain_id"],)).fetchone()[0]
            budget = connection.execute("SELECT admitted FROM budgets WHERE experiment_id=? AND subject_id=?", (identifier, principal.subject_id)).fetchone()
            if not budget or budget[0] >= profile.query_budget or queued >= profile.domain_queue_limit:
                raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
            if request.payload_ref and not connection.execute("SELECT 1 FROM batch_items WHERE experiment_id=? AND artifact_id=?", (identifier, request.payload_ref)).fetchone():
                raise BrokerError("NOT_FOUND", 404)
            turn = str(uuid4())
            artifact = self.store.put_payload(connection, row, "turn", {"text": request.text, "payload_ref": request.payload_ref,
                                                                         "turn_id": turn, "session_id": session_id,
                                                                         "turn_index": request.turn_index, "commitment_nonce": os.urandom(32).hex()})
            connection.execute("INSERT INTO turns(id,experiment_id,session_id,turn_index,owner,state,artifact_id,payload_ref) VALUES(?,?,?,?,?,'RESERVED',?,?)",
                               (turn, identifier, session_id, request.turn_index, principal.subject_id, artifact, request.payload_ref))
            connection.execute("UPDATE sessions SET next_index=next_index+1 WHERE id=?", (session_id,))
            connection.execute("UPDATE budgets SET admitted=admitted+1 WHERE experiment_id=? AND subject_id=?", (identifier, principal.subject_id))
            if on_reserved is not None:
                # Trusted internal hook: durable queue insertion shares this transaction.
                # Neither public JSON nor the HTTP router can supply a callback.
                on_reserved(connection, row, turn)
            return 201, {**context(row), "turn_id": turn, "session_id": session_id, "turn_index": request.turn_index, "state": "RESERVED"}

        return self._mutate(principal, identifier, request, "turns", key, f"/v1/experiments/{identifier}/sessions/{session_id}/turns", operation)
