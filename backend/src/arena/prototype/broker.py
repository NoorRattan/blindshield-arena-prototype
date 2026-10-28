"""Trusted sealed-list scheduling; ordinary Broker remains interactive-only.

The service never forwards participant turns or sessions to this batch path.
Every batch turn is tied to its frozen item, content commitment and lane/index.
"""
from contextlib import closing
from uuid import uuid4
import os

from arena.broker.core import Broker, context
from arena.broker.config import Profile
from arena.broker.store import BrokerError
from arena.contracts.common import Digest, Epoch, WireModel
from arena.contracts.crypto import canonical_bytes, commitment, sha256
from arena.contracts.evidence import SealResponse


class BatchSealIntent(WireModel):
    epoch: Epoch
    plan_sha256: Digest


class PrototypeBroker(Broker):
    def __init__(self, store, config, corpus):
        super().__init__(store, config)
        self.corpus = corpus

    @staticmethod
    def _interactive(row):
        # This subclass is available only inside the admitted local service.
        # Batch participant routes are refused by that service before entry.
        if row["phase"] != "RUNNING":
            raise BrokerError("WRONG_PHASE")

    def batch_plan(self, row):
        with closing(self.store.connect()) as conn:
            items = list(conn.execute("SELECT item_id,artifact_id FROM batch_items WHERE experiment_id=? ORDER BY item_id", (row["id"],)))
        if not 1 <= len(items) <= 24:
            raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
        result = []
        for index, item in enumerate(items):
            value = self.store.read_payload(item["artifact_id"])
            matches = [p for p in self.corpus.records.values() if p.text == value["text"]]
            if len(matches) != 1:
                raise BrokerError("POLICY_NOT_READY", 503)
            result.append({"item_id": item["item_id"], "artifact_id": item["artifact_id"],
                "source_ref": matches[0].payload_ref,
                "content_commitment": commitment(value["text"].encode(), bytes.fromhex(value["commitment_nonce"])),
                "content_nonce_hex": value["commitment_nonce"], "provenance": matches[0].provenance.model_dump(),
                "lane": index % 3, "turn_index": index // 3})
        return {"schema_version": "arena-prototype-batch-plan.v1", "items": result}

    def seal(self, principal, identifier, request, key, *, transport_admission=None):
        with closing(self.store.connect()) as conn:
            row = dict(self._object(conn, principal, identifier, request.epoch))
        if Profile.model_validate_json(row["config_json"]).request.interaction_mode != "SEALED_BATCH":
            return super().seal(principal, identifier, request, key, transport_admission=transport_admission)
        self._role(principal, "operator")
        plan = self.batch_plan(row)
        intent = BatchSealIntent(epoch=request.epoch, plan_sha256=sha256(canonical_bytes(plan)))
        def operation(conn, current):
            if current["phase"] != "CREATED":
                raise BrokerError("WRONG_PHASE")
            items = [dict(r) for r in conn.execute("SELECT item_id,artifact_id FROM batch_items WHERE experiment_id=? ORDER BY item_id", (identifier,))]
            if [{k: item[k] for k in ("item_id", "artifact_id")} for item in plan["items"]] != items:
                raise BrokerError("IDEMPOTENCY_CONFLICT")
            profile = Profile.model_validate_json(current["config_json"])
            private = {"context": context(current), "profile": profile.model_dump(), "items": items, "prototype_batch": plan}
            nonce = os.urandom(32)
            public = commitment(canonical_bytes(private), nonce)
            manifest = self.store.put_payload(conn, current, "manifest", {"manifest": private, "commitment_nonce": nonce.hex()})
            conn.execute("UPDATE experiments SET phase='SEALED',manifest_id=?,public_commitment=? WHERE id=?", (manifest, public, identifier))
            return 200, SealResponse(**context(current), phase="SEALED", receipt_id=str(uuid4()), public_commitment=public).model_dump()
        return self._mutate(principal, identifier, intent, "seal", key, f"/v1/experiments/{identifier}/seal", operation)

    def frozen_batch(self, row):
        sealed = self.store.read_payload(row["manifest_id"])
        if commitment(canonical_bytes(sealed["manifest"]), bytes.fromhex(sealed["commitment_nonce"])) != row["public_commitment"]:
            raise BrokerError("AUDIT_UNAVAILABLE", 503)
        plan = sealed["manifest"]["prototype_batch"]
        if self.batch_plan(row) != plan:
            raise BrokerError("AUDIT_UNAVAILABLE", 503)
        return plan

    def reserve_turn(self, principal, identifier, session_id, request, key, *, on_reserved=None):
        with closing(self.store.connect()) as conn:
            row = dict(self._object(conn, principal, identifier, request.epoch))
            mode = Profile.model_validate_json(row["config_json"]).request.interaction_mode
            if mode == "SEALED_BATCH":
                session = self._session(conn, row, session_id, principal.subject_id)
                expected = [item for item in self.frozen_batch(row)["items"]
                    if item["lane"] == session["lane"] and item["turn_index"] == request.turn_index]
                if len(expected) != 1 or request.text is not None or request.payload_ref != expected[0]["artifact_id"] or key != "batch-" + expected[0]["item_id"]:
                    raise BrokerError("FORBIDDEN", 403)
        def admission(conn, current, turn):
            if mode == "INTERACTIVE":
                state = conn.execute("SELECT finishing FROM prototype_state WHERE experiment_id=?", (identifier,)).fetchone()
                if not state or state[0]:
                    raise BrokerError("WRONG_PHASE")
            if on_reserved is not None:
                on_reserved(conn, current, turn)
        return super().reserve_turn(principal, identifier, session_id, request, key, on_reserved=admission)
