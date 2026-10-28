"""Trusted local mTLS test client/provisioner. All credentials stay PRIVATE.

This single-host measurement harness holds every demo identity. It is not tenant
key distribution, a deployed authority, or a replacement for per-cell custody.
"""

import asyncio
from contextlib import closing
import http.client
import json
import ssl
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.broker.provision import initialize, write_private
from arena.broker.server import Server, tls_context
from arena.contracts.api import AttemptResult
from arena.contracts.crypto import sha256
from arena.contracts.evidence import TurnFeedback
from arena.integration.controller import InternalTurnResult
from arena.ports import DependencyUnavailable
from .pilot import MeasuredTurn, WorkerSample
from .transport import LabProfile, ParticipantGateway, SignedLabProfile, lab_message


def lab_credentials(directory, broker, principals):
    """Explicit trusted fresh-run replacement of dev fingerprints, never from HTTP.

    Existing subjects/roles/domains/expiry/enabled flags remain authoritative. A
    fresh development CA provides actual client certs instead of synthetic hashes.
    """
    generated = initialize(directory, broker.config)
    identities = json.loads((directory / "identities.json").read_bytes())
    contexts = {}
    with closing(generated.connect()) as conn:
        bindings = {r["role"]: dict(r) for r in conn.execute("SELECT * FROM principals")}
    with broker.store.transaction() as conn:
        if conn.execute("SELECT 1 FROM n06_jobs").fetchone():
            raise DependencyUnavailable("FRESH_TLS_BINDING_REQUIRED")
        for role, principal in principals.items():
            binding = bindings[role]
            if role != "operator" and binding["subject_id"] != principal.subject_id:
                raise DependencyUnavailable("LOCAL_TLS_IDENTITY_BINDING_REJECTED")
            cursor = conn.execute("UPDATE principals SET fingerprint=?,expires_at=min(expires_at,?) WHERE subject_id=? AND role=? AND domain_id=? AND enabled=1",
                (binding["fingerprint"], binding["expires_at"], principal.subject_id, role, principal.domain_id))
            if cursor.rowcount != 1:
                raise DependencyUnavailable("LOCAL_TLS_IDENTITY_BINDING_REJECTED")
            label = identities[binding["subject_id"]]["label"]
            context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(directory / (label + ".pem")), str(directory / (label + ".key")))
            contexts[role] = context
    return contexts


class LocalMTLSPilot:
    def __init__(self, worker, operator, principals, directory, *, admission_window_ms=1000, admission=None):
        self.worker, self.queue, self.controller = worker, worker.queue, worker.controller
        self.contexts = lab_credentials(directory, self.queue.broker, principals)
        profile = LabProfile(**self.controller.ctx.model_dump(),
            execution_lock_sha256=self.queue.broker.config.profiles[0].execution_lock_sha256,
            feedback_policy_sha256=sha256(self._policy().model_dump_json().encode()), admission_window_ms=admission_window_ms)
        if admission is None:
            key = Ed25519PrivateKey.generate()
            signed = SignedLabProfile(profile=profile, signer_key_id="local-lab", signature=key.sign(lab_message(profile, "local-lab")).hex())
            public, key_id = key.public_key().public_bytes_raw(), "local-lab"
            write_private(directory / "profile.key", key.private_bytes_raw())
        else:
            signed = admission.plan.transport
            if signed.profile != profile:
                raise DependencyUnavailable("SEALED_TRANSPORT_LAB_PROFILE_MISMATCH")
            public, key_id = admission.trust.transport_public_key, admission.trust.transport_key_id
        write_private(directory / "profile-public.hex", public.hex().encode())
        write_private(directory / "profile.json", signed.model_dump_json(indent=2).encode())
        self.gateway = ParticipantGateway(operator, worker, signed, public, key_id, admission=admission)
        self.server = Server(("127.0.0.1", 0), self.queue.broker,
            tls_context(directory / "server.pem", directory / "server.key", directory / "ca.pem"), participant_gateway=self.gateway)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.pump = asyncio.create_task(self.gateway.pump())
        self.network_samples = []
        self.closed = False

    def _policy(self):
        with closing(self.queue.store.connect()) as conn:
            run = conn.execute("SELECT * FROM experiments WHERE id=?", (self.controller.ctx.experiment_id,)).fetchone()
            return self.queue._policy(conn, run)

    def request(self, role, method, path, value=None, key=None, headers=None):
        client = http.client.HTTPSConnection("127.0.0.1", self.server.server_address[1], context=self.contexts[role], timeout=6)
        body = None if value is None else json.dumps(value).encode()
        sent = {"Content-Type": "application/json"}
        if key is not None:
            sent["Idempotency-Key"] = key
        sent.update(headers or {})
        try:
            start = time.monotonic_ns()
            client.request(method, path, body=body, headers=sent)
            response = client.getresponse()
            data = response.read()
            return response.status, data, time.monotonic_ns() - start
        finally:
            client.close()

    async def turn(self, principal, session_id, request, key, *, index, lane):
        path = f"/v1/experiments/{self.controller.ctx.experiment_id}/sessions/{session_id}/turns"
        status, ack, admission_rtt = await asyncio.to_thread(self.request, "red", "POST", path, request.model_dump(exclude_none=True), key)
        if status != 202 or json.loads(ack)["status"] != "ACCEPTED":
            raise DependencyUnavailable("LOCAL_MTLS_SUBMISSION_REJECTED")
        turn_id = json.loads(ack)["turn_id"]
        with closing(self.queue.store.connect()) as conn:
            job = conn.execute("SELECT * FROM n06_jobs WHERE turn_id=?", (turn_id,)).fetchone()
        status, pending, _ = await asyncio.to_thread(self.request, "red", "GET", path + "/" + turn_id)
        if status != 202 or len(pending) != self.gateway.size:
            raise DependencyUnavailable("LOCAL_MTLS_INITIAL_PENDING_REQUIRED")
        authorized_ns = None
        while self.queue.clock_ns() < job["release_ns"]:
            with closing(self.queue.store.connect()) as conn:
                state = conn.execute("SELECT state FROM n06_jobs WHERE turn_id=?", (turn_id,)).fetchone()[0]
            if state == "AUTHORIZED" and authorized_ns is None:
                authorized_ns = self.queue.clock_ns()
            await asyncio.sleep(0.02)
        status, body, final_rtt = await asyncio.to_thread(self.request, "red", "GET", path + "/" + turn_id)
        published_ns = self.queue.clock_ns()
        if status != 200 or authorized_ns is None:
            raise DependencyUnavailable("LOCAL_MTLS_FINAL_AUTHORITY_REQUIRED")
        feedback = TurnFeedback.model_validate_json(body)
        with closing(self.queue.store.connect()) as conn:
            result = AttemptResult.model_validate_json(conn.execute("SELECT result_json FROM n04_turns WHERE turn_id=?", (turn_id,)).fetchone()[0])
        history = tuple(self.controller.recorder.get_events(self.controller.ctx))
        retry_status, retry_ack, _ = await asyncio.to_thread(self.request, "red", "POST", path, request.model_dump(exclude_none=True), key)
        retry_final, replay, _ = await asyncio.to_thread(self.request, "red", "GET", path + "/" + turn_id)
        if retry_status != 202 or retry_ack != ack or retry_final != 200 or replay != body or history != tuple(self.controller.recorder.get_events(self.controller.ctx)):
            raise DependencyUnavailable("LOCAL_MTLS_REPLAY_CHANGED")
        sample = WorkerSample(sample_index=index, lane=lane, admitted_ns=job["admitted_ns"], authorized_observed_ns=authorized_ns,
            deadline_ns=job["deadline_ns"], release_ns=job["release_ns"], published_observed_ns=published_ns, body_bytes=len(body),
            unpadded_body_bytes=len(feedback.model_copy(update={"padding": ""}).model_dump_json().encode()),
            pending_status=202, final_status=200, replay_identical=True)
        self.network_samples.append({"sample_index": index, "admission_rtt_ns": admission_rtt, "final_poll_rtt_ns": final_rtt,
                                     "ack_bytes": len(ack), "pending_bytes": len(pending), "feedback_bytes": len(body)})
        return MeasuredTurn(InternalTurnResult(turn_id, result, feedback.public_reply, feedback.feedback_receipt), sample)

    async def close(self):
        # Stop admitting BEFORE checking quiescence. A client cannot race new work
        # into a successfully drained run while the operator closes its recorder.
        if self.closed:
            return
        with self.gateway.lock:
            self.gateway.accepting = False
            self.gateway.draining = True
        await asyncio.to_thread(self.server.shutdown)
        await asyncio.to_thread(self.thread.join, 2)
        self.server.server_close()
        try:
            good = await self.gateway.quiesce()
        finally:
            self.gateway.stopped = True
            await self.pump
            self.closed = True
        if not good:
            raise DependencyUnavailable("LOCAL_MTLS_CLOSE_PENDING")
