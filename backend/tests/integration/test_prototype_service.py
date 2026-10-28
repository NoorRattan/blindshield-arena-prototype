"""Actual mTLS/SQLite/crypto service tests with explicitly synthetic model cells."""
import asyncio
from contextlib import closing
import http.client
import importlib.util
import json
from pathlib import Path
import sqlite3
import ssl
import threading
from types import SimpleNamespace
from uuid import uuid4
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from arena.broker.config import BrokerConfig, Profile
from arena.broker.provision import initialize
from arena.contracts.api import CreateExperiment
from arena.contracts.common import Principal
from arena.contracts.transport_profile import FeedbackPolicy
from arena.integration.lanes import ThreeLaneModel
from arena.integration.controller import ACTOR
from arena.contracts.crypto import event_digest
from arena.ports import DependencyUnavailable
from arena.recovery.anchor import RecoveryAnchorError
from arena.recovery import startup as recovery_startup
from arena.prototype import service as module
from arena.verifier.cli import main as verify_cli
from arena.verifier.invalid_bundle import verify_invalid_evidence_bundle
from test_n04 import CountingModel, SyntheticRuntime, payload


def test_credentials(directory, unused, store, domain):
    request = CreateExperiment(profile_id="test", model_version_id="test", defense_version_id="test", rubric_version_id="test",
        disclosure_profile_id="test", interaction_mode="INTERACTIVE", defense_mode="INPUT", dataset_catalog_id="test", strategy_version_id="test", budget_profile_id="test")
    profile = Profile(domain_id=domain, request=request, red_subject_id="red", blue_subject_id="blue-human", auditor_subject_ids=("auditor",))
    local = initialize(directory, BrokerConfig(profiles=(profile,)))
    identities = json.loads((directory / "identities.json").read_bytes())
    principals, clients = {}, {}
    with closing(local.connect()) as conn:
        rows = list(conn.execute("SELECT * FROM principals"))
    for row in rows:
        principal = Principal(**{key: row[key] for key in ("subject_id", "role", "domain_id", "expires_at")})
        store.provision(row["fingerprint"], principal)
        principals[principal.role] = principal
        label = identities[principal.subject_id]["label"]
        context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
        context.load_cert_chain(str(directory / (label + ".pem")), str(directory / (label + ".key")))
        clients[principal.role] = context
    return principals, clients, Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


# This is a fixture helper, not a standalone pytest test.
test_credentials.__test__ = False


class _TestAnchor:
    """Synthetic journal for service lifecycle tests; process/TLS are tested separately."""
    def __init__(self):
        self.events = {}
        self.pending = {}
        self.terminals = {}

    def health(self):
        return None

    def prepare(self, event):
        key = (event.domain_id, event.experiment_id, event.epoch)
        self.pending.setdefault(key, {})[event.sequence] = event

    def commit(self, event):
        key = (event.domain_id, event.experiment_id, event.epoch)
        self.events.setdefault(key, {})[event.sequence] = event
        return {}

    def abort(self, event, reason):
        return {"transition": "ABORTED"}

    def records(self, context):
        return []

    def verify_events(self, context, events):
        key = (context.domain_id, context.experiment_id, context.epoch)
        committed = self.events.get(key, {})
        assert len(committed) == len(events)
        assert all(event_digest(committed[i]) == event_digest(event) for i, event in enumerate(events, 1))
        return {"event_sequence": len(events), "event_root": event_digest(events[-1])}

    def terminal_close(self, checkpoint, witness, integrity):
        key = (checkpoint.checkpoint.domain_id, checkpoint.checkpoint.experiment_id, checkpoint.checkpoint.epoch)
        self.terminals[key] = (checkpoint, witness, integrity)
        return {"transition": "TERMINAL_CLOSED"}

    def verify_terminal(self, context, checkpoint, witness, integrity):
        key = (context.domain_id, context.experiment_id, context.epoch)
        assert self.terminals[key] == (checkpoint, witness, integrity)
        return {"transition": "TERMINAL_CLOSED"}


class _TestAnchorProcess:
    def __init__(self, **kwargs):
        self.anchor = _TestAnchor()

    def start(self):
        return self.anchor

    def stop(self):
        return None


async def make_service(tmp_path, monkeypatch, mode, defense_mode="INPUT", *, real_anchor=False,
                       credential_provisioner=None):
    monkeypatch.setattr(module, "provision", credential_provisioner or test_credentials)
    if not real_anchor:
        monkeypatch.setattr(module, "RecoveryAnchorProcess", _TestAnchorProcess)
    def finite_policy(**kwargs):
        return FeedbackPolicy(**(kwargs | {"execution_deadline_ms": 5000, "release_floor_ms": 6000}))
    monkeypatch.setattr(module, "FeedbackPolicy", finite_policy)
    sources = []
    for i in range(6):
        value = payload("SYNTHETIC_UNIT_FIXTURE_" + str(i))
        value = value.model_copy(update={"provenance": value.provenance.model_copy(update={"run_label": "REAL_PUBLIC", "record_id": "unit-" + str(i)})})
        sources.append(value)
    corpus = SimpleNamespace(records={p.payload_ref: p for p in sources}, receipt_sha256="a" * 64)
    async def resolve(identifier): return corpus.records[identifier]
    corpus.resolve = resolve
    runtime = SyntheticRuntime(("ALLOW",) * 12)
    runtime.lane_count, runtime.purpose = 3, "SERVICE"
    runtime.supported_interaction_modes = {"INTERACTIVE", "SEALED_BATCH"}
    cells = [SimpleNamespace(container="synthetic-" + str(i), model=CountingModel()) for i in range(3)]
    runtime.model = ThreeLaneModel(cells, lambda i: SimpleNamespace(container="new-" + str(i), model=CountingModel()))
    runtime.stop = lambda: None
    service = module.PrototypeService(runtime, corpus, tmp_path, tmp_path / "unused-keys", mode=mode, defense_mode=defense_mode)
    service.listen()
    return service, sources


async def make_real_anchor_service(tmp_path, monkeypatch):
    backend = tmp_path / "restart-backend"
    service_work = backend / "artifacts" / "prototype-live"
    authority_dir = service_work / "unused-keys"
    recovery_dir = service_work / "prototype-recovery"
    recovery_dir.mkdir(parents=True)
    (backend / "infra" / "prototype").mkdir(parents=True)
    owner_roots = backend / "infra" / "owner-delegated-n08"
    owner_roots.mkdir(parents=True)

    keys = {name: Ed25519PrivateKey.generate()
            for name in ("anchor", "recovery", "invalid_export")}
    authority_config = {
        "schema_version": "arena.prototype-recovery-authorities.v1",
        "anchor": {
            "authority_id": "test-prototype-anchor",
            "key_id": "prototype-anchor-20261026",
            "public_key": keys["anchor"].public_key().public_bytes_raw().hex(),
        },
        "recovery": {
            "authority_id": "test-feedback-recovery",
            "key_id": "test-feedback-recovery",
            "public_key": keys["recovery"].public_key().public_bytes_raw().hex(),
        },
        "invalid_export": {
            "authority_id": "test-invalid-export",
            "key_id": "test-invalid-export",
            "public_key": keys["invalid_export"].public_key().public_bytes_raw().hex(),
        },
        "recorder_principal_id": "n08-prototype-recorder-001",
    }
    (backend / "infra" / "prototype" / "recovery-authorities.json").write_text(
        json.dumps(authority_config), encoding="utf-8"
    )
    for name, key_id in (
        ("anchor", "prototype-anchor-20261026"),
        ("recovery", "test-feedback-recovery"),
        ("invalid_export", "test-invalid-export"),
    ):
        (recovery_dir / (key_id + "-private.pem")).write_bytes(keys[name].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    monkeypatch.setattr(module, "BACKEND", backend)
    monkeypatch.setattr(recovery_startup, "BACKEND", backend)

    def provision_with_anchor_recorder(directory, authority_path, store, domain):
        result = test_credentials(directory, authority_path, store, domain)
        ca = x509.load_pem_x509_certificate((directory / "ca.pem").read_bytes())
        ca_key = serialization.load_pem_private_key(
            (directory / "ca.key").read_bytes(), password=None
        )
        recorder_tls_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        recorder_tls_certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "recorder")]))
            .issuer_name(ca.subject)
            .public_key(recorder_tls_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("urn:arena:principal:n08-prototype-recorder-001")
            ]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        (directory / "client-recorder.pem").write_bytes(
            recorder_tls_certificate.public_bytes(serialization.Encoding.PEM)
        )
        (directory / "client-recorder.key").write_bytes(recorder_tls_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        return result

    service, sources = await make_service(
        service_work, monkeypatch, "INTERACTIVE", real_anchor=True,
        credential_provisioner=provision_with_anchor_recorder,
    )
    authority_dir.mkdir(parents=True, exist_ok=True)
    (authority_dir / "recorder-private.pem").write_bytes(service.recorder_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    (authority_dir / "witness-private.pem").write_bytes(service.witness_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    identities = json.loads((service.root / "tls" / "identities.json").read_bytes())
    for role, principal in service.p.items():
        label = identities[principal.subject_id]["label"]
        (service.root / "tls" / f"client-{role}.pem").write_bytes(
            (service.root / "tls" / f"{label}.pem").read_bytes()
        )
        (service.root / "tls" / f"client-{role}.key").write_bytes(
            (service.root / "tls" / f"{label}.key").read_bytes()
        )
    (owner_roots / "recorder-public.pem").write_bytes(service.recorder_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    (owner_roots / "witness-public.pem").write_bytes(service.witness_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    (owner_roots / "demo-ca-certificate.pem").write_bytes((service.root / "tls" / "ca.pem").read_bytes())
    return service, sources, backend, authority_dir


def request(service, role, method, action, body=None, key=None):
    path = action if action.startswith("/v1/") else f"/v1/experiments/{service.ctx.experiment_id}/{action}"
    client = http.client.HTTPSConnection("127.0.0.1", service.server.server_address[1], context=service.clients[role], timeout=6)
    try:
        headers = {"Content-Type": "application/json"}
        if key: headers["Idempotency-Key"] = key
        client.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = client.getresponse()
        data = response.read()
        content_type = response.getheader("Content-Type")
        return response.status, data if content_type == "application/zip" else json.loads(data), content_type
    finally: client.close()


async def operation(service, action, key=None):
    status, value, _ = await asyncio.to_thread(request, service, "operator", "POST", action, {"epoch": service.ctx.epoch}, key or action)
    assert status == 202, value
    replay = await asyncio.to_thread(request, service, "operator", "POST", action, {"epoch": service.ctx.epoch}, key or action)
    assert replay[1] == value
    for _ in range(400):
        status, observed, _ = await asyncio.to_thread(request, service, "operator", "GET", "operations/" + value["operation_id"])
        if observed["state"] in {"DONE", "FAILED"}:
            assert observed["state"] == "DONE", observed
            return observed
        await asyncio.sleep(.025)
    raise AssertionError("Admin operation did not finish")


@pytest.mark.parametrize("mode", ["INTERACTIVE", "SEALED_BATCH"])
@pytest.mark.parametrize("defense_mode", ["INPUT", "FEATURES", "OUTPUT", "POST_HOC"])
def test_authenticated_complete_lifecycle_and_offline_verification(mode, defense_mode, tmp_path, monkeypatch):
    async def scenario():
        service, sources = await make_service(tmp_path, monkeypatch, mode, defense_mode)
        try:
            assert (await asyncio.to_thread(request, service, "red", "POST", "/v1/experiments", service.request.model_dump(), "bad-create"))[0] == 403
            assert (await asyncio.to_thread(request, service, "operator", "POST", "/v1/experiments", service.request.model_dump(), "create"))[0] == 201
            batch = {"epoch": service.ctx.epoch, "items": [{"item_id": "item-" + str(i), "text": p.text} for i, p in enumerate(sources)]}
            assert (await asyncio.to_thread(request, service, "red", "POST", "attacks", batch, "upload"))[0] == 201
            assert (await asyncio.to_thread(request, service, "operator", "POST", "seal", {"epoch": service.ctx.epoch}, "seal"))[0] == 200
            assert (await asyncio.to_thread(request, service, "red", "POST", "attacks", batch, "post-seal"))[0] == 409
            assert (await asyncio.to_thread(request, service, "blue-human", "GET", "feedback"))[1]["status"] == "EMBARGOED"
            await operation(service, "start")
            if mode == "INTERACTIVE":
                sessions = []
                for i in range(3):
                    response = await asyncio.to_thread(request, service, "operator", "POST", "sessions", {"epoch": service.ctx.epoch}, "session-" + str(i))
                    assert response[0] == 201, response
                    sessions.append(response[1]["session_id"])
                while service.participant is None: await asyncio.sleep(.01)
                for wave in range(2):
                    async def turn(lane):
                        body = {"epoch": service.ctx.epoch, "turn_index": wave, "text": sources[wave * 3 + lane].text}
                        route = f"sessions/{sessions[lane]}/turns"
                        response = await asyncio.to_thread(request, service, "red", "POST", route, body, "turn-" + str(wave * 3 + lane))
                        assert response[0] == 202, response
                        assert (await asyncio.to_thread(request, service, "red", "POST", route, body, "turn-" + str(wave * 3 + lane)))[1] == response[1]
                        poll = route + "/" + response[1]["turn_id"]
                        assert (await asyncio.to_thread(request, service, "red", "GET", poll))[0] == 202
                        while True:
                            result = await asyncio.to_thread(request, service, "red", "GET", poll)
                            if result[0] != 202: break
                            await asyncio.sleep(.05)
                        assert result[0] == 200 and result[1]["public_reply"] == "model output", result
                    await asyncio.gather(*(turn(i) for i in range(3)))
            else:
                assert (await asyncio.to_thread(request, service, "red", "POST", "sessions/" + str(uuid4()) + "/turns", {"epoch": service.ctx.epoch, "turn_index": 0, "text": "substitute"}, "bad-turn"))[0] == 503
            await operation(service, "finish")
            assert (await asyncio.to_thread(request, service, "red", "GET", "feedback"))[1]["status"] == "EMBARGOED"
            await operation(service, "close")
            assert (await asyncio.to_thread(request, service, "red", "GET", "bundle"))[0] == 403
            response = await asyncio.to_thread(request, service, "auditor", "GET", "bundle")
            assert response[0] == 200 and response[2] == "application/zip" and response[1].startswith(b"PK")
            await operation(service, "release")
            analyses = await operation(service, "analysis") if defense_mode == "POST_HOC" else None
            if mode == "SEALED_BATCH":
                final = await asyncio.to_thread(request, service, "red", "GET", "feedback")
                assert final[1]["status"] == "RELEASED" and len(final[1]["items"]) == 6
            with closing(service.store.connect()) as conn:
                row = conn.execute("SELECT * FROM experiments").fetchone()
                assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 6
                assert conn.execute("SELECT count(*) FROM n04_turns WHERE state='DONE'").fetchone()[0] == 6
            args = ["--bundle", str(tmp_path / "evidence.zip"), "--recorder-key", service.recorder_key.public_key().public_bytes_raw().hex(),
                "--witness-key", service.witness_key.public_key().public_bytes_raw().hex(), "--domain-id", service.ctx.domain_id,
                "--experiment-id", service.ctx.experiment_id, "--epoch", str(service.ctx.epoch), "--manifest-digest", row["public_commitment"],
                "--recorder-key-id", "n08-prototype-recorder-001", "--witness-key-id", "n08-prototype-witness-001", "--defense-mode", defense_mode,
                "--broker-actor", ACTOR, "--keys-json", str(tmp_path / "replay-keys.json")]
            if mode == "SEALED_BATCH": args += ["--require-prototype-batch"]
            else:
                public = service.recorder_key.public_key().public_bytes_raw().hex()
                args += ["--require-transport-profile", "--transport-profile-key", public, "--transport-profile-key-id", "n08-prototype-recorder-001", "--feedback-policy-key", public, "--feedback-policy-key-id", "n08-prototype-recorder-001"]
            if analyses is not None:
                with closing(service.store.connect()) as conn:
                    release_id = conn.execute("SELECT release_id FROM n04_runs").fetchone()[0]
                args += ["--expected-release-id", release_id, "--analysis-keys-json", str(tmp_path / "analysis/replay-keys.json")]
                for signed in analyses["result"]["analyses"]:
                    turn = signed["receipt"]["turn_id"]
                    args += ["--post-hoc-bundle", str(tmp_path / "analysis" / (turn + ".zip"))]
                    assert (await asyncio.to_thread(request, service, "red", "GET", "analysis/" + turn))[0] == 403
                    assert (await asyncio.to_thread(request, service, "auditor", "GET", "analysis/" + turn))[2] == "application/zip"
            assert verify_cli(args) == 0
        finally:
            await service.shutdown()
    asyncio.run(scenario())


def test_sealed_item_mutation_is_refused_before_dispatch_and_never_released(tmp_path, monkeypatch):
    async def scenario():
        service, sources = await make_service(tmp_path, monkeypatch, "SEALED_BATCH")
        try:
            service.dispatch(service.p["operator"], "POST", "/v1/experiments", {"idempotency-key": "create"}, service.request.model_dump_json().encode())
            prefix = f"/v1/experiments/{service.ctx.experiment_id}/"
            batch = {"epoch": service.ctx.epoch, "items": [{"item_id": "one", "text": sources[0].text}]}
            service.dispatch(service.p["red"], "POST", prefix + "attacks", {"idempotency-key": "upload"}, json.dumps(batch).encode())
            service.dispatch(service.p["operator"], "POST", prefix + "seal", {"idempotency-key": "seal"}, json.dumps({"epoch": service.ctx.epoch}).encode())
            # Simulate a corrupted internal item reference after sealing. The
            # frozen plan must detect it even when replacement text is admitted.
            with service.store.transaction() as conn:
                row = conn.execute("SELECT * FROM experiments").fetchone()
                replacement = service.store.put_payload(conn, row, "attack", {"text": sources[1].text, "commitment_nonce": "00" * 32})
                conn.execute("UPDATE batch_items SET artifact_id=?", (replacement,))
            await operation(service, "start")
            await operation(service, "finish")
            with closing(service.store.connect()) as conn:
                assert tuple(conn.execute("SELECT phase,integrity FROM experiments").fetchone()) == ("INVALID", "INVALID")
                assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 0
            assert service.runtime.model.trace == []
            assert (await asyncio.to_thread(request, service, "operator", "POST", "release", {"epoch": service.ctx.epoch}, "release"))[0] == 409
        finally:
            await service.shutdown()
    asyncio.run(scenario())


def test_finish_settles_queued_work_and_release_keeps_the_floor_and_cold_resume_closed(tmp_path, monkeypatch):
    from arena.ports import DependencyUnavailable
    async def scenario():
        service, sources = await make_service(tmp_path, monkeypatch, "INTERACTIVE")
        try:
            await asyncio.to_thread(request, service, "operator", "POST", "/v1/experiments", service.request.model_dump(), "create")
            await asyncio.to_thread(request, service, "operator", "POST", "seal", {"epoch": service.ctx.epoch}, "seal")
            await operation(service, "start")
            sessions = []
            for i in range(3):
                sessions.append((await asyncio.to_thread(request, service, "operator", "POST", "sessions", {"epoch": service.ctx.epoch}, "session-" + str(i)))[1]["session_id"])
            while service.participant is None: await asyncio.sleep(.01)
            route = f"sessions/{sessions[0]}/turns"
            body = {"epoch": service.ctx.epoch, "turn_index": 0, "text": sources[0].text}
            assert (await asyncio.to_thread(request, service, "red", "POST", route, body, "first"))[0] == 202
            await operation(service, "finish")
            assert (await asyncio.to_thread(request, service, "red", "POST", route, dict(body, turn_index=1), "after-finish"))[0] == 409
            with closing(service.store.connect()) as conn:
                job = conn.execute("SELECT * FROM n06_jobs").fetchone()
                assert job["state"] == "AUTHORIZED" and job["published"] == 0
            await operation(service, "close")
            assert (await asyncio.to_thread(request, service, "operator", "POST", "release", {"epoch": service.ctx.epoch}, "release"))[0] == 202
            await asyncio.sleep(.05)
            with closing(service.store.connect()) as conn:
                if service.queue.clock_ns() < job["release_ns"]:
                    assert conn.execute("SELECT phase FROM experiments").fetchone()[0] == "CLOSED"
            await operation(service, "release")
            final = await asyncio.to_thread(request, service, "blue-human", "GET", "feedback")
            assert final[1]["status"] == "RELEASED" and len(final[1]["items"]) == 1
            assert service.queue.clock_ns() >= job["release_ns"]
            assert len(service.runtime.model.trace) == 1
            with pytest.raises(DependencyUnavailable, match="COLD_RESUME"):
                module.PrototypeService(service.runtime, service.corpus, tmp_path, tmp_path / "unused")
        finally:
            await service.shutdown()
    asyncio.run(scenario())


def test_anchor_outage_closes_only_as_quiescent_invalid_and_never_releases(tmp_path, monkeypatch):
    async def scenario():
        anchor_key = Ed25519PrivateKey.generate()
        recovery_key = Ed25519PrivateKey.generate()
        export_key = Ed25519PrivateKey.generate()
        def pinned(key, name):
            return {"authority_id": name, "key_id": name,
                    "public_key_bytes": key.public_key().public_bytes_raw()}
        authorities = {
            "anchor": pinned(anchor_key, "test-anchor"),
            "recovery": pinned(recovery_key, "test-recovery"),
            "invalid_export": pinned(export_key, "test-export"),
        }
        monkeypatch.setattr(module, "load_recovery_authorities", lambda _path: authorities)
        monkeypatch.setattr(module, "key_from_file", lambda _path: export_key)
        service, _ = await make_service(tmp_path, monkeypatch, "INTERACTIVE")
        try:
            await asyncio.to_thread(request, service, "operator", "POST", "/v1/experiments", service.request.model_dump(), "create")
            await asyncio.to_thread(request, service, "operator", "POST", "seal", {"epoch": service.ctx.epoch}, "seal")
            await operation(service, "start")
            await operation(service, "finish")

            class UnavailableAnchor:
                def __init__(self, delegate):
                    self.delegate = delegate
                    self.public_key = b"p" * 32
                    self.key_id = "test-anchor"
                    self.authority_id = "test-anchor"

                def prepare(self, event):
                    raise RecoveryAnchorError("ANCHOR_UNAVAILABLE")

                def abort(self, event, reason):
                    return self.delegate.abort(event, reason)

                def records(self, context):
                    return []

                def terminal_close(self, checkpoint, witness, integrity):
                    return self.delegate.terminal_close(checkpoint, witness, integrity)

            service.anchor = UnavailableAnchor(service.anchor)
            service.controller.recorder.anchor = service.anchor
            await operation(service, "close")
            with closing(service.store.connect()) as conn:
                run = conn.execute("SELECT phase,integrity FROM experiments").fetchone()
                controller = conn.execute("SELECT state FROM n04_runs").fetchone()
            assert tuple(run) == ("CLOSED", "INVALID")
            assert controller["state"] == "CLOSED"
            events = service.controller.recorder.get_events(service.ctx)
            assert events[-1].event_type == "CLOSED"
            assert events[-1].outcome_code == "INVALID"
            service.controller.export_invalid_evidence(
                service.p["auditor"], tmp_path / "direct-invalid-evidence.zip",
                authorities["invalid_export"], export_key)
            status, archive, content_type = await asyncio.to_thread(
                request, service, "auditor", "GET",
                f"/v1/experiments/{service.ctx.experiment_id}/invalid-evidence")
            assert status == 200 and content_type == "application/zip" and archive.startswith(b"PK"), (status, archive, content_type)
            result = verify_invalid_evidence_bundle(
                tmp_path / "invalid-evidence.zip",
                recorder_key=service.recorder_key.public_key().public_bytes_raw(),
                witness_key=service.witness_key.public_key().public_bytes_raw(),
                anchor_key=authorities["anchor"]["public_key_bytes"],
                recovery_key=authorities["recovery"]["public_key_bytes"],
                export_key=authorities["invalid_export"]["public_key_bytes"],
                expected_context=service.ctx,
                expected_manifest_digest=service._row(
                    service.p["auditor"], service.ctx.experiment_id)['public_commitment'],
                recorder_key_id="n08-prototype-recorder-001",
                witness_key_id="n08-prototype-witness-001",
                anchor_key_id="test-anchor", recovery_key_id="test-recovery",
                export_key_id="test-export",
            )
            assert result["status"] == "AUTHENTIC_INVALID_INCOMPLETE"
            with pytest.raises(DependencyUnavailable, match="RELEASE_REQUIRES_VALID_INTEGRITY"):
                service.controller.release(service.p["operator"])
        finally:
            await service.shutdown()
    asyncio.run(scenario())


def test_coordinated_store_rollback_is_refused_before_runtime_or_listener_start(tmp_path, monkeypatch):
    async def scenario():
        backend = tmp_path / "test-backend"
        service_work = backend / "artifacts" / "prototype-live"
        authority_dir = service_work / "unused-keys"
        recovery_dir = service_work / "prototype-recovery"
        recovery_dir.mkdir(parents=True)
        (backend / "infra" / "prototype").mkdir(parents=True)
        owner_roots = backend / "infra" / "owner-delegated-n08"
        owner_roots.mkdir(parents=True)

        keys = {name: Ed25519PrivateKey.generate() for name in ("anchor", "recovery", "invalid_export")}
        authority_config = {
            "schema_version": "arena.prototype-recovery-authorities.v1",
            "anchor": {
                "authority_id": "test-prototype-anchor",
                "key_id": "prototype-anchor-20261026",
                "public_key": keys["anchor"].public_key().public_bytes_raw().hex(),
            },
            "recovery": {
                "authority_id": "test-feedback-recovery",
                "key_id": "test-feedback-recovery",
                "public_key": keys["recovery"].public_key().public_bytes_raw().hex(),
            },
            "invalid_export": {
                "authority_id": "test-invalid-export",
                "key_id": "test-invalid-export",
                "public_key": keys["invalid_export"].public_key().public_bytes_raw().hex(),
            },
            "recorder_principal_id": "n08-prototype-recorder-001",
        }
        (backend / "infra" / "prototype" / "recovery-authorities.json").write_text(
            json.dumps(authority_config), encoding="utf-8"
        )
        anchor_private_path = recovery_dir / "prototype-anchor-20261026-private.pem"
        anchor_private_path.write_bytes(keys["anchor"].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        monkeypatch.setattr(module, "BACKEND", backend)
        monkeypatch.setattr(recovery_startup, "BACKEND", backend)

        def provision_with_anchor_recorder(directory, authority_path, store, domain):
            result = test_credentials(directory, authority_path, store, domain)
            ca = x509.load_pem_x509_certificate((directory / "ca.pem").read_bytes())
            ca_key = serialization.load_pem_private_key(
                (directory / "ca.key").read_bytes(), password=None
            )
            recorder_tls_key = ec.generate_private_key(ec.SECP256R1())
            now = datetime.now(timezone.utc)
            recorder_tls_certificate = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "recorder")]))
                .issuer_name(ca.subject)
                .public_key(recorder_tls_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
                .add_extension(x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier("urn:arena:principal:n08-prototype-recorder-001")
                ]), critical=False)
                .sign(ca_key, hashes.SHA256())
            )
            (directory / "client-recorder.pem").write_bytes(
                recorder_tls_certificate.public_bytes(serialization.Encoding.PEM)
            )
            (directory / "client-recorder.key").write_bytes(recorder_tls_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            return result

        service, _ = await make_service(
            service_work, monkeypatch, "INTERACTIVE", real_anchor=True,
            credential_provisioner=provision_with_anchor_recorder,
        )
        root = service.root
        try:
            await asyncio.to_thread(
                request, service, "operator", "POST", "/v1/experiments",
                service.request.model_dump(), "create",
            )
            await asyncio.to_thread(
                request, service, "operator", "POST", "seal",
                {"epoch": service.ctx.epoch}, "seal",
            )
            await operation(service, "start")

            recorder_public = service.recorder_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            witness_public = service.witness_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            (owner_roots / "recorder-public.pem").write_bytes(recorder_public)
            (owner_roots / "witness-public.pem").write_bytes(witness_public)

            snapshot_dir = tmp_path / "coherent-pre-close-snapshot"
            snapshot_dir.mkdir()
            for name in ("broker.sqlite3", "recorder.sqlite3", "witness.sqlite3"):
                source = root / name
                snapshot = snapshot_dir / name
                with sqlite3.connect(source) as original, sqlite3.connect(snapshot) as copied:
                    original.backup(copied)

            # Advance the recorder, witness, broker and independent anchor into
            # a terminal state, then restore the three protected stores together
            # while intentionally retaining the separate anchor's newer head.
            await operation(service, "finish")
            await operation(service, "close")
        finally:
            await service.shutdown()

        for name in ("broker.sqlite3", "recorder.sqlite3", "witness.sqlite3"):
            target = root / name
            with sqlite3.connect(snapshot_dir / name) as snapshot, sqlite3.connect(target) as restored:
                snapshot.backup(restored)

        with pytest.raises(RecoveryAnchorError, match="ANCHOR_AHEAD"):
            recovery_startup.inspect_existing_prototype(root, authority_dir)

        spec = importlib.util.spec_from_file_location(
            "prototype_run_rollback_test", Path(__file__).parents[2] / "tools" / "prototype_run.py"
        )
        prototype_run = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(prototype_run)
        monkeypatch.setattr(prototype_run, "BACKEND", backend)
        monkeypatch.setattr(
            prototype_run, "PrototypeRuntime",
            lambda *args, **kwargs: pytest.fail("runtime constructed before rollback refusal"),
        )
        with pytest.raises(ValueError, match="EXISTING_STORE_RECOVERY_REFUSED"):
            await prototype_run.run(SimpleNamespace(output=root, authority_directory=authority_dir))

    asyncio.run(scenario())


def test_wrong_key_recovery_retry_does_not_close_participant_gateway(tmp_path, monkeypatch):
    async def scenario():
        service, _ = await make_service(tmp_path, monkeypatch, "INTERACTIVE")
        try:
            await asyncio.to_thread(
                request, service, "operator", "POST", "/v1/experiments",
                service.request.model_dump(), "create",
            )
            await asyncio.to_thread(
                request, service, "operator", "POST", "seal",
                {"epoch": service.ctx.epoch}, "seal",
            )
            await operation(service, "start")
            turn_id = str(uuid4())
            with service.store.transaction() as conn:
                conn.execute(
                    "INSERT INTO n04_recoveries VALUES(?,?,?,?,?,?,?,?,?)",
                    (service.ctx.domain_id, service.ctx.experiment_id, service.ctx.epoch,
                     turn_id, "another-red-principal", "original-key", "operation-id", "{}", b"{}"),
                )
            service.participant = SimpleNamespace(
                accepting=True, active=False, lock=threading.RLock()
            )
            body = json.dumps({"turn_id": turn_id, "idempotency_key": "guessed-key"}).encode()
            with pytest.raises(module.BrokerError, match="IDEMPOTENCY_CONFLICT"):
                service.dispatch(
                    service.p["red"], "POST", "/v1/turn-feedback/recovery",
                    {
                        "idempotency-key": "guessed-key",
                        "accept": "application/vnd.arena.feedback-replay.v1+json",
                    }, body,
                )
            assert service.participant.accepting is True
        finally:
            await service.shutdown()

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["before-witness-ack", "after-witness-ack", "after-anchor-ack"])
def test_restart_retries_close_after_lost_ack_without_reset_or_new_events(tmp_path, monkeypatch, fault):
    async def scenario():
        service, _, backend, authority_dir = await make_real_anchor_service(tmp_path, monkeypatch)
        root = service.root
        try:
            await asyncio.to_thread(
                request, service, "operator", "POST", "/v1/experiments",
                service.request.model_dump(), "create",
            )
            await asyncio.to_thread(
                request, service, "operator", "POST", "seal",
                {"epoch": service.ctx.epoch}, "seal",
            )
            await operation(service, "start")
            await operation(service, "finish")
            close = service.controller.witness.close_checkpoint
            terminal_close = service.anchor.terminal_close
            if fault == "before-witness-ack":
                async def lose_witness_before_commit(checkpoint):
                    raise RuntimeError("simulated witness close outage")
                service.controller.witness.close_checkpoint = lose_witness_before_commit
            elif fault == "after-witness-ack":
                async def lose_ack_after_witness_commit(checkpoint):
                    await close(checkpoint)
                    raise RuntimeError("simulated lost witness close acknowledgment")
                service.controller.witness.close_checkpoint = lose_ack_after_witness_commit
            else:
                def lose_anchor_ack_after_commit(checkpoint, witness, integrity):
                    terminal_close(checkpoint, witness, integrity)
                    raise RuntimeError("simulated lost anchor terminal acknowledgment")
                service.anchor.terminal_close = lose_anchor_ack_after_commit
                service.controller.recorder.anchor = service.anchor
            status, submitted, _ = await asyncio.to_thread(
                request, service, "operator", "POST", "close",
                {"epoch": service.ctx.epoch}, "close-after-restart-fault",
            )
            assert status == 202, submitted
            for _ in range(400):
                observed = await asyncio.to_thread(
                    request, service, "operator", "GET",
                    "operations/" + submitted["operation_id"],
                )
                if observed[1]["state"] in {"DONE", "FAILED"}:
                    break
                await asyncio.sleep(.025)
            assert observed[1]["state"] == "FAILED", observed[1]
            with closing(service.store.connect()) as conn:
                run = conn.execute("SELECT phase,integrity FROM experiments").fetchone()
                controller = conn.execute(
                    "SELECT state,close_json,witness_json FROM n04_runs"
                ).fetchone()
            assert tuple(run) == ("SCORED", "PENDING")
            assert controller["state"] == "CLOSING" and controller["close_json"]
            assert controller["witness_json"] is None
            with sqlite3.connect(root / "witness.sqlite3") as witness_db:
                witness_close = witness_db.execute("SELECT count(*) FROM close_receipts").fetchone()[0]
            assert witness_close == (0 if fault == "before-witness-ack" else 1)
            before_events = tuple(
                event_digest(event) for event in service.controller.recorder.get_events(service.ctx)
            )
        finally:
            await service.shutdown()

        inspection = recovery_startup.inspect_existing_prototype(
            root, authority_dir, allow_feedback_recovery=True
        )
        assert inspection["recovery_only_action"] == "RETRY_PENDING_CLOSE"
        assert inspection["pending_close_kind"] == "AUTHORITY_ACK"

        # This synthetic service fixture has no real Docker cells. The startup
        # verifier still authenticates its stores; the pending checkpoint path
        # must not call the model fence or start a replacement runtime.
        cells = tuple({
            "container_id": hex(index + 16)[2:] * 64,
            "image_id": "test-pinned-image",
            "image_ref": "test-pinned-image",
            "cpuset": str(index),
        } for index in range(3))
        monkeypatch.setattr(module.PrototypeService, "_load_manifest_bound_old_cells", lambda self: cells)
        resumed = module.PrototypeService.open_existing_recovery(
            service.corpus, root, authority_dir
        )
        try:
            resumed.startup_recovery_preflight()
            assert resumed.runtime is None and resumed.worker is None
            assert resumed.controller.runtime.started is False
            fence_calls = []
            resumed._fence_previous_model_containers = lambda session_id: fence_calls.append(session_id)
            resumed.listen()
            await operation(resumed, "close", "close-after-restart-fault")
            after_events = tuple(event_digest(event) for event in resumed.recorder.get_events(resumed.ctx))
            assert after_events == before_events
            assert fence_calls == []
            with closing(resumed.store.connect()) as conn:
                run = conn.execute("SELECT phase,integrity FROM experiments").fetchone()
                controller = conn.execute(
                    "SELECT state,close_json,witness_json FROM n04_runs"
                ).fetchone()
            assert tuple(run) == ("CLOSED", "VALID_WITHIN_PROFILE")
            assert controller["state"] == "CLOSED" and controller["witness_json"]
            assert (root / "anchor-records.jsonl").is_file()
            assert (root / "evidence.zip").is_file()
            assert (root / "replay-keys.json").is_file()
        finally:
            await resumed.shutdown()

    asyncio.run(scenario())
