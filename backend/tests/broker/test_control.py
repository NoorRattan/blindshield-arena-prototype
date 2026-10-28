"""Real local SQLite/TLS evidence. Synthetic RUNNING SQL fixtures are NOT run authority."""

from contextlib import closing
import hashlib
import http.client
import json
import multiprocessing
import os
from pathlib import Path
import socket
import ssl
import threading
import time
from uuid import uuid4

import pytest

from arena.broker.config import BrokerConfig
from arena.broker.core import Broker
from arena.broker.provision import initialize
from arena.broker.server import Server, tls_context
from arena.broker.store import BrokerError, Store
from arena.contracts.api import AttackBatch, EpochRequest, TurnSubmission
from arena.contracts.common import Principal
from arena.contracts.crypto import canonical_bytes, commitment
from arena.contracts.jsonwire import load_wire

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def arena(tmp_path):
    config = load_wire(BrokerConfig, (ROOT / "config/broker-demo.json").read_bytes())
    directory = tmp_path / "dev"
    store = initialize(directory, config)
    identities = json.loads((directory / "identities.json").read_bytes())
    def principal(subject):
        label = identities[subject]["label"]
        context = ssl.PEM_cert_to_DER_cert((directory / f"{label}.pem").read_text())
        return store.authenticate(hashlib.sha256(context).hexdigest())
    return Broker(store, config), directory, {s: principal(s) for s in identities}


def created(arena):
    broker, _, principals = arena
    _, result = broker.create(principals["operator"], broker.config.profiles[0].request, "create")
    return result


def running(arena):
    """Synthetic state insertion for reservation tests. No public path can bypass start."""
    result = created(arena)
    with arena[0].store.transaction() as connection:
        connection.execute("UPDATE experiments SET phase='RUNNING' WHERE id=?", (result["experiment_id"],))
    return result


def session(arena, experiment, key="session"):
    return arena[0].session(arena[2]["operator"], experiment["experiment_id"], EpochRequest(epoch=experiment["epoch"]), key)[1]["session_id"]


def expect_error(code, function, *args):
    with pytest.raises(BrokerError) as error:
        function(*args)
    assert error.value.code == code
    return error.value.status


def test_create_replay_changed_body_epoch_and_restart(arena):
    broker, directory, principals = arena
    first = created(arena)
    assert created(arena) == first
    _, second = broker.create(principals["operator"], broker.config.profiles[0].request, "new")
    assert second["epoch"] == first["epoch"] + 1
    recovered = Broker(Store(directory / "broker.sqlite3", (directory / "vault.key").read_bytes()), broker.config)
    assert recovered.create(principals["operator"], broker.config.profiles[0].request, "create")[1] == first
    changed = broker.config.profiles[0].request.model_copy(update={"model_version_id": "not-approved"})
    expect_error("POLICY_NOT_READY", broker.create, principals["operator"], changed, "new")


def test_payload_encryption_idempotency_and_frozen_manifest(arena):
    broker, directory, p = arena
    exp = created(arena)
    identifier = exp["experiment_id"]
    text = "private-canary-4c02-雪\r\n"
    upload = AttackBatch(epoch=exp["epoch"], items=[{"item_id": "one", "text": text}])
    first = broker.upload(p["red"], identifier, upload, "up")
    assert broker.upload(p["red"], identifier, upload, "up") == first
    expect_error("IDEMPOTENCY_CONFLICT", broker.upload, p["red"], identifier,
                 AttackBatch(epoch=exp["epoch"], items=[{"item_id": "one", "text": "changed"}]), "up")
    _, sealed = broker.seal(p["operator"], identifier, EpochRequest(epoch=exp["epoch"]), "seal")
    with closing(broker.store.connect()) as connection:
        row = connection.execute("SELECT * FROM experiments WHERE id=?", (identifier,)).fetchone()
        artifact = connection.execute("SELECT artifact_id FROM batch_items WHERE experiment_id=?", (identifier,)).fetchone()[0]
        manifest = broker.store.read_payload(row["manifest_id"])
        assert commitment(canonical_bytes(manifest["manifest"]), bytes.fromhex(manifest["commitment_nonce"])) == sealed["public_commitment"]
    assert broker.store.read_payload(artifact)["text"] == text
    assert broker.upload(p["red"], identifier, upload, "up") == first  # Replay survives phase advance.
    expect_error("WRONG_PHASE", broker.upload, p["red"], identifier, upload, "another")
    for path in directory.glob("broker.sqlite3*"):
        assert text.encode("utf-8") not in path.read_bytes()
    wrong_key = Store(broker.store.path, os.urandom(32))
    with pytest.raises(Exception):
        wrong_key.read_payload(artifact)


def test_atomic_rollback_on_duplicate_batch_item(arena):
    broker, _, p = arena
    exp = created(arena)
    original = AttackBatch(epoch=exp["epoch"], items=[{"item_id": "used", "text": "first"}])
    broker.upload(p["red"], exp["experiment_id"], original, "up")
    bad = AttackBatch(epoch=exp["epoch"], items=[{"item_id": "fresh", "text": "must-rollback"}, {"item_id": "used", "text": "duplicate"}])
    expect_error("IDEMPOTENCY_CONFLICT", broker.upload, p["red"], exp["experiment_id"], bad, "bad")
    with closing(broker.store.connect()) as connection:
        assert connection.execute("SELECT count(*) FROM payloads").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM batch_items").fetchone()[0] == 1


def test_roles_domains_memberships_stale_epoch_and_embargo(arena):
    broker, _, p = arena
    exp = created(arena)
    identifier = exp["experiment_id"]
    assert broker.status(p["blue"], identifier)[1] == {"status": "EMBARGOED"}
    assert broker.status(p["red"], identifier, True)[1] == {"status": "EMBARGOED"}
    for subject in ("operator", "auditor"):
        expect_error("FORBIDDEN", broker.status, p[subject], identifier, True)
    with broker.store.transaction() as connection:
        connection.execute("UPDATE experiments SET phase='INVALID',integrity='INVALID' WHERE id=?", (identifier,))
    assert broker.status(p["blue"], identifier)[1] == {"status": "EMBARGOED"}
    other_domain = p["red"].model_copy(update={"domain_id": str(uuid4())})
    other_subject = p["red"].model_copy(update={"subject_id": "unassigned"})
    for principal in (other_domain, other_subject):
        assert expect_error("NOT_FOUND", broker.status, principal, identifier) == 404
    assert expect_error("NOT_FOUND", broker.status, p["red"], str(uuid4())) == 404
    expect_error("STALE_EPOCH", broker.seal, p["operator"], identifier, EpochRequest(epoch=exp["epoch"] + 1), "stale")
    expect_error("FORBIDDEN", broker.create, p["red"], broker.config.profiles[0].request, "bad")


def test_no_fake_start_or_closed_evidence(arena):
    broker, _, p = arena
    exp = created(arena)
    identifier, request = exp["experiment_id"], EpochRequest(epoch=exp["epoch"])
    broker.seal(p["operator"], identifier, request, "seal")
    assert expect_error("POLICY_NOT_READY", broker.unavailable, p["operator"], identifier, request, "start") == 503
    assert broker.status(p["operator"], identifier)[1]["phase"] == "SEALED"
    expect_error("WRONG_PHASE", broker.session, p["operator"], identifier, request, "s")
    for phase, action in (("INVALID", "close"), ("CLOSED", "release")):
        with broker.store.transaction() as connection:
            connection.execute("UPDATE experiments SET phase=? WHERE id=?", (phase, identifier))
        expect_error("POLICY_NOT_READY", broker.unavailable, p["operator"], identifier, request, action)
        assert broker.status(p["operator"], identifier)[1]["phase"] == phase


def test_atomic_budget_order_binding_and_queue(arena):
    broker, _, p = arena
    exp = running(arena)
    identifier = exp["experiment_id"]
    sessions = [session(arena, exp, f"s-{n}") for n in range(3)]
    expect_error("RESOURCE_BUDGET_EXCEEDED", broker.session, p["operator"], identifier, EpochRequest(epoch=exp["epoch"]), "s-4")
    request = TurnSubmission(epoch=exp["epoch"], turn_index=0, text="canary")
    first = broker.reserve_turn(p["red"], identifier, sessions[0], request, "turn")
    assert broker.reserve_turn(p["red"], identifier, sessions[0], request, "turn") == first
    expect_error("IDEMPOTENCY_CONFLICT", broker.reserve_turn, p["red"], identifier, sessions[1], request, "turn")
    expect_error("WRONG_PHASE", broker.reserve_turn, p["red"], identifier, sessions[0], request, "different")
    expect_error("RESOURCE_BUDGET_EXCEEDED", broker.reserve_turn, p["red"], identifier, sessions[0], TurnSubmission(epoch=exp["epoch"], turn_index=1, text="next"), "next")
    # Freeze a lower test-only budget before additional admissions; no public profile mutation exists.
    with broker.store.transaction() as connection:
        profile = broker.config.profiles[0].model_copy(update={"query_budget": 2})
        connection.execute("UPDATE experiments SET config_json=? WHERE id=?", (profile.model_dump_json(), identifier))
    broker.reserve_turn(p["red"], identifier, sessions[1], request, "two")
    expect_error("RESOURCE_BUDGET_EXCEEDED", broker.reserve_turn, p["red"], identifier, sessions[2], request, "three")
    with closing(broker.store.connect()) as connection:
        assert connection.execute("SELECT admitted FROM budgets").fetchone()[0] == 2


def test_actual_500_query_cap_is_shared_across_three_sessions(arena):
    broker, _, p = arena
    exp = running(arena)
    identifier = exp["experiment_id"]
    sessions = [session(arena, exp, f"s-{n}") for n in range(3)]
    for number in range(500):
        lane, index = number % 3, number // 3
        request = TurnSubmission(epoch=exp["epoch"], turn_index=index, text="synthetic-budget-test")
        status, receipt = broker.reserve_turn(p["red"], identifier, sessions[lane], request, f"t-{number}")
        assert status == 201
        # Synthetic settlement only, to exercise 500 *admissions*, not to claim model completion.
        with broker.store.transaction() as connection:
            connection.execute("UPDATE turns SET state='CANCELLED' WHERE id=?", (receipt["turn_id"],))
    request = TurnSubmission(epoch=exp["epoch"], turn_index=166, text="cap")
    expect_error("RESOURCE_BUDGET_EXCEEDED", broker.reserve_turn, p["red"], identifier, sessions[2], request, "over-cap")
    assert broker.reserve_turn(p["red"], identifier, sessions[1],
        TurnSubmission(epoch=exp["epoch"], turn_index=166, text="synthetic-budget-test"), "t-499")[0] == 201
    with closing(broker.store.connect()) as connection:
        assert connection.execute("SELECT admitted FROM budgets").fetchone()[0] == 500
        assert connection.execute("SELECT count(*) FROM turns").fetchone()[0] == 500


def test_domain_queue_cap_applies_across_experiments(arena):
    broker, _, p = arena
    first = running(arena)
    _, second = broker.create(p["operator"], broker.config.profiles[0].request, "another-experiment")
    with broker.store.transaction() as connection:
        connection.execute("UPDATE experiments SET phase='RUNNING' WHERE id=?", (second["experiment_id"],))
    for exp, count in ((first, 3), (second, 2)):
        for number in range(count):
            sid = session(arena, exp, f"session-{number}")
            args = (p["red"], exp["experiment_id"], sid, TurnSubmission(epoch=exp["epoch"], turn_index=0, text="queue"), f"reserve-{number}")
            if exp == second and number == 1:
                expect_error("RESOURCE_BUDGET_EXCEEDED", broker.reserve_turn, *args)
            else:
                broker.reserve_turn(*args)
    with closing(broker.store.connect()) as connection:
        assert connection.execute("SELECT count(*) FROM turns").fetchone()[0] == 4


def test_batch_requires_nonempty_seal_and_registered_config_is_exact(arena):
    broker, _, p = arena
    profile = broker.config.profiles[0]
    batch = profile.model_copy(update={"request": profile.request.model_copy(update={"interaction_mode": "SEALED_BATCH"})})
    broker.config = BrokerConfig(profiles=[batch])
    exp = created(arena)
    expect_error("POLICY_NOT_READY", broker.seal, p["operator"], exp["experiment_id"], EpochRequest(epoch=exp["epoch"]), "seal")
    assert broker.status(p["operator"], exp["experiment_id"])[1]["phase"] == "CREATED"
    broker.upload(p["red"], exp["experiment_id"], AttackBatch(epoch=exp["epoch"], items=[{"item_id": "one", "text": "test"}]), "upload")
    assert broker.seal(p["operator"], exp["experiment_id"], EpochRequest(epoch=exp["epoch"]), "seal")[1]["phase"] == "SEALED"


def _reserve_process(db_path, key, config_json, principal_json, identifier, session_id, epoch, start, output):
    broker = Broker(Store(Path(db_path), key), BrokerConfig.model_validate_json(config_json))
    start.wait(10)
    try:
        output.put(broker.reserve_turn(Principal.model_validate_json(principal_json), identifier, session_id,
                                      TurnSubmission(epoch=epoch, turn_index=0, text="process-canary"), "race"))
    except Exception as error:
        output.put({"error_type": type(error).__name__})


def test_real_process_same_key_reserves_and_charges_once(arena):
    broker, _, p = arena
    exp = running(arena)
    sid = session(arena, exp)
    ctx = multiprocessing.get_context("spawn")
    start, output = ctx.Event(), ctx.Queue()
    workers = [ctx.Process(target=_reserve_process, args=(str(broker.store.path), broker.store.master_key,
               broker.config.model_dump_json(), p["red"].model_dump_json(), exp["experiment_id"], sid, exp["epoch"], start, output)) for _ in range(4)]
    try:
        for process in workers:
            process.start()
        start.set()
        results = [output.get(timeout=30) for _ in workers]
        for process in workers:
            process.join(timeout=15)
            assert process.exitcode == 0
        assert all(result == results[0] for result in results)
        assert results[0][0] == 201
        with closing(broker.store.connect()) as connection:
            assert connection.execute("SELECT count(*) FROM turns").fetchone()[0] == 1
            assert connection.execute("SELECT admitted FROM budgets").fetchone()[0] == 1
    finally:
        for process in workers:
            if process.is_alive():
                process.terminate()
                process.join(5)
        output.close()


def _crash_process(path, key, turn_id, commit):
    store = Store(Path(path), key)
    connection = store.connect()
    connection.execute("BEGIN IMMEDIATE")
    connection.execute("UPDATE turns SET state='DISPATCHED' WHERE id=?", (turn_id,))
    if commit:
        connection.commit()
    os._exit(37)  # No cleanup: actual abrupt process termination, not a mocked exception.


@pytest.mark.parametrize("committed", [False, True])
def test_abrupt_exit_recovery_never_retries(arena, committed):
    broker, _, p = arena
    exp = running(arena)
    sid = session(arena, exp)
    request = TurnSubmission(epoch=exp["epoch"], turn_index=0, text="crash")
    original = broker.reserve_turn(p["red"], exp["experiment_id"], sid, request, "turn")
    process = multiprocessing.get_context("spawn").Process(target=_crash_process, args=(str(broker.store.path), broker.store.master_key, original[1]["turn_id"], committed))
    process.start()
    process.join(20)
    if process.is_alive():
        process.terminate()
        process.join(5)
    assert process.exitcode == 37
    assert broker.store.recover_ambiguous() == int(committed)
    assert broker.store.recover_ambiguous() == 0
    # Original reservation receipt can replay; it does not represent final feedback or execution permission.
    assert broker.reserve_turn(p["red"], exp["experiment_id"], sid, request, "turn") == original
    with closing(broker.store.connect()) as connection:
        turn = connection.execute("SELECT * FROM turns").fetchone()
        lane = connection.execute("SELECT * FROM sessions").fetchone()
        assert turn["state"] == ("UNKNOWN" if committed else "RESERVED")
        assert lane["quarantined"] == int(committed)
        assert connection.execute("SELECT admitted FROM budgets").fetchone()[0] == 1
        if committed:
            result = json.loads(turn["result_json"])
            assert result["integrity"] == "INVALID" and result["model_execution"] == "UNKNOWN"
            assert broker.status(p["operator"], exp["experiment_id"])[1]["phase"] == "INVALID"


@pytest.fixture
def live(arena):
    broker, directory, principals = arena
    context = tls_context(directory / "server.pem", directory / "server.key", directory / "ca.pem")
    server = Server(("127.0.0.1", 0), broker, context)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    identities = json.loads((directory / "identities.json").read_bytes())
    def client_context(subject="operator", source=directory):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=str(directory / "ca.pem"))
        if subject:
            label = identities[subject]["label"]
            context.load_cert_chain(str(source / f"{label}.pem"), str(source / f"{label}.key"))
        return context
    def request(method, path, body=None, subject="operator", key="req", extra=None):
        connection = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=client_context(subject), timeout=8)
        encoded = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Idempotency-Key": key}
        headers.update(extra or {})
        try:
            connection.request(method, path, encoded, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()
    try:
        yield arena, server, client_context, request
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_real_tls_flow_replay_embargo_and_no_execution(live):
    (broker, _, _), _, _, request = live
    status, exp = request("POST", "/v1/experiments", broker.config.profiles[0].request.model_dump(), key="create")
    assert status == 201
    identifier, epoch = exp["experiment_id"], exp["epoch"]
    assert request("POST", "/v1/experiments", broker.config.profiles[0].request.model_dump(), key="create") == (status, exp)
    status, _ = request("POST", f"/v1/experiments/{identifier}/attacks", {"epoch": epoch, "items": [{"item_id": "one", "text": "synthetic"}]}, subject="red")
    assert status == 201
    assert request("GET", f"/v1/experiments/{identifier}/status", subject="blue")[1] == {"status": "EMBARGOED"}
    assert request("POST", f"/v1/experiments/{identifier}/seal", {"epoch": epoch})[0] == 200
    result = request("POST", f"/v1/experiments/{identifier}/start", {"epoch": epoch})
    assert result[0] == 503 and result[1]["code"] == "POLICY_NOT_READY"
    assert request("GET", f"/v1/experiments/{identifier}/status")[1]["phase"] == "SEALED"


def test_tls_requires_client_ca_binding_and_revocation(live, tmp_path):
    (broker, _, p), server, client_context, request = live
    with pytest.raises((ssl.SSLError, OSError, http.client.HTTPException)):
        request("GET", "/v1/experiments", subject=None)
    foreign = tmp_path / "foreign"
    initialize(foreign, broker.config)
    connection = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=client_context("operator", foreign), timeout=5)
    try:
        with pytest.raises((ssl.SSLError, OSError, http.client.HTTPException)):
            connection.request("GET", "/v1/experiments")
            connection.getresponse()
    finally:
        connection.close()
    broker.store.revoke(p["red"].subject_id)
    result = request("GET", "/v1/experiments", subject="red")
    assert result[0] == 401 and result[1]["code"] == "UNAUTHORIZED"
    # Still CA-valid but no server-side binding: certificate subject alone has no authority.
    with broker.store.transaction() as connection:
        connection.execute("DELETE FROM principals WHERE subject_id='auditor'")
    assert request("GET", "/v1/experiments", subject="auditor")[0] == 401


@pytest.mark.parametrize("extra", [{"X-Role": "operator"}, {"X-Forwarded-Client-Cert": "fake"}, {"Content-Encoding": "gzip"}, {"Transfer-Encoding": "chunked"}])
def test_no_identity_header_or_encoding_bypass(live, extra):
    (broker, _, _), server, client_context, request = live
    result = request("POST", "/v1/experiments", broker.config.profiles[0].request.model_dump(), subject="red", extra=extra)
    assert result[0] == 400 and set(result[1]) == {"code", "request_id"}
    # Separate TLS writes reproduce a header rejection before the body arrives.
    # The server must deliver the error even when a late body remains unread.
    with client_context("red").wrap_socket(socket.create_connection(server.server_address, timeout=8), server_hostname="localhost") as sock:
        injected = b"".join(f"{key}: {value}\r\n".encode("ascii") for key, value in extra.items())
        sock.sendall(b"POST /v1/experiments HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nIdempotency-Key: x\r\nContent-Length: 2\r\n" + injected + b"\r\n")
        time.sleep(0.02)
        sock.sendall(b"{}")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == 400
        assert json.loads(response.read())["code"] == "INVALID_SCHEMA"


@pytest.mark.parametrize("fragment,code,status", [
    (b"Content-Length: 2\r\nContent-Length: 2\r\n", "INVALID_SCHEMA", 400),
    (b"Content-Length: 70001\r\n", "BODY_TOO_LARGE", 413),
    (b"Content-Length: -1\r\n", "INVALID_SCHEMA", 400),
    (b"Content-Length: 2\r\n folded: bad\r\n", "INVALID_SCHEMA", 400),
])
def test_real_raw_http_bounds_and_ambiguous_framing(live, fragment, code, status):
    _, server, client_context, _ = live
    with client_context().wrap_socket(socket.create_connection(server.server_address, timeout=8), server_hostname="localhost") as sock:
        sock.sendall(b"POST /v1/experiments HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nIdempotency-Key: x\r\n" + fragment + b"\r\n{}")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == status
        assert json.loads(response.read())["code"] == code


def test_turn_http_route_cannot_admit_without_evidence(live):
    arena, _, _, request = live
    exp = running(arena)
    sid = session(arena, exp)
    status, body = request("POST", f"/v1/experiments/{exp['experiment_id']}/sessions/{sid}/turns",
                           {"epoch": exp["epoch"], "turn_index": 0, "text": "not-dispatched"}, subject="red")
    assert status == 503 and body["code"] == "POLICY_NOT_READY"
    cancel_status, cancel_body = request("POST", f"/v1/experiments/{exp['experiment_id']}/sessions/{sid}/cancel",
                                        {"epoch": exp["epoch"]}, subject="operator", key="cancel")
    assert cancel_status == 503 and cancel_body["code"] == "POLICY_NOT_READY"
    assert request("POST", f"/v1/experiments/{exp['experiment_id']}/sessions/{uuid4()}/cancel",
                   {"epoch": exp["epoch"]}, subject="operator", key="unknown")[0] == 404
    with closing(arena[0].store.connect()) as connection:
        assert connection.execute("SELECT admitted FROM budgets").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM turns").fetchone()[0] == 0


def test_strict_raw_json_does_not_echo_payload_or_accept_roles(live):
    (broker, _, _), server, client_context, _ = live
    for body in (b'{"secret":"canary-sensitive","secret":"duplicate"}',
                 json.dumps({**broker.config.profiles[0].request.model_dump(), "role": "operator"}).encode()):
        with client_context().wrap_socket(socket.create_connection(server.server_address, timeout=8), server_hostname="localhost") as sock:
            sock.sendall(b"POST /v1/experiments HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nIdempotency-Key: x\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            response = http.client.HTTPResponse(sock)
            response.begin()
            assert response.status == 400
            result = response.read()
            assert b"canary-sensitive" not in result and b"role" not in result
            assert set(json.loads(result)) == {"code", "request_id"}


def test_expired_database_binding_and_no_overwrite(arena):
    broker, directory, p = arena
    with broker.store.transaction() as connection:
        connection.execute("UPDATE principals SET expires_at='2020-01-01T00:00:00Z' WHERE subject_id='red'")
        fingerprint = connection.execute("SELECT fingerprint FROM principals WHERE subject_id='red'").fetchone()[0]
    expect_error("UNAUTHORIZED", broker.store.authenticate, fingerprint)
    expect_error("UNAUTHORIZED", broker.store.authenticate, "0" * 64)
    with pytest.raises(FileExistsError):
        initialize(directory, broker.config)
