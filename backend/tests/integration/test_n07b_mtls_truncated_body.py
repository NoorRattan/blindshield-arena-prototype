"""Actual-mTLS short-body denial at the N07B HTTP parser boundary.

The client declares a longer JSON body than it sends, then ends its TLS write
side with close-notify. The fixture is synthetic and makes no inference claim.
"""

import asyncio
from contextlib import closing
import hashlib
import json
import socket
import ssl
import time

from arena.contracts.api import TurnSubmission
from arena.execution.lab import LocalMTLSPilot
from test_n06_execution import environment


SCOPE = "N07B_ACTUAL_MTLS_TRUNCATED_BODY_DENIAL"


def _durable_snapshot(env):
    """Capture selected control state; this is not a full-database snapshot."""
    with closing(env.store.connect()) as conn:
        snapshot = {
            "experiment": tuple(conn.execute(
                "SELECT phase,integrity FROM experiments WHERE id=?",
                (env.ctx.experiment_id,),
            ).fetchone()),
            "sessions": tuple(tuple(row) for row in conn.execute(
                "SELECT id,quarantined FROM sessions WHERE experiment_id=? ORDER BY id",
                (env.ctx.experiment_id,),
            )),
            "budget_admissions": tuple(row[0] for row in conn.execute(
                "SELECT admitted FROM budgets ORDER BY rowid"
            )),
            "jobs": tuple(tuple(row) for row in conn.execute(
                "SELECT turn_id,state,known_execution,published FROM n06_jobs "
                "WHERE experiment_id=? ORDER BY turn_id",
                (env.ctx.experiment_id,),
            )),
            "turns": tuple(tuple(row) for row in conn.execute(
                "SELECT id,state FROM turns WHERE experiment_id=? ORDER BY id",
                (env.ctx.experiment_id,),
            )),
            "lab_actions": tuple(tuple(row) for row in conn.execute(
                "SELECT operation_id,acknowledged FROM n06_lab_actions "
                "WHERE experiment_id=? ORDER BY operation_id",
                (env.ctx.experiment_id,),
            )),
            "idempotency_count": conn.execute(
                "SELECT count(*) FROM idempotency WHERE experiment_id=?",
                (env.ctx.experiment_id,),
            ).fetchone()[0],
            "payload_count": conn.execute(
                "SELECT count(*) FROM payloads WHERE experiment_id=?",
                (env.ctx.experiment_id,),
            ).fetchone()[0],
            "lab_run": tuple(conn.execute(
                "SELECT state FROM n06_lab_runs WHERE experiment_id=?",
                (env.ctx.experiment_id,),
            ).fetchone()),
            "n04_run": tuple(conn.execute(
                "SELECT state FROM n04_runs WHERE experiment_id=?",
                (env.ctx.experiment_id,),
            ).fetchone()),
        }
    snapshot["recorder_events"] = tuple(
        (event.sequence, event.event_type, event.outcome_code)
        for event in env.recorder.get_events(env.ctx)
    )
    snapshot["model_calls"] = len(env.runtime.model.calls)
    return snapshot


def _flush_encrypted(sock, outgoing):
    while outgoing.pending:
        sock.sendall(outgoing.read())


def _read_encrypted(sock, incoming, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("TLS_RESPONSE_DEADLINE")
    sock.settimeout(remaining)
    encrypted = sock.recv(65_536)
    if not encrypted:
        incoming.write_eof()
        return False
    incoming.write(encrypted)
    return True


def _short_body_response(context, host, port, path, body):
    """Send a partial request and close the TLS write side orderly."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=host)
    deadline = time.monotonic() + 6
    with socket.create_connection((host, port), timeout=6) as sock:
        while True:
            try:
                tls.do_handshake()
                _flush_encrypted(sock, outgoing)
                break
            except ssl.SSLWantReadError:
                _flush_encrypted(sock, outgoing)
                if not _read_encrypted(sock, incoming, deadline):
                    raise ConnectionError("TLS_HANDSHAKE_EOF")
            except ssl.SSLWantWriteError:
                _flush_encrypted(sock, outgoing)

        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/json\r\n"
            "Idempotency-Key: n07b-truncated-body\r\n"
            f"Content-Length: {len(body) + 1}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body
        offset = 0
        while offset < len(request):
            try:
                offset += tls.write(request[offset:])
            except ssl.SSLWantWriteError:
                pass
            except ssl.SSLWantReadError:
                if not _read_encrypted(sock, incoming, deadline):
                    raise ConnectionError("TLS_WRITE_EOF")
            _flush_encrypted(sock, outgoing)

        try:
            tls.unwrap()
        except ssl.SSLWantReadError:
            pass
        _flush_encrypted(sock, outgoing)

        response = bytearray()
        content_length = None
        while time.monotonic() < deadline:
            try:
                chunk = tls.read(65_536)
                if chunk:
                    response.extend(chunk)
                else:
                    break
            except ssl.SSLWantReadError:
                if not _read_encrypted(sock, incoming, deadline):
                    break
            except ssl.SSLZeroReturnError:
                break
            _flush_encrypted(sock, outgoing)
            if b"\r\n\r\n" in response:
                header, payload = bytes(response).split(b"\r\n\r\n", 1)
                for line in header.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        content_length = int(line.split(b":", 1)[1].strip())
                        break
                if content_length is not None and len(payload) >= content_length:
                    return bytes(response)
        raise TimeoutError("HTTP_RESPONSE_INCOMPLETE")


def test_actual_mtls_short_body_with_orderly_tls_eof_is_denied_without_mutation(tmp_path):
    async def scenario():
        env = await environment(tmp_path / "fixture")
        lab = LocalMTLSPilot(
            env.worker,
            env.p["operator"],
            env.p,
            tmp_path / "tls",
            admission_window_ms=100,
        )
        try:
            before = _durable_snapshot(env)
            assert before["experiment"] == ("RUNNING", "PENDING")
            assert before["sessions"] == ((env.session, 0),)
            assert before["budget_admissions"] == (0,)
            assert before["jobs"] == before["turns"] == before["lab_actions"] == ()
            assert before["model_calls"] == 0

            path = (
                f"/v1/experiments/{env.ctx.experiment_id}/sessions/"
                f"{env.session}/turns"
            )
            request_body = json.dumps(TurnSubmission(
                epoch=env.ctx.epoch,
                turn_index=0,
                text=env.source.text,
            ).model_dump(exclude_none=True)).encode("utf-8")
            assert json.loads(request_body)["turn_index"] == 0
            response = await asyncio.to_thread(
                _short_body_response,
                lab.contexts["red"],
                "127.0.0.1",
                lab.server.server_address[1],
                path,
                request_body,
            )
            header, body = response.split(b"\r\n\r\n", 1)
            status_line = header.split(b"\r\n", 1)[0]
            status = int(status_line.split(b" ")[1])
            payload = json.loads(body)
            after = _durable_snapshot(env)
            assert status == 400
            assert len(body) == 4096
            assert payload["schema_version"] == "arena.execution.v1"
            assert payload["status"] == "ERROR"
            assert payload["code"] == "INVALID_SCHEMA"
            assert env.source.text.encode("utf-8") not in body
            assert after == before

            observation = {
                "scope": SCOPE,
                "transport": "LOCAL_HTTPS_MUTUAL_TLS",
                "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
                "fixture_state": list(before["experiment"]),
                "declared_content_length": len(request_body) + 1,
                "transmitted_body_bytes": len(request_body),
                "tls_eof": "ORDERLY_CLOSE_NOTIFY",
                "http_status": status,
                "envelope_status": payload["status"],
                "error_code": payload["code"],
                "response_bytes": len(body),
                "response_sha256": hashlib.sha256(body).hexdigest(),
                "durable_snapshot_sha256": hashlib.sha256(
                    repr(before).encode("utf-8")
                ).hexdigest(),
                "captured_snapshot_unchanged": after == before,
                "real_inference_performed": False,
                "full_n07_acceptance": False,
                "full_arena_acceptance": False,
                "guarantee_tier_achieved": None,
            }
            assert observation["captured_snapshot_unchanged"] is True
            print("N07B_MTLS_TRUNCATED_BODY " + json.dumps(observation, sort_keys=True))
        finally:
            await lab.close()

    asyncio.run(scenario())
