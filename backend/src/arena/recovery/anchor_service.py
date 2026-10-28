"""Authenticated loopback process for the independent recovery-anchor journal."""

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import socket
import socketserver
import ssl
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.contracts.common import Context
from .anchor import RECORDER_PRINCIPAL, RecoveryAnchor, RecoveryAnchorError


MAX_REQUEST_BYTES = 1_000_000


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, anchor, context):
        self.anchor, self.context = anchor, context
        super().__init__(address, _Handler)


class _Handler(socketserver.BaseRequestHandler):
    def _response(self, stream, value):
        stream.write(json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n")
        stream.flush()

    def handle(self):
        self.request.settimeout(3)
        try:
            secure = self.server.context.wrap_socket(self.request, server_side=True)
        except (OSError, ssl.SSLError):
            return
        with secure:
            stream = secure.makefile("rwb")
            try:
                cert = secure.getpeercert()
                uris = [value for kind, value in cert.get("subjectAltName", ()) if kind == "URI"]
                if uris != ["urn:arena:principal:" + RECORDER_PRINCIPAL]:
                    raise ValueError("RECORDER_IDENTITY_REQUIRED")
                raw = stream.readline(MAX_REQUEST_BYTES + 1)
                if len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
                    raise ValueError("REQUEST_TOO_LARGE")
                request = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
                response = self._dispatch(request)
                self._response(stream, {"ok": True, "value": response})
                if request.get("operation") == "shutdown":
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
            except Exception as exc:
                code = exc.args[0] if isinstance(exc, (ValueError, RecoveryAnchorError)) and exc.args else "ANCHOR_UNAVAILABLE"
                try:
                    self._response(stream, {"ok": False, "code": str(code)[:80]})
                except OSError:
                    pass

    def _dispatch(self, request):
        if not isinstance(request, dict) or "operation" not in request:
            raise ValueError("INVALID_REQUEST")
        op = request["operation"]
        allowed = {
            "health": {"operation"},
            "prepare": {"operation", "event"},
            "commit": {"operation", "event"},
            "abort": {"operation", "event", "reason_code"},
            "records": {"operation", "context"},
            "terminal_close": {"operation", "checkpoint", "witness", "integrity"},
            "shutdown": {"operation"},
        }.get(op)
        if allowed is None or set(request) != allowed:
            raise ValueError("INVALID_REQUEST_FIELDS")
        if op == "health":
            return {"status": "READY"}
        if op == "prepare":
            return self.server.anchor.prepare(request["event"])
        if op == "commit":
            return self.server.anchor.commit(request["event"])
        if op == "abort":
            return self.server.anchor.abort(request["event"], request["reason_code"])
        if op == "records":
            context = Context.model_validate(request["context"])
            return self.server.anchor.records(context)
        if op == "terminal_close":
            return self.server.anchor.terminal_close(
                request["checkpoint"], request["witness"], request["integrity"]
            )
        return {"status": "STOPPING"}


def serve(db_path: Path, key_path: Path, ca_path: Path, server_cert: Path, server_key: Path,
          port: int, authority_id: str, key_id: str, expected_public_key: bytes):
    raw = key_path.read_bytes()
    if b"-----BEGIN PRIVATE KEY-----" in raw:
        private = serialization.load_pem_private_key(raw, password=None)
    else:
        private = Ed25519PrivateKey.from_private_bytes(raw)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("ANCHOR_ED25519_KEY_REQUIRED")
    if private.public_key().public_bytes_raw() != expected_public_key:
        raise ValueError("ANCHOR_PINNED_KEY_MISMATCH")
    anchor = RecoveryAnchor(db_path, private, authority_id, key_id)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(server_cert), str(server_key))
    context.load_verify_locations(cafile=str(ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    with _Server(("127.0.0.1", port), anchor, context) as server:
        server.serve_forever(poll_interval=0.1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--ca", required=True, type=Path)
    parser.add_argument("--server-cert", required=True, type=Path)
    parser.add_argument("--server-key", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--authority-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--expected-public-key", required=True)
    args = parser.parse_args(argv)
    serve(args.db, args.private_key, args.ca, args.server_cert, args.server_key,
          args.port, args.authority_id, args.key_id, bytes.fromhex(args.expected_public_key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
