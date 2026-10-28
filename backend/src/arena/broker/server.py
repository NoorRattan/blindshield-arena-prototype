"""Bounded, one-request HTTPS transport for the local PoC control plane.

No proxy certificate headers, streaming, compressed bodies, keepalive or general web serving.
Not a substitute for sandbox/network deployment or an audited production HTTP server.
"""

import hashlib
import json
import re
import socket
import socketserver
import ssl
import threading
from uuid import uuid4

from pydantic import TypeAdapter

from arena.contracts.api import AttackBatch, CreateExperiment, EpochRequest, TurnSubmission
from arena.contracts.common import ClientKey, Uuid
from arena.contracts.jsonwire import ContractError, MAX_BODY_BYTES, load_wire
from .store import BrokerError


def tls_context(certificate, key, ca):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(key))
    context.load_verify_locations(cafile=str(ca))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, broker, context, *, participant_gateway=None):
        if participant_gateway is not None and (address[0] != "127.0.0.1" or participant_gateway.broker is not broker):
            raise ValueError("LOCAL_PARTICIPANT_LISTENER_REQUIRED")
        self.participant_gateway = participant_gateway
        self.broker, self.context = broker, context
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Never serialize exception values, certificates, headers or submitted payloads.
        self.broker.store.operator_alerts.record_safely("TRANSPORT_FAILURE")


def dispatch(broker, principal, method, path, headers, body):
    if "?" in path or "%" in path or "#" in path:
        raise BrokerError("NOT_FOUND", 404)
    if method == "POST":
        TypeAdapter(ClientKey).validate_python(headers.get("idempotency-key"))
    if path == "/v1/experiments" and method == "POST":
        return broker.create(principal, load_wire(CreateExperiment, body), headers["idempotency-key"])
    matched = re.fullmatch(r"/v1/experiments/([^/]+)/(status|feedback|attacks|seal|start|sessions|finish|close|release|bundle)(?:/([^/]+)/(turns|cancel))?", path)
    if not matched:
        raise BrokerError("NOT_FOUND", 404)
    identifier, action, session_id, subaction = matched.groups()
    try:
        TypeAdapter(Uuid).validate_python(identifier)
        if session_id:
            TypeAdapter(Uuid).validate_python(session_id)
    except ValueError:
        raise BrokerError("NOT_FOUND", 404) from None
    if session_id and action != "sessions":
        raise BrokerError("NOT_FOUND", 404)
    if method == "GET" and not session_id:
        if action in ("status", "feedback"):
            return broker.status(principal, identifier, action == "feedback")
        if action == "bundle":
            return broker.unavailable(principal, identifier, None, action)
    if method == "POST" and action not in ("status", "feedback", "bundle"):
        schema = TurnSubmission if subaction == "turns" else AttackBatch if action == "attacks" else EpochRequest
        request = load_wire(schema, body)
        key = headers["idempotency-key"]
        if subaction:
            return broker.unavailable(principal, identifier, request, subaction, session_id)
        implemented = {"attacks": broker.upload, "seal": broker.seal, "sessions": broker.session}
        if action in implemented:
            return implemented[action](principal, identifier, request, key)
        return broker.unavailable(principal, identifier, request, action)
    raise BrokerError("NOT_FOUND", 404)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            secured = self.server.context.wrap_socket(self.request, server_side=True)
        except (OSError, ssl.SSLError):
            self.server.broker.store.operator_alerts.record_safely("TLS_DENIED")
            return
        # A total request deadline bounds slow fragments, in addition to the TLS handshake limit.
        def expire():
            try:
                secured.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(5, expire)
        timer.daemon = True
        timer.start()
        with secured:
            stream = secured.makefile("rb")
            try:
                principal = self.server.broker.store.authenticate(hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest())
                method, path, headers, body = self.parse(stream)
                gateway = self.server.participant_gateway
                if gateway is None:
                    status, result = dispatch(self.server.broker, principal, method, path, headers, body)
                else:
                    status, result = gateway.dispatch(principal, method, path, headers, body)
            except BrokerError as error:
                status, result = error.status, {"code": error.code, "request_id": str(uuid4())}
            except (ContractError, ValueError, TypeError, UnicodeError):
                status, result = 400, {"code": "INVALID_SCHEMA", "request_id": str(uuid4())}
            except Exception:
                status, result = 503, {"code": "AUDIT_UNAVAILABLE", "request_id": str(uuid4())}
            finally:
                stream.close()
            diagnostic_code = result.get("code", "DENIED_PATH") if isinstance(result, dict) else "DENIED_PATH"
            if status >= 400 and isinstance(result, bytes):
                try:
                    diagnostic_code = json.loads(result).get("code", "DENIED_PATH")
                except (ValueError, TypeError, AttributeError):
                    pass
            if self.server.participant_gateway is not None and status >= 400 and not isinstance(result, bytes):
                status, result = self.server.participant_gateway.error(status, result["code"])
            try:
                encoded = result if isinstance(result, bytes) else json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode("ascii")
                content_type = "application/zip" if getattr(result, "content_type", None) == "application/zip" else "application/json"
                secured.sendall(f"HTTP/1.1 {status} Result\r\nContent-Type: {content_type}\r\nContent-Length: {len(encoded)}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n".encode("ascii") + encoded)
                if status >= 400:
                    # Header/auth rejection can precede the client's body write. Closing with
                    # unread TLS records races that write and can discard the error on Windows.
                    # Send the fixed error first, then bounded-discard late bytes (never parse
                    # or execute them). The original total deadline remains in force.
                    secured.settimeout(0.25)
                    remaining = MAX_BODY_BYTES + 16_384
                    while remaining:
                        chunk = secured.recv(min(4096, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
            except OSError:
                pass
            finally:
                timer.cancel()
                if status >= 400:
                    # After sending the role-safe response; no private journal
                    # fields/counters become a participant response surface.
                    self.server.broker.store.operator_alert(diagnostic_code, status)

    @staticmethod
    def parse(stream):
        line = stream.readline(4097)
        if len(line) > 4096 or not line.endswith(b"\r\n"):
            raise BrokerError("INVALID_SCHEMA", 400)
        try:
            method, path, version = line[:-2].decode("ascii").split(" ")
        except (ValueError, UnicodeError):
            raise BrokerError("INVALID_SCHEMA", 400) from None
        if method not in ("POST", "GET") or version != "HTTP/1.1" or not path.startswith("/"):
            raise BrokerError("INVALID_SCHEMA", 400)
        headers = {}
        total = 0
        for _ in range(33):
            line = stream.readline(4097)
            total += len(line)
            if total > 16_384 or len(line) > 4096 or not line.endswith(b"\r\n"):
                raise BrokerError("INVALID_SCHEMA", 400)
            if line == b"\r\n":
                break
            if len(headers) >= 32 or b":" not in line or line[:1] in (b" ", b"\t"):
                raise BrokerError("INVALID_SCHEMA", 400)
            name, value = line[:-2].split(b":", 1)
            if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise BrokerError("INVALID_SCHEMA", 400)
            name = name.decode("ascii").lower()
            if name in headers or any(c < 32 or c > 126 for c in value):
                raise BrokerError("INVALID_SCHEMA", 400)
            headers[name] = value.decode("ascii").strip(" ")
        else:
            raise BrokerError("INVALID_SCHEMA", 400)
        if not headers.get("host") or any(k in headers for k in ("transfer-encoding", "content-encoding", "expect", "upgrade")):
            raise BrokerError("INVALID_SCHEMA", 400)
        if any(k.startswith(("x-role", "x-principal", "x-client-cert", "x-forwarded")) for k in headers):
            raise BrokerError("INVALID_SCHEMA", 400)
        length = headers.get("content-length", "0" if method == "GET" else "")
        if not re.fullmatch(r"[0-9]{1,8}", length):
            raise BrokerError("INVALID_SCHEMA", 400)
        length = int(length)
        if length > MAX_BODY_BYTES:
            raise BrokerError("BODY_TOO_LARGE", 413)
        if method == "GET" and length or method == "POST" and headers.get("content-type") != "application/json":
            raise BrokerError("INVALID_SCHEMA", 400)
        body = stream.read(length)
        if len(body) != length:
            raise BrokerError("INVALID_SCHEMA", 400)
        return method, path, headers, body
