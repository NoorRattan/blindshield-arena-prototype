"""Bounded mTLS client for the independent recovery-anchor process."""

from __future__ import annotations

import json
import socket
import ssl
from contextlib import closing

from arena.contracts.common import Context
from arena.contracts.evidence import Event

from .anchor import RecoveryAnchorError, operation_id, verify_anchor_records
from .anchor import verify_record
from arena.contracts.crypto import event_digest


MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class RecoveryAnchorClient:
    def __init__(self, host, port, ca, certificate, private_key, public_key, key_id, authority_id=None):
        if host != "127.0.0.1" or not (1 <= port <= 65535):
            raise ValueError("LOOPBACK_ANCHOR_REQUIRED")
        self.host, self.port = host, port
        self.public_key, self.key_id, self.authority_id = public_key, key_id, authority_id
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.check_hostname = True
        self.context.load_cert_chain(str(certificate), str(private_key))

    def _request(self, operation, **fields):
        raw = json.dumps({"operation": operation, **fields}, ensure_ascii=True,
                         sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        if len(raw) > 1_000_000:
            raise RecoveryAnchorError("ANCHOR_REQUEST_TOO_LARGE")
        try:
            with closing(socket.create_connection((self.host, self.port), timeout=3)) as plain:
                with self.context.wrap_socket(plain, server_hostname=self.host) as secure:
                    secure.settimeout(5)
                    secure.sendall(raw)
                    chunks = bytearray()
                    while len(chunks) <= MAX_RESPONSE_BYTES:
                        part = secure.recv(min(65536, MAX_RESPONSE_BYTES + 1 - len(chunks)))
                        if not part:
                            break
                        chunks.extend(part)
                        if b"\n" in chunks:
                            break
            if len(chunks) > MAX_RESPONSE_BYTES or b"\n" not in chunks:
                raise RecoveryAnchorError("ANCHOR_RESPONSE_INVALID")
            answer = json.loads(bytes(chunks).split(b"\n", 1)[0].decode("utf-8", errors="strict"))
            if not isinstance(answer, dict) or not isinstance(answer.get("ok"), bool):
                raise RecoveryAnchorError("ANCHOR_RESPONSE_INVALID")
            expected = {"ok", "value"} if answer["ok"] else {"ok", "code"}
            if set(answer) != expected:
                raise RecoveryAnchorError("ANCHOR_RESPONSE_INVALID")
            if not answer["ok"]:
                raise RecoveryAnchorError(str(answer["code"]))
            return answer["value"]
        except RecoveryAnchorError:
            raise
        except Exception as exc:
            raise RecoveryAnchorError("ANCHOR_UNAVAILABLE") from exc

    def health(self):
        result = self._request("health")
        if result != {"status": "READY"}:
            raise RecoveryAnchorError("ANCHOR_UNAVAILABLE")

    def prepare(self, event):
        record = self._request("prepare", event=event.model_dump(mode="json"))
        verify_record(record, self.public_key, self.key_id, self.authority_id)
        if record.get("transition") != "PREPARED" or record.get("event_digest") != event_digest(event):
            raise RecoveryAnchorError("ANCHOR_PREPARE_ACK_MISMATCH")
        return record

    def commit(self, event):
        record = self._request("commit", event=event.model_dump(mode="json"))
        verify_record(record, self.public_key, self.key_id, self.authority_id)
        if record.get("transition") != "COMMITTED" or record.get("event_digest") != event_digest(event):
            raise RecoveryAnchorError("ANCHOR_COMMIT_ACK_MISMATCH")
        return record

    def abort(self, event, reason_code):
        record = self._request("abort", event=event.model_dump(mode="json"), reason_code=reason_code)
        verify_record(record, self.public_key, self.key_id, self.authority_id)
        if record.get("transition") != "ABORTED" or record.get("event_digest") != event_digest(event):
            raise RecoveryAnchorError("ANCHOR_ABORT_ACK_MISMATCH")
        return record

    def records(self, context):
        records = self._request("records", context=context.model_dump(mode="json"))
        if not isinstance(records, list):
            raise RecoveryAnchorError("ANCHOR_RESPONSE_INVALID")
        verify_anchor_records(records, context, self.public_key, self.key_id, self.authority_id)
        return records

    def verify_events(self, context, events):
        records = self.records(context)
        state = verify_anchor_records(records, context, self.public_key, self.key_id, self.authority_id)
        event_list = list(events)
        if state["pending"]:
            raise RecoveryAnchorError("ANCHOR_PREPARE_UNRESOLVED")
        if state["event_sequence"] != len(event_list):
            raise RecoveryAnchorError("ANCHOR_EVENT_COUNT_MISMATCH")
        for event in event_list:
            digest = event_digest(event)
            op = operation_id(context, event.sequence, digest)
            committed = state["committed"].get(op)
            if not committed or committed["event_digest"] != digest or committed["event_sequence"] != event.sequence:
                raise RecoveryAnchorError("ANCHOR_EVENT_BINDING_MISMATCH")
        if event_list and (state["event_root"] != event_digest(event_list[-1])):
            raise RecoveryAnchorError("ANCHOR_FINAL_ROOT_MISMATCH")
        return state

    def terminal_close(self, checkpoint, witness, integrity):
        record = self._request("terminal_close", checkpoint=checkpoint.model_dump(mode="json"),
                               witness=witness.model_dump(mode="json"), integrity=integrity)
        verify_record(record, self.public_key, self.key_id, self.authority_id)
        if record.get("transition") != "TERMINAL_CLOSED":
            raise RecoveryAnchorError("ANCHOR_TERMINAL_ACK_MISMATCH")
        context = Context(domain_id=checkpoint.checkpoint.domain_id,
                          experiment_id=checkpoint.checkpoint.experiment_id,
                          epoch=checkpoint.checkpoint.epoch)
        state = verify_anchor_records(
            self.records(context), context, self.public_key, self.key_id, self.authority_id
        )
        if state["terminal"] != record:
            raise RecoveryAnchorError("ANCHOR_TERMINAL_REPLAY_MISMATCH")
        return record

    def verify_terminal(self, context, checkpoint, witness, integrity):
        state = verify_anchor_records(
            self.records(context), context, self.public_key, self.key_id, self.authority_id
        )
        terminal = state["terminal"]
        if not terminal:
            raise RecoveryAnchorError("ANCHOR_TERMINAL_MISSING")
        from .anchor import terminal_operation_id
        from arena.contracts.crypto import checkpoint_digest
        import hashlib
        witness_sha = hashlib.sha256(json.dumps(
            witness.model_dump(mode="json"), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
        expected_id = terminal_operation_id(
            context, checkpoint.checkpoint.event_count, checkpoint.checkpoint.final_root,
            checkpoint_digest(checkpoint.checkpoint), witness_sha, integrity,
        )
        if (terminal["operation_id"] != expected_id
                or terminal["checkpoint_digest"] != checkpoint_digest(checkpoint.checkpoint)
                or terminal["witness_close_digest"] != witness_sha
                or terminal["recorder_event_count"] != checkpoint.checkpoint.event_count
                or terminal["final_event_root"] != checkpoint.checkpoint.final_root
                or terminal["final_integrity"] != integrity):
            raise RecoveryAnchorError("ANCHOR_TERMINAL_MISMATCH")
        return terminal

    def shutdown(self):
        return self._request("shutdown")
