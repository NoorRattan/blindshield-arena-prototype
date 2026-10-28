"""Launch the durable anchor in a separate hidden local process."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.model_runtime import BACKEND
from .anchor import RecoveryAnchorError
from .client import RecoveryAnchorClient


class RecoveryAnchorProcess:
    def __init__(self, *, data_directory, private_key_path, public_key, authority_id, key_id,
                 ca, server_certificate, server_private_key, recorder_certificate,
                 recorder_private_key, port=0):
        if Path(data_directory).is_symlink() or Path(private_key_path).is_symlink():
            raise RecoveryAnchorError("ANCHOR_PATH_SYMLINK_REFUSED")
        self.data_directory = Path(data_directory).resolve()
        self.private_key_path = Path(private_key_path).resolve()
        self.public_key = public_key
        self.authority_id, self.key_id = authority_id, key_id
        self.ca, self.server_certificate, self.server_private_key = map(
            Path, (ca, server_certificate, server_private_key)
        )
        self.recorder_certificate, self.recorder_private_key = map(
            Path, (recorder_certificate, recorder_private_key)
        )
        self.port = port
        self.process = None
        self.client = None

    def _validate_paths(self):
        if self.data_directory.is_relative_to(BACKEND.parent) or self.private_key_path.is_relative_to(BACKEND.parent):
            raise RecoveryAnchorError("ANCHOR_STATE_AND_KEY_MUST_BE_OUTSIDE_REPOSITORY")
        for path in (self.data_directory, self.private_key_path, self.ca,
                     self.server_certificate, self.server_private_key,
                     self.recorder_certificate, self.recorder_private_key):
            if path.is_symlink():
                raise RecoveryAnchorError("ANCHOR_PATH_SYMLINK_REFUSED")
        if not self.private_key_path.is_file():
            raise RecoveryAnchorError("ANCHOR_PRIVATE_KEY_NOT_PROVISIONED")
        raw = self.private_key_path.read_bytes()
        if len(raw) > 4096:
            raise RecoveryAnchorError("ANCHOR_PRIVATE_KEY_INVALID")
        try:
            private = (serialization.load_pem_private_key(raw, password=None)
                       if b"-----BEGIN PRIVATE KEY-----" in raw
                       else Ed25519PrivateKey.from_private_bytes(raw))
        except Exception as exc:
            raise RecoveryAnchorError("ANCHOR_PRIVATE_KEY_INVALID") from exc
        if (not isinstance(private, Ed25519PrivateKey)
                or private.public_key().public_bytes_raw() != self.public_key):
            raise RecoveryAnchorError("ANCHOR_PINNED_KEY_MISMATCH")
        if any(not path.is_file() for path in (self.ca, self.server_certificate,
                                                self.server_private_key,
                                                self.recorder_certificate,
                                                self.recorder_private_key)):
            raise RecoveryAnchorError("ANCHOR_TLS_IDENTITY_MISSING")

    @staticmethod
    def _free_port():
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def start(self, *, require_existing=False):
        self._validate_paths()
        existed = self.data_directory.exists()
        database = self.data_directory / "anchor.sqlite3"
        marker = self.private_key_path.parent / "anchor-instance.json"
        expected_marker = {
            "schema_version": "arena.recovery-anchor-instance.v1",
            "authority_id": self.authority_id,
            "key_id": self.key_id,
            "database_name": "anchor.sqlite3",
        }
        if require_existing and (not marker.is_file() or not existed):
            raise RecoveryAnchorError("ANCHOR_LEDGER_MISSING_OR_UNSAFE")
        if marker.is_symlink():
            raise RecoveryAnchorError("ANCHOR_INSTANCE_MARKER_UNSAFE")
        if marker.exists():
            try:
                raw = marker.read_bytes()
                if json.loads(raw.decode("utf-8")) != expected_marker or raw != (
                    json.dumps(expected_marker, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("utf-8"):
                    raise ValueError
            except Exception as exc:
                raise RecoveryAnchorError("ANCHOR_INSTANCE_MARKER_INVALID") from exc
            if not existed or not database.is_file() or database.is_symlink():
                raise RecoveryAnchorError("ANCHOR_LEDGER_MISSING_OR_UNSAFE")
        elif existed:
            raise RecoveryAnchorError("ANCHOR_LEDGER_MISSING_OR_UNSAFE")
        else:
            marker.parent.mkdir(parents=True, exist_ok=True)
            payload = (json.dumps(expected_marker, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        self.data_directory.mkdir(parents=True, exist_ok=True)
        if self.port == 0:
            self.port = self._free_port()
        args = [
            sys.executable, "-m", "arena.recovery.anchor_service",
            "--db", str(self.data_directory / "anchor.sqlite3"),
            "--private-key", str(self.private_key_path),
            "--ca", str(self.ca),
            "--server-cert", str(self.server_certificate),
            "--server-key", str(self.server_private_key),
            "--port", str(self.port),
            "--authority-id", self.authority_id,
            "--key-id", self.key_id,
            "--expected-public-key", self.public_key.hex(),
        ]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.process = subprocess.Popen(
            args, cwd=BACKEND, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, creationflags=flags,
        )
        self.client = RecoveryAnchorClient(
            "127.0.0.1", self.port, self.ca, self.recorder_certificate,
            self.recorder_private_key, self.public_key, self.key_id, self.authority_id,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RecoveryAnchorError("ANCHOR_PROCESS_EXITED")
            try:
                self.client.health()
                return self.client
            except RecoveryAnchorError:
                time.sleep(0.05)
        self.stop()
        raise RecoveryAnchorError("ANCHOR_STARTUP_TIMEOUT")

    def stop(self):
        if self.client is not None and self.process is not None and self.process.poll() is None:
            try:
                self.client.shutdown()
            except RecoveryAnchorError:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=2)
        self.process = None
