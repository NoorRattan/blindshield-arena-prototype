"""Real SQLite transactions and encrypted private payload storage, with no model calls."""

from contextlib import closing, contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from arena.contracts.api import AttemptResult
from arena.contracts.common import Principal
from arena.contracts.crypto import canonical_bytes, decrypt_artifact, encrypt_artifact
from arena.contracts.evidence import ArtifactAAD
from .alerts import OperatorAlerts, category, journal_path


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS principals(
 fingerprint TEXT PRIMARY KEY, subject_id TEXT NOT NULL UNIQUE, role TEXT NOT NULL,
 domain_id TEXT NOT NULL, expires_at TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN(0,1)));
CREATE TABLE IF NOT EXISTS epochs(domain_id TEXT PRIMARY KEY, value INTEGER NOT NULL CHECK(value>0));
CREATE TABLE IF NOT EXISTS experiments(
 id TEXT PRIMARY KEY, domain_id TEXT NOT NULL, epoch INTEGER NOT NULL,
 owner TEXT NOT NULL, phase TEXT NOT NULL, integrity TEXT NOT NULL DEFAULT 'PENDING',
 config_json TEXT NOT NULL, manifest_id TEXT, public_commitment TEXT,
 UNIQUE(domain_id,epoch));
CREATE TABLE IF NOT EXISTS memberships(
 experiment_id TEXT NOT NULL REFERENCES experiments(id), subject_id TEXT NOT NULL,
 role TEXT NOT NULL, PRIMARY KEY(experiment_id,subject_id));
CREATE TABLE IF NOT EXISTS idempotency(
 subject_id TEXT NOT NULL, domain_id TEXT NOT NULL, experiment_id TEXT NOT NULL,
 epoch INTEGER NOT NULL, action TEXT NOT NULL, client_key TEXT NOT NULL,
 request_digest TEXT NOT NULL, response_json TEXT NOT NULL, status INTEGER NOT NULL,
 PRIMARY KEY(subject_id,domain_id,experiment_id,epoch,action,client_key));
CREATE TABLE IF NOT EXISTS payloads(
 artifact_id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
 kind TEXT NOT NULL, aad_json TEXT NOT NULL, ciphertext BLOB NOT NULL, wrapped_key BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS batch_items(
 experiment_id TEXT NOT NULL REFERENCES experiments(id), item_id TEXT NOT NULL,
 artifact_id TEXT NOT NULL REFERENCES payloads(artifact_id), PRIMARY KEY(experiment_id,item_id));
CREATE TABLE IF NOT EXISTS sessions(
 id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
 owner TEXT NOT NULL, lane INTEGER NOT NULL, next_index INTEGER NOT NULL DEFAULT 0,
 quarantined INTEGER NOT NULL DEFAULT 0, UNIQUE(experiment_id,lane));
CREATE TABLE IF NOT EXISTS budgets(
 experiment_id TEXT NOT NULL REFERENCES experiments(id), subject_id TEXT NOT NULL,
 admitted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(experiment_id,subject_id));
CREATE TABLE IF NOT EXISTS turns(
 id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL REFERENCES experiments(id),
 session_id TEXT NOT NULL REFERENCES sessions(id), turn_index INTEGER NOT NULL,
 owner TEXT NOT NULL, state TEXT NOT NULL, artifact_id TEXT REFERENCES payloads(artifact_id),
 payload_ref TEXT, result_json TEXT, UNIQUE(session_id,turn_index));
CREATE UNIQUE INDEX IF NOT EXISTS one_unresolved_turn ON turns(session_id)
 WHERE state IN ('RESERVED','DISPATCHED','UNKNOWN');
"""


class BrokerError(ValueError):
    def __init__(self, code: str, status: int = 409):
        self.code, self.status = code, status
        super().__init__(code)


class Store:
    def __init__(self, path: Path, master_key: bytes):
        if len(master_key) != 32:
            raise ValueError("A separately provisioned 32-byte vault key is required")
        self.path = Path(path)
        self.master_key = master_key
        self.operator_alerts = OperatorAlerts(journal_path(self.path))

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)
            versions = connection.execute("SELECT version FROM schema_meta").fetchall()
            if not versions:
                connection.execute("INSERT INTO schema_meta VALUES(1)")
            elif len(versions) != 1 or versions[0][0] != 1:
                raise ValueError("Unsupported broker database version")
        self.operator_alerts.initialize()

    def operator_alert(self, code, status=400):
        return self.operator_alerts.record_safely(category(code, status))

    @contextmanager
    def transaction(self):
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            raise BrokerError("AUDIT_UNAVAILABLE", 503) from None
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def provision(self, fingerprint: str, principal: Principal):
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO principals VALUES(?,?,?,?,?,1)",
                (
                    fingerprint,
                    principal.subject_id,
                    principal.role,
                    principal.domain_id,
                    principal.expires_at,
                ),
            )

    def authenticate(self, fingerprint: str) -> Principal:
        with closing(self.connect()) as connection:
            row = connection.execute(
                "SELECT * FROM principals WHERE fingerprint=? AND enabled=1",
                (fingerprint,),
            ).fetchone()
        if not row or datetime.fromisoformat(
            row["expires_at"].replace("Z", "+00:00")
        ) <= datetime.now(timezone.utc):
            raise BrokerError("UNAUTHORIZED", 401)
        return Principal(
            subject_id=row["subject_id"],
            role=row["role"],
            domain_id=row["domain_id"],
            expires_at=row["expires_at"],
        )

    def revoke(self, subject_id: str):
        with self.transaction() as connection:
            connection.execute(
                "UPDATE principals SET enabled=0 WHERE subject_id=?", (subject_id,)
            )

    def put_payload(
        self, connection, experiment, kind: str, content: dict, artifact_id=None
    ):
        artifact_id = artifact_id or str(uuid4())
        aad = ArtifactAAD(
            domain_id=experiment["domain_id"],
            experiment_id=experiment["id"],
            epoch=experiment["epoch"],
            schema_version="arena.v2",
            artifact_id=artifact_id,
            classification="PRIVATE_MANIFEST"
            if kind == "manifest"
            else "PRIVATE_PAYLOAD",
        )
        data_key, ciphertext = encrypt_artifact(
            json.dumps(content, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            ),
            aad,
        )
        nonce = os.urandom(12)
        wrapped = nonce + AESGCM(self.master_key).encrypt(
            nonce, data_key, b"arena.v2/key-wrap\x00" + canonical_bytes(aad)
        )
        connection.execute(
            "INSERT INTO payloads VALUES(?,?,?,?,?,?)",
            (
                artifact_id,
                experiment["id"],
                kind,
                canonical_bytes(aad).decode("ascii"),
                ciphertext,
                wrapped,
            ),
        )
        return artifact_id

    def read_payload(self, artifact_id: str) -> dict:
        """Trusted private worker/storage path only; never exposed as a participant HTTP route."""
        with closing(self.connect()) as connection:
            row = connection.execute(
                "SELECT * FROM payloads WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
        if not row:
            raise BrokerError("NOT_FOUND", 404)
        aad = ArtifactAAD.model_validate(json.loads(row["aad_json"]))
        wrapped = row["wrapped_key"]
        key = AESGCM(self.master_key).decrypt(
            wrapped[:12], wrapped[12:], b"arena.v2/key-wrap\x00" + canonical_bytes(aad)
        )
        return json.loads(decrypt_artifact(row["ciphertext"], key, aad))

    def recover_ambiguous(self) -> int:
        """Never re-dispatch after restart. RESERVED work remains unexecuted and queued."""
        result = AttemptResult(
            defense_mode="INPUT",
            pipeline_disposition="INFRASTRUCTURE_FAILED",
            model_execution="UNKNOWN",
            scoring="NOT_EVALUATED",
            integrity="INVALID",
        )
        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT id,session_id,experiment_id FROM turns WHERE state='DISPATCHED'"
            ).fetchall()
            for row in rows:
                config = json.loads(
                    connection.execute(
                        "SELECT config_json FROM experiments WHERE id=?",
                        (row["experiment_id"],),
                    ).fetchone()[0]
                )
                mode = config["request"]["defense_mode"]
                actual = result.model_copy(update={"defense_mode": mode})
                if connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='n04_turns'"
                ).fetchone():
                    known = connection.execute(
                        "SELECT known_execution FROM n04_turns WHERE turn_id=?",
                        (row["id"],),
                    ).fetchone()
                    if known and known[0] == "EXECUTED":
                        actual = AttemptResult(
                            defense_mode=mode,
                            pipeline_disposition="INFRASTRUCTURE_FAILED",
                            model_execution="EXECUTED",
                            scoring="FAILED",
                            integrity="INVALID",
                        )
                connection.execute(
                    "UPDATE turns SET state='UNKNOWN',result_json=? WHERE id=?",
                    (actual.model_dump_json(), row["id"]),
                )
                connection.execute(
                    "UPDATE sessions SET quarantined=1 WHERE id=?", (row["session_id"],)
                )
                connection.execute(
                    "UPDATE experiments SET phase='INVALID',integrity='INVALID' WHERE id=?",
                    (row["experiment_id"],),
                )
            return len(rows)
