"""Private ciphertext custody with fresh keys, fsync-before-event and bounded export."""

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from arena.contracts.crypto import (
    canonical_bytes,
    encrypt_artifact,
    decrypt_artifact,
    sha256,
)
from arena.contracts.evidence import ArtifactAAD, ArtifactRef
from arena.ports import DependencyUnavailable


class ArtifactVault:
    def __init__(self, root: Path, context, wrapping_key: bytes):
        self.root, self.context, self.key = Path(root).resolve(), context, wrapping_key
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = self.root / "custody.sqlite3"
        with closing(self.connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY,aad TEXT NOT NULL,wrapped BLOB NOT NULL,digest TEXT NOT NULL)"
            )

    def connect(self):
        conn = sqlite3.connect(self.db, isolation_level=None, timeout=5)
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def put(self, value: dict, classification: str):
        plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(plaintext) > 750_000:
            raise DependencyUnavailable("PRIVATE_ARTIFACT_SIZE_EXCEEDED")
        identifier = str(uuid4())
        aad = ArtifactAAD(
            **self.context.model_dump(),
            schema_version="arena.v2",
            artifact_id=identifier,
            classification=classification,
        )
        key, blob = encrypt_artifact(plaintext, aad)
        nonce = os.urandom(12)
        wrapped = nonce + AESGCM(self.key).encrypt(nonce, key, canonical_bytes(aad))
        path = self.root / f"{identifier}.bin"
        with path.open("xb") as output:
            output.write(blob)
            output.flush()
            os.fsync(output.fileno())
        # SQLite commits key custody only after complete ciphertext bytes exist.
        with closing(self.connect()) as conn:
            conn.execute(
                "INSERT INTO artifacts VALUES(?,?,?,?)",
                (identifier, canonical_bytes(aad).decode(), wrapped, sha256(blob)),
            )
        return ArtifactRef(artifact_id=identifier, ciphertext_sha256=sha256(blob))

    def get(self, ref, *, expected_classification=None):
        with closing(self.connect()) as conn:
            row = conn.execute(
                "SELECT aad,wrapped,digest FROM artifacts WHERE id=?",
                (ref.artifact_id,),
            ).fetchone()
        if not row or row[2] != ref.ciphertext_sha256:
            raise DependencyUnavailable("ARTIFACT_CUSTODY_MISMATCH")
        aad = ArtifactAAD.model_validate_json(row[0])
        if (aad.domain_id, aad.experiment_id, aad.epoch) != (
            self.context.domain_id,
            self.context.experiment_id,
            self.context.epoch,
        ):
            raise DependencyUnavailable("ARTIFACT_CUSTODY_CONTEXT_MISMATCH")
        if expected_classification is not None and aad.classification != expected_classification:
            raise DependencyUnavailable("ARTIFACT_CUSTODY_CLASSIFICATION_MISMATCH")
        path = self.root / f"{ref.artifact_id}.bin"
        root = self.root.resolve()
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            raise DependencyUnavailable("ARTIFACT_BYTES_LOST_OR_CHANGED")
        if path.stat().st_size > 1_000_000:
            raise DependencyUnavailable("ARTIFACT_SIZE_EXCEEDED")
        blob = path.read_bytes()
        if sha256(blob) != ref.ciphertext_sha256:
            raise DependencyUnavailable("ARTIFACT_BYTES_CHANGED")
        wrapped = row[1]
        key = AESGCM(self.key).decrypt(wrapped[:12], wrapped[12:], canonical_bytes(aad))
        return json.loads(decrypt_artifact(blob, key, aad))

    def export_ciphertexts(self, refs):
        result = {}
        for ref in refs:
            self.get(ref)  # Verify custody, AAD, key, tag and digest before exporting.
            result[ref.artifact_id] = (
                self.root / f"{ref.artifact_id}.bin"
            ).read_bytes()
        return result

    def export_ciphertext_only(self, refs):
        """Return committed ciphertext without opening or decrypting participant data."""
        result = {}
        root = self.root.resolve()
        with closing(self.connect()) as conn:
            for ref in refs:
                row = conn.execute(
                    "SELECT aad,digest FROM artifacts WHERE id=?", (ref.artifact_id,)
                ).fetchone()
                if not row or row[1] != ref.ciphertext_sha256:
                    raise DependencyUnavailable("ARTIFACT_CUSTODY_MISMATCH")
                aad = ArtifactAAD.model_validate_json(row[0])
                if (aad.domain_id, aad.experiment_id, aad.epoch, aad.artifact_id) != (
                    self.context.domain_id, self.context.experiment_id,
                    self.context.epoch, ref.artifact_id,
                ):
                    raise DependencyUnavailable("ARTIFACT_CUSTODY_CONTEXT_MISMATCH")
                path = self.root / f"{ref.artifact_id}.bin"
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
                    raise DependencyUnavailable("ARTIFACT_BYTES_LOST_OR_CHANGED")
                blob = path.read_bytes()
                if len(blob) > 1_000_000 or sha256(blob) != ref.ciphertext_sha256:
                    raise DependencyUnavailable("ARTIFACT_BYTES_CHANGED")
                result[ref.artifact_id] = blob
        return result

    def private_replay_keys(self, refs):
        """Operator-only material; never included in a public bundle or stdout."""
        result = {}
        with closing(self.connect()) as conn:
            for ref in refs:
                aad_text, wrapped = conn.execute(
                    "SELECT aad,wrapped FROM artifacts WHERE id=?", (ref.artifact_id,)
                ).fetchone()
                aad = ArtifactAAD.model_validate_json(aad_text)
                key = AESGCM(self.key).decrypt(
                    wrapped[:12], wrapped[12:], canonical_bytes(aad)
                )
                result[ref.artifact_id] = {
                    "key": key.hex(),
                    "classification": aad.classification,
                }
        return result
