"""Durable SQLite recorder using the restricted arena.v2 canonical format."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import sqlite3
from typing import Dict, Iterator, List, Optional, Sequence
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..contracts.common import Context, Opaque, Uuid
from ..contracts.crypto import (
    event_digest,
    canonical_bytes,
    sign,
    turn_message,
    verify,
    witness_message,
    validate_chain,
    checkpoint_digest,
)
from ..contracts.evidence import (
    ArtifactRef,
    Event,
    EventProposal,
    SignedCheckpoint,
    SignedTurnReceipt,
    TurnReceipt,
)
from ..ports import DependencyUnavailable
from .canonical import to_canonical_bytes
from .checkpoint import build_and_sign_checkpoint
from arena.integration.types import (
    PostHocReceipt,
    SignedPostHocReceipt,
    post_hoc_message,
)


class DurableRecorder:
    """Durable transactional event recorder backed by SQLite with write-before-ACK semantics."""

    def __init__(self, db_path: Path, private_key: bytes, signer_key_id: str, *, anchor=None) -> None:
        self.db_path = db_path.resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.private_key = private_key
        self.signer_key_id = signer_key_id
        self.anchor = anchor
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS recorder_identity(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
            )
            expected = {
                "key_id": self.signer_key_id,
                "public_key": Ed25519PrivateKey.from_private_bytes(self.private_key)
                .public_key()
                .public_bytes_raw()
                .hex(),
            }
            actual = dict(conn.execute("SELECT key,value FROM recorder_identity"))
            if actual and actual != expected:
                raise DependencyUnavailable("RECORDER_AUTHORITY_STATE_MISMATCH")
            if not actual:
                conn.executemany(
                    "INSERT INTO recorder_identity VALUES(?,?)", expected.items()
                )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    domain_id TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(domain_id, experiment_id, epoch)
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    domain_id TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    operation_id TEXT NOT NULL,
                    canonical_json TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    previous_digest TEXT NOT NULL,
                    PRIMARY KEY(domain_id, experiment_id, epoch, sequence),
                    UNIQUE(domain_id, experiment_id, epoch, operation_id)
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    ciphertext_sha256 TEXT NOT NULL,
                    blob_path TEXT
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                    domain_id TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    PRIMARY KEY(domain_id, experiment_id, epoch)
                );
                """
            )
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS run_actors (
                    domain_id TEXT NOT NULL, experiment_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                    actor_id TEXT NOT NULL, PRIMARY KEY(domain_id,experiment_id,epoch));
                CREATE TABLE IF NOT EXISTS artifact_contexts (
                    artifact_id TEXT PRIMARY KEY, domain_id TEXT NOT NULL,
                    experiment_id TEXT NOT NULL, epoch INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS turn_authorizations (
                    domain_id TEXT NOT NULL, experiment_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                    turn_id TEXT NOT NULL, receipt_json TEXT NOT NULL, signature TEXT NOT NULL,
                    PRIMARY KEY(domain_id,experiment_id,epoch,turn_id));
                CREATE TABLE IF NOT EXISTS post_hoc_authorizations (
                    domain_id TEXT NOT NULL, experiment_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                    turn_id TEXT NOT NULL, receipt_json TEXT NOT NULL, signature TEXT NOT NULL,
                    PRIMARY KEY(domain_id,experiment_id,epoch,turn_id));
            """)

    def register_run(
        self,
        context: Context,
        public_manifest_digest: str,
        *,
        actor_id: str | None = None,
    ) -> None:
        """Register trusted run and manifest before appends begin."""
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                row = conn.execute(
                    "SELECT manifest_digest, status FROM runs WHERE domain_id=? AND experiment_id=? AND epoch=?;",
                    (str(context.domain_id), str(context.experiment_id), context.epoch),
                ).fetchone()
                if row:
                    if row[0] != public_manifest_digest:
                        raise DependencyUnavailable("RUN_MANIFEST_MISMATCH")
                else:
                    now_utc = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO runs (domain_id, experiment_id, epoch, manifest_digest, status, created_at) "
                        "VALUES (?, ?, ?, ?, 'OPEN', ?);",
                        (
                            str(context.domain_id),
                            str(context.experiment_id),
                            context.epoch,
                            public_manifest_digest,
                            now_utc,
                        ),
                    )
                if actor_id is not None:
                    old = conn.execute(
                        "SELECT actor_id FROM run_actors WHERE domain_id=? AND experiment_id=? AND epoch=?",
                        (context.domain_id, context.experiment_id, context.epoch),
                    ).fetchone()
                    if old and old[0] != actor_id:
                        raise DependencyUnavailable("RUN_ACTOR_CONFLICT")
                    if not old and row:
                        raise DependencyUnavailable(
                            "LEGACY_RUN_CANNOT_BECOME_INTEGRATED"
                        )
                    conn.execute(
                        "INSERT OR IGNORE INTO run_actors VALUES(?,?,?,?)",
                        (
                            context.domain_id,
                            context.experiment_id,
                            context.epoch,
                            actor_id,
                        ),
                    )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def register_artifact(
        self,
        artifact_id: Uuid,
        ciphertext_sha256: str,
        blob_path: Optional[str] = None,
        *,
        context: Context | None = None,
    ) -> None:
        """Check ciphertext bytes before registration; never replace an artifact identity."""
        if blob_path is None:
            raise DependencyUnavailable("ARTIFACT_BYTES_REQUIRED")
        path = Path(blob_path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
            raise DependencyUnavailable("ARTIFACT_FILE_INVALID")
        if hashlib.sha256(path.read_bytes()).hexdigest() != ciphertext_sha256:
            raise DependencyUnavailable("ARTIFACT_DIGEST_MISMATCH")
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                old = conn.execute(
                    "SELECT ciphertext_sha256,blob_path FROM artifacts WHERE artifact_id=?",
                    (artifact_id,),
                ).fetchone()
                value = (ciphertext_sha256, str(path.resolve()))
                if old and tuple(old) != value:
                    raise DependencyUnavailable("ARTIFACT_IDENTITY_CONFLICT")
                conn.execute(
                    "INSERT OR IGNORE INTO artifacts VALUES(?,?,?)",
                    (artifact_id, *value),
                )
                if context is not None:
                    binding = (context.domain_id, context.experiment_id, context.epoch)
                    old_binding = conn.execute(
                        "SELECT domain_id,experiment_id,epoch FROM artifact_contexts WHERE artifact_id=?",
                        (artifact_id,),
                    ).fetchone()
                    if old_binding and tuple(old_binding) != binding:
                        raise DependencyUnavailable("ARTIFACT_CONTEXT_CONFLICT")
                    conn.execute(
                        "INSERT OR IGNORE INTO artifact_contexts VALUES(?,?,?,?)",
                        (artifact_id, *binding),
                    )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def _verify_artifacts_exist(
        self, conn: sqlite3.Connection, refs: Sequence[ArtifactRef]
    ) -> None:
        for ref in refs:
            row = conn.execute(
                "SELECT ciphertext_sha256, blob_path FROM artifacts WHERE artifact_id=?;",
                (str(ref.artifact_id).lower(),),
            ).fetchone()
            if not row or row[0].lower() != str(ref.ciphertext_sha256).lower():
                raise DependencyUnavailable(
                    f"MISSING_ARTIFACT_CIPHERTEXT: {ref.artifact_id}"
                )
            path = Path(row[1]) if row[1] else None
            if (
                path is None
                or path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > 1_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest()
                != ref.ciphertext_sha256
            ):
                raise DependencyUnavailable("ARTIFACT_BYTES_LOST_OR_CHANGED")

    async def append(
        self, proposal: EventProposal, authenticated_actor: Opaque
    ) -> Event:
        return await self._append(
            proposal, authenticated_actor, str(uuid4()), integrated=False
        )

    async def append_once(
        self, proposal: EventProposal, authenticated_actor: Opaque, operation_id: Uuid
    ) -> Event:
        """Integration port: durable caller operation identity, scoped to the run."""
        return await self._append(
            proposal, authenticated_actor, operation_id, integrated=True
        )

    async def append_invalid_close_once(
        self, proposal: EventProposal, authenticated_actor: Opaque, operation_id: Uuid
    ) -> Event:
        """Persist only a quiescent INVALID terminal despite an unavailable anchor.

        This operation deliberately leaves the external anchor behind and may
        only write the explicit CLOSED/INVALID forensic terminal. It cannot be
        used for valid execution, ordinary export, release, or later appends.
        """
        if proposal.event_type != "CLOSED" or proposal.outcome_code != "INVALID":
            raise DependencyUnavailable("UNANCHORED_APPEND_REQUIRES_INVALID_CLOSE")
        return await self._append(
            proposal, authenticated_actor, operation_id, integrated=True,
            anchor_enabled=False,
        )

    async def _append(self, proposal, authenticated_actor, operation_id, *, integrated,
                      anchor_enabled=True):
        """Atomically persist event to hash chain with write-before-ACK semantics."""
        domain_id = str(proposal.domain_id)
        experiment_id = str(proposal.experiment_id)
        epoch = proposal.epoch

        # The shared port has no caller-supplied operation identity. Never guess one
        # from event fields: two legitimate events can share those values.

        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            event = None
            anchor_prepared = False
            try:
                # 1. Verify run exists
                run_row = conn.execute(
                    "SELECT manifest_digest, status FROM runs WHERE domain_id=? AND experiment_id=? AND epoch=?;",
                    (domain_id, experiment_id, epoch),
                ).fetchone()
                if not run_row:
                    raise DependencyUnavailable("UNREGISTERED_RUN_CONTEXT")
                manifest_digest, status = run_row
                actor = conn.execute(
                    "SELECT actor_id FROM run_actors WHERE domain_id=? AND experiment_id=? AND epoch=?",
                    (domain_id, experiment_id, epoch),
                ).fetchone()
                if integrated and (not actor or actor[0] != authenticated_actor):
                    raise DependencyUnavailable("RECORDER_CALLER_DENIED")
                if actor and not integrated:
                    raise DependencyUnavailable("INTEGRATED_RUN_REQUIRES_OPERATION_ID")
                previous_operation = conn.execute(
                    "SELECT canonical_json FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? AND operation_id=?",
                    (domain_id, experiment_id, epoch, operation_id),
                ).fetchone()
                if previous_operation:
                    original = Event.model_validate_json(previous_operation[0])
                    fields = proposal.model_dump()
                    if original.actor_id != authenticated_actor or any(
                        getattr(original, key) != value for key, value in fields.items()
                    ):
                        # Compare models instead of dumped artifact dictionaries.
                        reconstructed = EventProposal.model_validate(
                            {key: getattr(original, key) for key in fields}
                        )
                        if (
                            reconstructed != proposal
                            or original.actor_id != authenticated_actor
                        ):
                            raise DependencyUnavailable("EVENT_OPERATION_CONFLICT")
                    if self.anchor is not None and anchor_enabled:
                        self.anchor.commit(original)
                    conn.execute("COMMIT")
                    return original

                # 2. Deny appends if run is CLOSED.
                if status == "CLOSED":
                    raise DependencyUnavailable("APPEND_AFTER_CLOSE_DENIED")

                # 4. Verify all referenced artifacts exist durably
                self._verify_artifacts_exist(conn, proposal.artifact_ciphertext_refs)
                if integrated:
                    for ref in proposal.artifact_ciphertext_refs:
                        bound = conn.execute(
                            "SELECT domain_id,experiment_id,epoch FROM artifact_contexts WHERE artifact_id=?",
                            (ref.artifact_id,),
                        ).fetchone()
                        if not bound or tuple(bound) != (
                            domain_id,
                            experiment_id,
                            epoch,
                        ):
                            raise DependencyUnavailable("ARTIFACT_CONTEXT_MISMATCH")

                # 5. Fetch previous sequence and digest
                last_row = conn.execute(
                    "SELECT sequence, digest FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? "
                    "ORDER BY sequence DESC LIMIT 1;",
                    (domain_id, experiment_id, epoch),
                ).fetchone()

                if not last_row:
                    seq = 1
                    previous_digest = "0" * 64
                else:
                    previous_event = Event.model_validate_json(
                        conn.execute(
                            "SELECT canonical_json FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? AND sequence=?;",
                            (domain_id, experiment_id, epoch, last_row[0]),
                        ).fetchone()[0]
                    )
                    if previous_event.event_type == "CLOSED":
                        raise DependencyUnavailable(
                            "APPEND_AFTER_TERMINAL_EVENT_DENIED"
                        )
                    seq = last_row[0] + 1
                    previous_digest = last_row[1]

                # Format RFC3339 UTC time ending in Z
                utc_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                event = Event(
                    domain_id=proposal.domain_id,
                    experiment_id=proposal.experiment_id,
                    epoch=proposal.epoch,
                    session_id=proposal.session_id,
                    turn_id=proposal.turn_id,
                    turn_index=proposal.turn_index,
                    event_type=proposal.event_type,
                    outcome_code=proposal.outcome_code,
                    artifact_ciphertext_refs=proposal.artifact_ciphertext_refs,
                    duration_us=proposal.duration_us,
                    schema_version="arena.v2",
                    sequence=seq,
                    previous_digest=previous_digest,
                    actor_id=str(authenticated_actor),
                    public_manifest_digest=manifest_digest,
                    utc_time=utc_now,
                )

                digest = event_digest(event)
                canonical_str = to_canonical_bytes(event).decode("ascii")

                # The independent anchor reserves these exact canonical event
                # bytes before the protected recorder transaction can commit.
                if self.anchor is not None and anchor_enabled:
                    self.anchor.prepare(event)
                    anchor_prepared = True

                conn.execute(
                    "INSERT INTO events (domain_id, experiment_id, epoch, sequence, operation_id, canonical_json, digest, previous_digest) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                    (
                        domain_id,
                        experiment_id,
                        epoch,
                        seq,
                        operation_id,
                        canonical_str,
                        digest,
                        previous_digest,
                    ),
                )

                conn.execute("COMMIT;")
                if self.anchor is not None and anchor_enabled:
                    # A lost/failed ACK leaves the persisted event and PREPARED
                    # record intact. The next exact operation may commit that
                    # same position; a new event is refused until then.
                    self.anchor.commit(event)
                return event
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK;")
                if anchor_prepared and event is not None:
                    exists = conn.execute(
                        "SELECT 1 FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? AND operation_id=?",
                        (domain_id, experiment_id, epoch, operation_id),
                    ).fetchone()
                    if not exists:
                        # The durable recorder operation ledger proves this
                        # exact append did not commit; the anchor consumes an
                        # ABORTED sequence before another event may be prepared.
                        self.anchor.abort(event, "RECORDER_APPEND_NOT_COMMITTED")
                raise

    async def authorize_turn(self, receipt: TurnReceipt) -> SignedTurnReceipt:
        """Refuse to sign until commitment coverage and prefix binding are specified."""
        raise DependencyUnavailable("TURN_COMMITMENT_COVERAGE_UNRESOLVED")

    def authorize_start(self, receipt, authenticated_actor):
        """Authenticate a witness request only for this recorder's durable start prefix."""
        scope = (receipt.domain_id, receipt.experiment_id, receipt.epoch)
        with self._get_connection() as conn:
            run = conn.execute(
                "SELECT manifest_digest,status FROM runs WHERE domain_id=? AND experiment_id=? AND epoch=?",
                scope,
            ).fetchone()
            actor = conn.execute(
                "SELECT actor_id FROM run_actors WHERE domain_id=? AND experiment_id=? AND epoch=?",
                scope,
            ).fetchone()
            event = conn.execute(
                "SELECT canonical_json,digest FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY sequence DESC LIMIT 1",
                scope,
            ).fetchone()
            if (
                not run
                or run[1] != "OPEN"
                or run[0] != receipt.public_manifest_digest
                or not actor
                or actor[0] != authenticated_actor
                or not event
            ):
                raise DependencyUnavailable("RECORDER_START_AUTHORITY_DENIED")
            parsed = Event.model_validate_json(event[0])
            if (
                parsed.event_type != "START_RESERVED"
                or parsed.sequence != receipt.event_count
                or event[1] != receipt.prefix_root
            ):
                raise DependencyUnavailable("RECORDER_START_PREFIX_MISMATCH")
            return sign(witness_message(receipt), self.private_key)

    async def authorize_bound_turn(
        self,
        receipt: TurnReceipt,
        authenticated_actor: Opaque,
        input_ref: ArtifactRef,
        response_ref: ArtifactRef,
    ) -> SignedTurnReceipt:
        """Sign a durable FEEDBACK_AUTHORIZED prefix with exact required references.

        The trusted broker attests the specified commitment openings; encrypted
        openings and their coverage are independently checked during private replay.
        """
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                scope = (receipt.domain_id, receipt.experiment_id, receipt.epoch)
                actor = conn.execute(
                    "SELECT actor_id FROM run_actors WHERE domain_id=? AND experiment_id=? AND epoch=?",
                    scope,
                ).fetchone()
                if (
                    not actor
                    or actor[0] != authenticated_actor
                    or receipt.signer_key_id != self.signer_key_id
                ):
                    raise DependencyUnavailable("RECORDER_CALLER_DENIED")
                old = conn.execute(
                    "SELECT receipt_json,signature FROM turn_authorizations WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                    (*scope, receipt.turn_id),
                ).fetchone()
                if old:
                    if TurnReceipt.model_validate_json(old[0]) != receipt:
                        raise DependencyUnavailable("TURN_AUTHORIZATION_CONFLICT")
                    conn.execute("COMMIT")
                    return SignedTurnReceipt(receipt=receipt, signature=old[1])
                row = conn.execute(
                    "SELECT canonical_json,digest FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? AND sequence=?",
                    (*scope, receipt.event_count),
                ).fetchone()
                if not row or row[1] != receipt.prefix_root:
                    raise DependencyUnavailable("TURN_PREFIX_MISMATCH")
                event = Event.model_validate_json(row[0])
                if (
                    event.event_type != "FEEDBACK_AUTHORIZED"
                    or event.outcome_code != "OK"
                    or (event.session_id, event.turn_id, event.turn_index)
                    != (receipt.session_id, receipt.turn_id, receipt.turn_index)
                    or set(event.artifact_ciphertext_refs) != {input_ref, response_ref}
                ):
                    raise DependencyUnavailable("TURN_FEEDBACK_EVENT_MISMATCH")
                self._verify_artifacts_exist(conn, (input_ref, response_ref))
                signature = sign(turn_message(receipt), self.private_key)
                conn.execute(
                    "INSERT INTO turn_authorizations VALUES(?,?,?,?,?,?)",
                    (
                        *scope,
                        receipt.turn_id,
                        canonical_bytes(receipt).decode(),
                        signature,
                    ),
                )
                conn.execute("COMMIT")
                return SignedTurnReceipt(receipt=receipt, signature=signature)
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def get_turn_authorization(
        self, context: Context, turn_id: Uuid
    ) -> SignedTurnReceipt | None:
        """Read an existing authorization without creating or re-signing one."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT receipt_json,signature FROM turn_authorizations "
                "WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                (context.domain_id, context.experiment_id, context.epoch, turn_id),
            ).fetchone()
        if row is None:
            return None
        receipt = TurnReceipt.model_validate_json(row[0])
        return SignedTurnReceipt(receipt=receipt, signature=row[1])

    def copy_turn_authorization(self, signed, authenticated_actor, input_ref, response_ref):
        """Restore an existing exact signature; this path never invokes signing."""
        receipt = signed.receipt
        public = Ed25519PrivateKey.from_private_bytes(self.private_key).public_key().public_bytes_raw()
        if (receipt.signer_key_id != self.signer_key_id
                or not verify(turn_message(receipt), signed.signature, public)):
            raise DependencyUnavailable("TURN_AUTHORIZATION_COPY_SIGNATURE_INVALID")
        scope = (receipt.domain_id, receipt.experiment_id, receipt.epoch)
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                actor = conn.execute(
                    "SELECT actor_id FROM run_actors WHERE domain_id=? AND experiment_id=? AND epoch=?", scope,
                ).fetchone()
                if not actor or actor[0] != authenticated_actor:
                    raise DependencyUnavailable("RECORDER_CALLER_DENIED")
                row = conn.execute(
                    "SELECT canonical_json,digest FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? AND sequence=?",
                    (*scope, receipt.event_count),
                ).fetchone()
                event = Event.model_validate_json(row[0]) if row else None
                if (not event or row[1] != receipt.prefix_root
                        or event.event_type != "FEEDBACK_AUTHORIZED" or event.outcome_code != "OK"
                        or (event.session_id, event.turn_id, event.turn_index) != (
                            receipt.session_id, receipt.turn_id, receipt.turn_index)
                        or event.artifact_ciphertext_refs != (input_ref, response_ref)):
                    raise DependencyUnavailable("TURN_AUTHORIZATION_COPY_PREFIX_INVALID")
                self._verify_artifacts_exist(conn, (input_ref, response_ref))
                old = conn.execute(
                    "SELECT receipt_json,signature FROM turn_authorizations WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                    (*scope, receipt.turn_id),
                ).fetchone()
                canonical = canonical_bytes(receipt).decode()
                if old and (old[0] != canonical or old[1] != signed.signature):
                    raise DependencyUnavailable("TURN_AUTHORIZATION_COPY_CONFLICT")
                if not old:
                    conn.execute("INSERT INTO turn_authorizations VALUES(?,?,?,?,?,?)",
                                 (*scope, receipt.turn_id, canonical, signed.signature))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return signed

    async def close(self, context: Context) -> SignedCheckpoint:
        """Terminal close of experiment epoch; produces signed checkpoint."""
        domain_id = str(context.domain_id)
        experiment_id = str(context.experiment_id)
        epoch = context.epoch

        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                # Check for existing checkpoint (idempotent replay)
                cp_row = conn.execute(
                    "SELECT checkpoint_json, signature FROM checkpoints WHERE domain_id=? AND experiment_id=? AND epoch=?;",
                    (domain_id, experiment_id, epoch),
                ).fetchone()
                if cp_row:
                    conn.execute("COMMIT;")
                    return SignedCheckpoint(
                        checkpoint=json.loads(cp_row[0]),
                        signature=cp_row[1],
                    )

                run_row = conn.execute(
                    "SELECT manifest_digest FROM runs WHERE domain_id=? AND experiment_id=? AND epoch=?;",
                    (domain_id, experiment_id, epoch),
                ).fetchone()
                if not run_row:
                    raise DependencyUnavailable("UNREGISTERED_RUN_CONTEXT")
                manifest_digest = run_row[0]

                # The broker must persist the truthful terminal outcome before checkpointing.
                last_row = conn.execute(
                    "SELECT sequence, digest, canonical_json FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? "
                    "ORDER BY sequence DESC LIMIT 1;",
                    (domain_id, experiment_id, epoch),
                ).fetchone()

                if not last_row:
                    raise DependencyUnavailable("CLOSE_PENDING_MISSING_TERMINAL_EVENT")
                terminal = Event.model_validate_json(last_row[2])
                if terminal.event_type != "CLOSED":
                    raise DependencyUnavailable("CLOSE_PENDING_MISSING_TERMINAL_EVENT")
                prior_rows = conn.execute(
                    "SELECT canonical_json FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? "
                    "AND sequence < ? ORDER BY sequence ASC;",
                    (domain_id, experiment_id, epoch, terminal.sequence),
                ).fetchall()
                prior_events = [Event.model_validate_json(row[0]) for row in prior_rows]
                prior_invalid = any(
                    event.event_type == "INTEGRITY_VIOLATION"
                    or (
                        event.event_type == "MODEL_RESULT"
                        and event.outcome_code == "UNKNOWN"
                    )
                    for event in prior_events
                )
                if prior_invalid and terminal.outcome_code != "INVALID":
                    raise DependencyUnavailable("CLOSE_OUTCOME_WOULD_CLEAR_INVALIDITY")

                # Fetch all events to compute final_root and collect all artifacts
                rows = conn.execute(
                    "SELECT sequence, canonical_json, digest FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? "
                    "ORDER BY sequence ASC;",
                    (domain_id, experiment_id, epoch),
                ).fetchall()

                event_count = len(rows)
                final_root = rows[-1][2] if rows else "0" * 64

                all_artifacts: Dict[str, ArtifactRef] = {}
                for _, canonical_json, _ in rows:
                    ev = Event.model_validate_json(canonical_json)
                    for ref in ev.artifact_ciphertext_refs:
                        all_artifacts[str(ref.artifact_id)] = ref

                signed_checkpoint = build_and_sign_checkpoint(
                    context=context,
                    public_manifest_digest=manifest_digest,
                    event_count=event_count,
                    final_root=final_root,
                    artifacts=list(all_artifacts.values()),
                    signer_key_id=self.signer_key_id,
                    private_key=self.private_key,
                )
                validate_chain(
                    tuple(Event.model_validate_json(item[1]) for item in rows),
                    signed_checkpoint.checkpoint,
                )
                self._verify_artifacts_exist(
                    conn, signed_checkpoint.checkpoint.required_artifacts
                )

                cp_canonical = to_canonical_bytes(signed_checkpoint.checkpoint).decode(
                    "ascii"
                )
                conn.execute(
                    "INSERT INTO checkpoints (domain_id, experiment_id, epoch, checkpoint_json, signature) "
                    "VALUES (?, ?, ?, ?, ?);",
                    (
                        domain_id,
                        experiment_id,
                        epoch,
                        cp_canonical,
                        signed_checkpoint.signature,
                    ),
                )

                conn.execute(
                    "UPDATE runs SET status='CLOSED' WHERE domain_id=? AND experiment_id=? AND epoch=?;",
                    (domain_id, experiment_id, epoch),
                )

                conn.execute("COMMIT;")
                return signed_checkpoint
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def get_events(self, context: Context) -> List[Event]:
        """Retrieve all events for a run in chronological order."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT canonical_json FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY sequence ASC;",
                (str(context.domain_id), str(context.experiment_id), context.epoch),
            ).fetchall()
            return [Event.model_validate_json(row[0]) for row in rows]

    def get_event_bytes(self, context: Context) -> bytes:
        """Return the exact canonical event records retained by the recorder."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT canonical_json FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY sequence ASC;",
                (str(context.domain_id), str(context.experiment_id), context.epoch),
            ).fetchall()
            if not rows:
                return b""
            return ("\n".join(row[0] for row in rows) + "\n").encode("ascii")

    def authorize_analysis(
        self, receipt: PostHocReceipt, authenticated_actor: Opaque
    ) -> SignedPostHocReceipt:
        """Sign a separately linked post-release assertion, never reopen the event chain.

        The trusted broker attests its administrative release authorization. An
        offline reviewer supplies the expected release ID independently.
        """
        scope = (receipt.domain_id, receipt.experiment_id, receipt.epoch)
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                actor = conn.execute(
                    "SELECT actor_id FROM run_actors WHERE domain_id=? AND experiment_id=? AND epoch=?",
                    scope,
                ).fetchone()
                closed = conn.execute(
                    "SELECT checkpoint_json FROM checkpoints WHERE domain_id=? AND experiment_id=? AND epoch=?",
                    scope,
                ).fetchone()
                if (
                    not actor
                    or actor[0] != authenticated_actor
                    or not closed
                    or receipt.signer_key_id != self.signer_key_id
                ):
                    raise DependencyUnavailable("POST_HOC_RECORDER_AUTHORITY_DENIED")
                from arena.contracts.evidence import Checkpoint

                checkpoint = Checkpoint.model_validate_json(closed[0])
                if checkpoint_digest(checkpoint) != receipt.terminal_checkpoint_digest:
                    raise DependencyUnavailable("POST_HOC_CHECKPOINT_MISMATCH")
                if (
                    receipt.source_input not in checkpoint.required_artifacts
                    or receipt.source_output not in checkpoint.required_artifacts
                ):
                    raise DependencyUnavailable(
                        "POST_HOC_SOURCE_NOT_IN_CLOSED_EVIDENCE"
                    )
                events = [
                    Event.model_validate_json(item[0])
                    for item in conn.execute(
                        "SELECT canonical_json FROM events WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY sequence",
                        scope,
                    )
                ]
                invalid = (
                    any(
                        event.event_type == "INTEGRITY_VIOLATION"
                        or (
                            event.event_type == "MODEL_RESULT"
                            and event.outcome_code == "UNKNOWN"
                        )
                        for event in events
                    )
                    or events[-1].outcome_code == "INVALID"
                )
                if (receipt.aggregate_integrity == "INVALID") != invalid:
                    raise DependencyUnavailable(
                        "POST_HOC_CANNOT_REWRITE_PRIOR_INTEGRITY"
                    )
                refs = (
                    receipt.source_input,
                    receipt.source_output,
                    receipt.analysis_artifact,
                )
                self._verify_artifacts_exist(conn, refs)
                for ref in refs:
                    binding = conn.execute(
                        "SELECT domain_id,experiment_id,epoch FROM artifact_contexts WHERE artifact_id=?",
                        (ref.artifact_id,),
                    ).fetchone()
                    if not binding or tuple(binding) != scope:
                        raise DependencyUnavailable(
                            "POST_HOC_ARTIFACT_CONTEXT_MISMATCH"
                        )
                old = conn.execute(
                    "SELECT receipt_json,signature FROM post_hoc_authorizations WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                    (*scope, receipt.turn_id),
                ).fetchone()
                if old:
                    if PostHocReceipt.model_validate_json(old[0]) != receipt:
                        raise DependencyUnavailable("POST_HOC_AUTHORIZATION_CONFLICT")
                    conn.execute("COMMIT")
                    return SignedPostHocReceipt(receipt=receipt, signature=old[1])
                signature = sign(post_hoc_message(receipt), self.private_key)
                conn.execute(
                    "INSERT INTO post_hoc_authorizations VALUES(?,?,?,?,?,?)",
                    (
                        *scope,
                        receipt.turn_id,
                        canonical_bytes(receipt).decode(),
                        signature,
                    ),
                )
                conn.execute("COMMIT")
                return SignedPostHocReceipt(receipt=receipt, signature=signature)
            except BaseException:
                conn.execute("ROLLBACK")
                raise
