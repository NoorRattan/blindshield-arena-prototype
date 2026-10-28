"""Durable SQLite witness authority enforcing anti-rollback epoch reservations and close idempotency."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator

from ..contracts.common import Context
from ..contracts.crypto import (
    sign,
    witness_message,
    verify,
    verify_checkpoint,
    checkpoint_digest,
)
from ..contracts.evidence import (
    SignedWitnessClose,
    SignedWitnessStart,
    WitnessClose,
    WitnessStart,
    SignedCheckpoint,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ..ports import DependencyUnavailable
from ..recorder.canonical import to_canonical_bytes


class SQLiteWitnessAuthority:
    """Witness authority backed by a separate SQLite database.

    Guarantees strict monotonic epoch progression (anti-regression),
    first-start-wins reservations, and first-close-wins terminal consensus.
    """

    def __init__(
        self,
        db_path: Path,
        private_key: bytes,
        witness_key_id: str,
        *,
        initialize_if_missing: bool = False,
        recorder_public_key: bytes | None = None,
        recorder_key_id: str | None = None,
    ) -> None:
        self.db_path = db_path.resolve()
        if not self.db_path.exists() and not initialize_if_missing:
            raise DependencyUnavailable(
                "WITNESS_STATE_INITIALIZATION_REQUIRES_EXPLICIT_PROVISIONING"
            )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.private_key = private_key
        self.witness_key_id = witness_key_id
        self.recorder_public_key = recorder_public_key
        self.recorder_key_id = recorder_key_id
        if (recorder_public_key is None) != (recorder_key_id is None):
            raise ValueError("Both recorder trust inputs are required")
        if recorder_public_key is not None and (
            recorder_key_id == witness_key_id
            or recorder_public_key
            == Ed25519PrivateKey.from_private_bytes(private_key)
            .public_key()
            .public_bytes_raw()
        ):
            raise DependencyUnavailable("INDEPENDENT_AUTHORITY_KEYS_REQUIRED")
        self._new_authority = initialize_if_missing and not self.db_path.exists()
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
                "CREATE TABLE IF NOT EXISTS authority_metadata(identity TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            expected = {
                "witness_key_id": self.witness_key_id,
                "public_key": Ed25519PrivateKey.from_private_bytes(self.private_key)
                .public_key()
                .public_bytes_raw()
                .hex(),
                "recorder_key": self.recorder_public_key.hex()
                if self.recorder_public_key is not None
                else "COMPONENT_ONLY_UNAUTHENTICATED",
                "recorder_key_id": self.recorder_key_id
                or "COMPONENT_ONLY_UNAUTHENTICATED",
            }
            stored = dict(conn.execute("SELECT identity,value FROM authority_metadata"))
            if stored != expected:
                if stored or not self._new_authority:
                    raise DependencyUnavailable("WITNESS_AUTHORITY_STATE_MISMATCH")
                conn.executemany(
                    "INSERT INTO authority_metadata VALUES(?,?)", expected.items()
                )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS epoch_watermarks (
                    domain_id TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    highest_committed_epoch INTEGER NOT NULL,
                    current_active_epoch INTEGER,
                    PRIMARY KEY(domain_id, experiment_id)
                );
                """
            )
            conn.execute("""CREATE TABLE IF NOT EXISTS domain_reservations(
                domain_id TEXT PRIMARY KEY, highest_reserved INTEGER NOT NULL,
                experiment_id TEXT NOT NULL, epoch INTEGER NOT NULL)""")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS start_receipts (
                    domain_id TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    reservation_id TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    PRIMARY KEY(domain_id, experiment_id, epoch)
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS close_receipts (
                    domain_id TEXT NOT NULL,
                    experiment_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    checkpoint_digest TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    PRIMARY KEY(domain_id, experiment_id, epoch)
                );
                """
            )

    async def reserve_start(self, receipt: WitnessStart) -> SignedWitnessStart:
        if self.recorder_public_key is not None:
            raise DependencyUnavailable("AUTHENTICATED_RECORDER_START_REQUIRED")
        return await self._reserve_start(receipt)

    async def reserve_start_authenticated(
        self, receipt: WitnessStart, recorder_signature: str
    ) -> SignedWitnessStart:
        if self.recorder_public_key is None or not verify(
            witness_message(receipt), recorder_signature, self.recorder_public_key
        ):
            raise DependencyUnavailable("RECORDER_START_SIGNATURE_INVALID")
        return await self._reserve_start(receipt)

    async def _reserve_start(self, receipt):
        """Reserve starting an epoch, preventing regression and conflicting reservations."""
        if receipt.witness_key_id != self.witness_key_id:
            raise DependencyUnavailable("WITNESS_KEY_ID_MISMATCH")
        domain_id = str(receipt.domain_id)
        experiment_id = str(receipt.experiment_id)
        epoch = receipt.epoch

        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                domain_watermark = conn.execute(
                    "SELECT highest_reserved,experiment_id,epoch FROM domain_reservations WHERE domain_id=?",
                    (domain_id,),
                ).fetchone()
                if domain_watermark and (
                    epoch < domain_watermark[0]
                    or (
                        epoch == domain_watermark[0]
                        and (experiment_id, epoch) != tuple(domain_watermark[1:])
                    )
                ):
                    raise DependencyUnavailable("DOMAIN_EPOCH_REGRESSION_OR_CONFLICT")
                if domain_watermark and (experiment_id, epoch) != tuple(
                    domain_watermark[1:]
                ):
                    active = conn.execute(
                        "SELECT current_active_epoch FROM epoch_watermarks WHERE domain_id=? AND experiment_id=?",
                        (domain_id, domain_watermark[1]),
                    ).fetchone()
                    if active and active[0] is not None:
                        raise DependencyUnavailable("DOMAIN_ACTIVE_EPOCH_IN_FLIGHT")
                # 1. Check watermarks for regression or unclosed epochs
                wm_row = conn.execute(
                    "SELECT highest_committed_epoch, current_active_epoch FROM epoch_watermarks "
                    "WHERE domain_id=? AND experiment_id=?;",
                    (domain_id, experiment_id),
                ).fetchone()

                if wm_row:
                    highest_committed, current_active = wm_row
                    if epoch <= highest_committed:
                        raise DependencyUnavailable(
                            f"EPOCH_REGRESSION_REJECTED: requested {epoch} <= highest committed {highest_committed}"
                        )
                    if current_active is not None and current_active != epoch:
                        raise DependencyUnavailable(
                            f"ACTIVE_EPOCH_IN_FLIGHT: epoch {current_active} is still active"
                        )
                else:
                    highest_committed = 0

                # 2. Check for existing start receipt on this exact epoch (lost ACK retry)
                existing_start = conn.execute(
                    "SELECT receipt_json, signature FROM start_receipts WHERE domain_id=? AND experiment_id=? AND epoch=?;",
                    (domain_id, experiment_id, epoch),
                ).fetchone()

                if existing_start:
                    stored_receipt = WitnessStart.model_validate_json(existing_start[0])
                    # Check if identical (same reservation and parameters)
                    if stored_receipt == receipt:
                        conn.execute("COMMIT;")
                        return SignedWitnessStart(
                            receipt=stored_receipt, signature=existing_start[1]
                        )
                    raise DependencyUnavailable("CONFLICTING_START_RESERVATION")

                # 3. Sign the WitnessStart receipt
                msg = witness_message(receipt)
                sig = sign(msg, self.private_key)
                signed_start = SignedWitnessStart(receipt=receipt, signature=sig)

                # 4. Commit to database
                canonical_str = to_canonical_bytes(receipt).decode("ascii")
                conn.execute(
                    "INSERT INTO start_receipts (domain_id, experiment_id, epoch, reservation_id, manifest_digest, receipt_json, signature) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?);",
                    (
                        domain_id,
                        experiment_id,
                        epoch,
                        str(receipt.reservation_id),
                        receipt.public_manifest_digest,
                        canonical_str,
                        sig,
                    ),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO epoch_watermarks (domain_id, experiment_id, highest_committed_epoch, current_active_epoch) "
                    "VALUES (?, ?, ?, ?);",
                    (domain_id, experiment_id, highest_committed, epoch),
                )
                conn.execute(
                    "INSERT INTO domain_reservations VALUES(?,?,?,?) ON CONFLICT(domain_id) DO UPDATE SET highest_reserved=excluded.highest_reserved,experiment_id=excluded.experiment_id,epoch=excluded.epoch",
                    (domain_id, epoch, experiment_id, epoch),
                )

                conn.execute("COMMIT;")
                return signed_start
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    async def close(self, receipt: WitnessClose) -> SignedWitnessClose:
        if self.recorder_public_key is not None:
            raise DependencyUnavailable("SIGNED_RECORDER_CHECKPOINT_REQUIRED")
        return await self._close(receipt)

    async def close_checkpoint(self, signed: SignedCheckpoint) -> SignedWitnessClose:
        checkpoint = signed.checkpoint
        if self.recorder_public_key is None or not verify_checkpoint(
            signed,
            self.recorder_public_key,
            checkpoint,
            checkpoint.public_manifest_digest,
            self.recorder_key_id,
        ):
            raise DependencyUnavailable("RECORDER_CHECKPOINT_SIGNATURE_INVALID")
        return await self._close(
            WitnessClose(
                **Context.model_validate(
                    {key: getattr(checkpoint, key) for key in Context.model_fields}
                ).model_dump(),
                schema_version="arena.v2",
                receipt_type="CLOSE",
                public_manifest_digest=checkpoint.public_manifest_digest,
                checkpoint_digest=checkpoint_digest(checkpoint),
                event_count=checkpoint.event_count,
                final_root=checkpoint.final_root,
                witness_key_id=self.witness_key_id,
            )
        )

    def watermark(self, context: Context) -> tuple[int, int | None]:
        with self._get_connection() as conn:
            domain = conn.execute(
                "SELECT highest_reserved,experiment_id,epoch FROM domain_reservations WHERE domain_id=?",
                (context.domain_id,),
            ).fetchone()
            if domain and (context.experiment_id, context.epoch) != tuple(domain[1:]):
                raise DependencyUnavailable("STALE_DOMAIN_WATERMARK")
            row = conn.execute(
                "SELECT highest_committed_epoch,current_active_epoch FROM epoch_watermarks WHERE domain_id=? AND experiment_id=?",
                (context.domain_id, context.experiment_id),
            ).fetchone()
            return tuple(row) if row else (0, None)

    async def _close(self, receipt):
        """First close wins; identical retry returns original; conflicting close fails."""
        if receipt.witness_key_id != self.witness_key_id:
            raise DependencyUnavailable("WITNESS_KEY_ID_MISMATCH")
        domain_id = str(receipt.domain_id)
        experiment_id = str(receipt.experiment_id)
        epoch = receipt.epoch

        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                # 1. Check if already closed
                existing_close = conn.execute(
                    "SELECT receipt_json, signature FROM close_receipts WHERE domain_id=? AND experiment_id=? AND epoch=?;",
                    (domain_id, experiment_id, epoch),
                ).fetchone()

                if existing_close:
                    stored_receipt = WitnessClose.model_validate_json(existing_close[0])
                    # Check identical close retry
                    if stored_receipt == receipt:
                        conn.execute("COMMIT;")
                        return SignedWitnessClose(
                            receipt=stored_receipt, signature=existing_close[1]
                        )
                    raise DependencyUnavailable("CONFLICTING_CLOSE_RECEIPT")

                # 2. Verify epoch was actually reserved and active
                wm_row = conn.execute(
                    "SELECT highest_committed_epoch, current_active_epoch FROM epoch_watermarks "
                    "WHERE domain_id=? AND experiment_id=?;",
                    (domain_id, experiment_id),
                ).fetchone()

                if not wm_row or wm_row[1] != epoch:
                    raise DependencyUnavailable(
                        f"CLOSE_WITHOUT_ACTIVE_START: epoch {epoch} is not active"
                    )

                start_row = conn.execute(
                    "SELECT manifest_digest FROM start_receipts WHERE domain_id=? AND experiment_id=? AND epoch=?;",
                    (domain_id, experiment_id, epoch),
                ).fetchone()
                if not start_row or start_row[0] != receipt.public_manifest_digest:
                    raise DependencyUnavailable("CLOSE_MANIFEST_MISMATCH")

                highest_committed = max(wm_row[0], epoch)

                # 3. Sign WitnessClose
                msg = witness_message(receipt)
                sig = sign(msg, self.private_key)
                signed_close = SignedWitnessClose(receipt=receipt, signature=sig)

                # 4. Commit to database
                canonical_str = to_canonical_bytes(receipt).decode("ascii")
                conn.execute(
                    "INSERT INTO close_receipts (domain_id, experiment_id, epoch, checkpoint_digest, receipt_json, signature) "
                    "VALUES (?, ?, ?, ?, ?, ?);",
                    (
                        domain_id,
                        experiment_id,
                        epoch,
                        receipt.checkpoint_digest,
                        canonical_str,
                        sig,
                    ),
                )
                conn.execute(
                    "UPDATE epoch_watermarks SET highest_committed_epoch=?, current_active_epoch=NULL "
                    "WHERE domain_id=? AND experiment_id=?;",
                    (highest_committed, domain_id, experiment_id),
                )

                conn.execute("COMMIT;")
                return signed_close
            except Exception:
                conn.execute("ROLLBACK;")
                raise
