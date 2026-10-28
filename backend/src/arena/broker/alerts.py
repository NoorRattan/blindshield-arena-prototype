"""Private bounded diagnostic journal, separate from signed arena evidence."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import threading
import time


RETENTION = 256
CODES = frozenset({"DENIED_PATH", "STALE_STATE", "VERSION_MISMATCH",
                   "AUDIT_UNAVAILABLE", "TLS_DENIED", "TRANSPORT_FAILURE"})


def category(code, status):
    # Only fixed categories are persisted; never an exception, URL, identity or body.
    if not isinstance(code, str):
        code = "DENIED_PATH"
    if code in {"STALE_EPOCH", "STALE_STATE", "EPOCH_MISMATCH", "STALE_OPERATION"}:
        return "STALE_STATE"
    if code in {"POLICY_NOT_READY", "VERSION_MISMATCH", "MANIFEST_MISMATCH",
                "FROZEN_MANIFEST_MISMATCH", "ARTIFACT_VERSION_MISMATCH"}:
        return "VERSION_MISMATCH"
    if status >= 500 or code == "AUDIT_UNAVAILABLE":
        return "AUDIT_UNAVAILABLE"
    return "DENIED_PATH"


class OperatorAlerts:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self._lock = threading.Lock()
        self.unretained_in_process = 0

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        with closing(self._connect()) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS operator_alerts(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at_unix_ns INTEGER NOT NULL,
                    code TEXT NOT NULL CHECK(code IN
                    ('DENIED_PATH','STALE_STATE','VERSION_MISMATCH','AUDIT_UNAVAILABLE','TLS_DENIED','TRANSPORT_FAILURE')));
                CREATE TABLE IF NOT EXISTS operator_alert_meta(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1), dropped INTEGER NOT NULL);
                INSERT OR IGNORE INTO operator_alert_meta VALUES(1,0);
            """)

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=.25, isolation_level=None)
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def record(self, code):
        if code not in CODES:
            raise ValueError("FIXED_OPERATOR_ALERT_CODE_REQUIRED")
        with closing(self._connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("INSERT INTO operator_alerts(observed_at_unix_ns,code) VALUES(?,?)", (time.time_ns(), code))
                removed = conn.execute("DELETE FROM operator_alerts WHERE sequence NOT IN (SELECT sequence FROM operator_alerts ORDER BY sequence DESC LIMIT ?)", (RETENTION,)).rowcount
                conn.execute("UPDATE operator_alert_meta SET dropped=dropped+? WHERE singleton=1", (removed,))
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    def record_safely(self, code):
        try:
            self.record(code)
            return True
        except (OSError, sqlite3.Error, ValueError):
            # Do not replace the participant's denial, retry inference, or expose
            # diagnostics when the private sink is unavailable.
            with self._lock:
                self.unretained_in_process += 1
            return False

    def snapshot(self):
        with closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=.25)) as conn:
            conn.execute("BEGIN")
            dropped = conn.execute("SELECT dropped FROM operator_alert_meta WHERE singleton=1").fetchone()[0]
            rows = conn.execute("SELECT sequence,observed_at_unix_ns,code FROM operator_alerts ORDER BY sequence").fetchall()
        with self._lock:
            failed = self.unretained_in_process
        return {"scope": "PRIVATE_OPERATOR_DIAGNOSTICS_NOT_SIGNED_EVIDENCE", "retention": RETENTION,
                "dropped": dropped, "unretained_in_process": failed,
                "alerts": [dict(sequence=row[0], observed_at_unix_ns=row[1], code=row[2]) for row in rows]}


def journal_path(database):
    database = Path(database)
    return database.with_name(database.name + ".operator-alerts.sqlite3")
