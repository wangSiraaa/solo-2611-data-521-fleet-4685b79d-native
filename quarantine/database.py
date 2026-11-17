"""SQLite persistence for uploads, scan attempts and imported rows.

All multi-step state changes run inside ``BEGIN IMMEDIATE`` transactions that
condition on the current row state.  In particular a scan result is only
finalized when the attempt is still ``running`` and its recorded
``scan_id``/``content_id``/``generation`` match the upload.  A cancelled or
superseded attempt can therefore never settle a newer attempt, and a late
record cannot reactivate a cancelled upload.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

# Upload states
RECEIVED = "received"
SCANNING = "scanning"
BLOCKED = "blocked"
ERROR = "error"
READY = "ready"
IMPORTED = "imported"

# Attempt states
ATTEMPT_RUNNING = "running"
ATTEMPT_ALLOW = "allow"
ATTEMPT_BLOCK = "block"
ATTEMPT_ERROR = "error"
ATTEMPT_ABORTED = "aborted"

UPLOAD_STATES = {RECEIVED, SCANNING, BLOCKED, ERROR, READY, IMPORTED}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS uploads (
    upload_id     TEXT PRIMARY KEY,
    content_id    TEXT NOT NULL,
    size          INTEGER NOT NULL,
    display_name  TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN
        ('received','scanning','blocked','error','ready','imported')),
    generation    INTEGER NOT NULL DEFAULT 0,
    error_reason  TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    imported_at   TEXT
);

CREATE TABLE IF NOT EXISTS scan_attempts (
    scan_id      TEXT PRIMARY KEY,
    upload_id    TEXT NOT NULL REFERENCES uploads(upload_id),
    content_id   TEXT NOT NULL,
    generation   INTEGER NOT NULL,
    state        TEXT NOT NULL CHECK (state IN
        ('running','allow','block','error','aborted')),
    verdict      TEXT,
    reason       TEXT,
    detail       TEXT,
    pid          INTEGER,
    stdout_bytes INTEGER,
    stderr_tail  TEXT,
    exit_code    INTEGER,
    created_at   TEXT NOT NULL,
    finished_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_attempts_upload ON scan_attempts(upload_id);

CREATE TABLE IF NOT EXISTS imported_rows (
    business_id TEXT NOT NULL PRIMARY KEY,
    upload_id   TEXT NOT NULL REFERENCES uploads(upload_id),
    value       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rows_upload ON imported_rows(upload_id);
"""


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.executescript(SCHEMA)

    @contextmanager
    def txn(self):
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    @contextmanager
    def read(self):
        # Reads also take the (re-entrant) lock; they are short and never wait
        # on a scanner subprocess, so status stays responsive.
        with self.lock:
            yield self.conn

    def close(self) -> None:
        with self.lock:
            self.conn.close()
