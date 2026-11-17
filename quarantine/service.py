"""Quarantine admission coordinator.

Responsibilities:

* admit an upload by reading the caller's path exactly once into the managed
  object store, keyed by SHA-256 + length;
* own scan attempts (one fresh ``scan_id`` each) and the 2-worker process pool;
* advance upload state only from terminal results bound to the exact
  ``content_id`` + ``generation`` of the attempt;
* import a whole validated CSV atomically, never leaving prefix rows;
* reject business-id collisions from a different upload as CONFLICT;
* cancel and reap in-flight scanners without letting a late ALLOW reactivate.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import database as db
from .csv_validation import parse_csv
from .database import Database
from .errors import (
    CsvValidationError,
    ObjectIntegrityError,
    QuarantineError,
    UploadConflict,
    UploadNotFound,
    UploadTooLarge,
)
from .object_store import ObjectStore
from .scanner import ScanAdapter, ScanResult

DEFAULT_MAX_BYTES = 1024 * 1024
MAX_SCAN_PROCESSES = 2


class InvalidState(QuarantineError):
    def __init__(self, upload_id: str, state: str, action: str):
        super().__init__(f"cannot {action} upload {upload_id!r} in state {state!r}")
        self.upload_id = upload_id
        self.state = state


@dataclass
class Job:
    scan_id: str
    upload_id: str
    generation: int
    content_id: str
    cancel: threading.Event = field(default_factory=threading.Event)
    future: Future | None = None
    _proc: Any = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def set_proc(self, proc) -> None:
        with self._lock:
            self._proc = proc
            if self.cancel.is_set():
                # Cancel arrived before registration; do not let the child run.
                try:
                    proc.kill()
                except OSError:
                    pass

    def proc(self):
        with self._lock:
            return self._proc


class QuarantineService:
    def __init__(
        self,
        root: Path,
        fixture: Path,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        scan_timeout: float = 10.0,
        recover: bool = True,
    ):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.store = ObjectStore(self.root)
        self.db = Database(self.root / "quarantine.sqlite3")
        self.adapter = ScanAdapter(fixture, timeout=scan_timeout)
        self.max_bytes = max_bytes
        self._jobs: dict[str, Job] = {}
        self._jobs_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(
            max_workers=MAX_SCAN_PROCESSES, thread_name_prefix="scan"
        )
        self._closed = False
        self._closing = False
        if recover:
            self.recover_orphans()

    # ------------------------------------------------------------------
    # lifecycle / recovery
    # ------------------------------------------------------------------
    def recover_orphans(self) -> list[str]:
        """Treat attempts left ``running`` by a previous process as pending.

        Their outcome is unknown (neither ALLOW nor a confirmed failure), so
        the upload returns to ``received`` for explicit rescheduling.  A
        previously *started* scan is never treated as a pass.
        """
        recovered: list[str] = []
        with self.db.txn() as conn:
            rows = conn.execute(
                "SELECT scan_id, upload_id, generation FROM scan_attempts "
                "WHERE state = 'running'"
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE scan_attempts SET state='aborted', reason='orphaned', "
                    "detail='process exited before scan settled', finished_at=? "
                    "WHERE scan_id=? AND state='running'",
                    (db._now(), row["scan_id"]),
                )
                cur = conn.execute(
                    "UPDATE uploads SET state='received', error_reason=NULL, "
                    "updated_at=? WHERE upload_id=? AND state='scanning' "
                    "AND generation=?",
                    (db._now(), row["upload_id"], row["generation"]),
                )
                if cur.rowcount:
                    recovered.append(row["upload_id"])
        return recovered

    def close(self, *, wait: bool = True, timeout: float = 5.0) -> None:
        """Stop scans; in-flight attempts become *pending*, not failed.

        The distinction matters on restart: a scan that was merely interrupted
        must be rescheduled, not treated as a pass or as a security failure.
        Safe to call more than once.
        """
        if self._closed:
            return
        self._closing = True
        self._closed = True
        with self._jobs_lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            # Set the flag; the adapter loop observes it within one poll
            # interval and kills the whole child process group itself.
            job.cancel.set()
        if wait:
            for job in jobs:
                if job.future is not None:
                    try:
                        job.future.result(timeout=timeout)
                    except Exception:
                        pass
        self._pool.shutdown(wait=wait, cancel_futures=True)
        self.recover_orphans()
        self.db.close()

    # ------------------------------------------------------------------
    # submit / status
    # ------------------------------------------------------------------
    def submit(self, upload_id: str, source_path: Path, display_name: str) -> dict:
        """Admit bytes once; retries of the same upload_id are idempotent."""
        if not upload_id:
            raise CsvValidationError("EMPTY_UPLOAD_ID", "upload_id is required")
        source_path = Path(source_path)

        # Hold the store lock across admission + reference commit so an
        # explicit GC cannot delete the object before it is referenced.
        with self.store.lock:
            content_id, size, created = self.store.admit_from_path(
                source_path, self.max_bytes
            )
            now = db._now()
            with self.db.txn() as conn:
                existing = conn.execute(
                    "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
                ).fetchone()
                if existing is not None:
                    if existing["content_id"] != content_id:
                        raise UploadConflict(
                            upload_id, existing["content_id"], content_id
                        )
                    return self._status_row(conn, existing)
                conn.execute(
                    "INSERT INTO uploads(upload_id, content_id, size, display_name,"
                    " state, generation, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,0,?,?)",
                    (upload_id, content_id, size, display_name, db.RECEIVED, now, now),
                )
                row = conn.execute(
                    "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
                ).fetchone()
                return self._status_row(conn, row)

    def status(self, upload_id: str) -> dict:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
            ).fetchone()
            if row is None:
                raise UploadNotFound(upload_id)
            return self._status_row(conn, row)

    def _status_row(self, conn, row) -> dict:
        attempts = conn.execute(
            "SELECT scan_id, content_id, generation, state, verdict, reason,"
            " detail, exit_code, pid, stdout_bytes,"
            " length(stderr_tail) AS stderr_bytes, created_at, finished_at"
            " FROM scan_attempts WHERE upload_id=? ORDER BY created_at, rowid",
            (row["upload_id"],),
        ).fetchall()
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM imported_rows WHERE upload_id=?",
            (row["upload_id"],),
        ).fetchone()["n"]
        return {
            "upload_id": row["upload_id"],
            "content_id": row["content_id"],
            "size": row["size"],
            "display_name": row["display_name"],
            "state": row["state"],
            "generation": row["generation"],
            "error_reason": row["error_reason"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "imported_at": row["imported_at"],
            "imported_row_count": count,
            "attempts": [dict(a) for a in attempts],
        }

    # ------------------------------------------------------------------
    # scan
    # ------------------------------------------------------------------
    def scan(
        self,
        upload_id: str,
        *,
        mode: str = "normal",
        wait: bool = True,
        wait_timeout: float | None = None,
    ) -> dict:
        """Start a fresh attempt (new scan_id) and optionally await it."""
        with self.db.txn() as conn:
            row = conn.execute(
                "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
            ).fetchone()
            if row is None:
                raise UploadNotFound(upload_id)
            if row["state"] == db.IMPORTED:
                raise InvalidState(upload_id, row["state"], "scan")
            if row["state"] == db.SCANNING:
                # Idempotent: return the attempt already in flight.
                return self._status_row(conn, row)
            generation = row["generation"] + 1
            scan_id = uuid.uuid4().hex
            conn.execute(
                "UPDATE uploads SET state=?, generation=?, error_reason=NULL,"
                " updated_at=? WHERE upload_id=?",
                (db.SCANNING, generation, db._now(), upload_id),
            )
            conn.execute(
                "INSERT INTO scan_attempts(scan_id, upload_id, content_id,"
                " generation, state, created_at) VALUES (?,?,?,?,?,?)",
                (scan_id, upload_id, row["content_id"], generation,
                 db.ATTEMPT_RUNNING, db._now()),
            )
        job = Job(scan_id, upload_id, generation, row["content_id"])
        with self._jobs_lock:
            self._jobs[scan_id] = job
        job.future = self._pool.submit(
            self._execute_attempt, job, row["content_id"], row["size"], mode
        )
        if wait:
            try:
                job.future.result(timeout=wait_timeout)
            except TimeoutError:
                pass
        return self.status(upload_id)

    def wait_scan(self, scan_id: str, timeout: float | None = None) -> bool:
        with self._jobs_lock:
            job = self._jobs.get(scan_id)
        if job is None or job.future is None:
            return True
        try:
            job.future.result(timeout=timeout)
            return True
        except TimeoutError:
            return False

    def _execute_attempt(
        self, job: Job, content_id: str, size: int, mode: str
    ) -> None:
        # Skip if cancel landed before the worker picked the job up.
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT state, generation, content_id FROM uploads"
                " WHERE upload_id=?",
                (job.upload_id,),
            ).fetchone()
            attempt = conn.execute(
                "SELECT state FROM scan_attempts WHERE scan_id=?", (job.scan_id,)
            ).fetchone()
        if (
            row is None
            or attempt is None
            or attempt["state"] != db.ATTEMPT_RUNNING
            or row["state"] != db.SCANNING
            or row["generation"] != job.generation
            or row["content_id"] != content_id
            or job.cancel.is_set()
        ):
            self._abandon(job, "not_scheduled")
            return

        try:
            object_path = self.store.path_for(content_id)
            result = self.adapter.run(
                scan_id=job.scan_id,
                content_id=content_id,
                size=size,
                object_path=object_path,
                mode=mode,
                proc_register=job.set_proc,
                cancel_event=job.cancel,
            )
        except Exception as exc:  # defensive: never leave a running attempt
            result = ScanResult(
                scan_id=job.scan_id,
                content_id=content_id,
                size=size,
                state="error",
                verdict=None,
                reason="adapter_exception",
                detail=repr(exc),
            )
        self._finalize(job, result)

    def _finalize(self, job: Job, result: ScanResult) -> None:
        try:
            self._finalize_locked(job, result)
        finally:
            with self._jobs_lock:
                self._jobs.pop(job.scan_id, None)

    def _finalize_locked(self, job: Job, result: ScanResult) -> None:
        with self.db.txn() as conn:
            attempt = conn.execute(
                "SELECT * FROM scan_attempts WHERE scan_id=?", (job.scan_id,)
            ).fetchone()
            upload = conn.execute(
                "SELECT * FROM uploads WHERE upload_id=?", (job.upload_id,)
            ).fetchone()
            # Ownership check: this result may only settle *this* attempt, and
            # only if that attempt is still the current running one.
            if (
                attempt is None
                or attempt["state"] != db.ATTEMPT_RUNNING
                or upload is None
                or upload["state"] != db.SCANNING
                or upload["generation"] != job.generation
                or upload["content_id"] != job.content_id
            ):
                conn.execute(
                    "UPDATE scan_attempts SET state='aborted',"
                    " detail=COALESCE(detail, 'superseded or cancelled before finalize'),"
                    " finished_at=COALESCE(finished_at, ?)"
                    " WHERE scan_id=? AND state='running'",
                    (db._now(), job.scan_id),
                )
                return
            if result.cancelled and self._closing:
                # Service shutdown, not a security outcome: return to pending.
                conn.execute(
                    "UPDATE scan_attempts SET state='aborted',"
                    " reason='service_shutdown', detail='interrupted by shutdown',"
                    " finished_at=? WHERE scan_id=? AND state='running'",
                    (db._now(), job.scan_id),
                )
                conn.execute(
                    "UPDATE uploads SET state=?, error_reason=NULL, updated_at=?"
                    " WHERE upload_id=? AND state=? AND generation=?",
                    (db.RECEIVED, db._now(), job.upload_id,
                     db.SCANNING, job.generation),
                )
                return
            if result.content_id != job.content_id or result.scan_id != job.scan_id:
                # The adapter already enforces this; keep a last line of defence.
                attempt_state, reason = db.ATTEMPT_ERROR, "result_owner_mismatch"
            elif result.state == "allow":
                attempt_state, reason = db.ATTEMPT_ALLOW, result.reason
            elif result.state == "block":
                attempt_state, reason = db.ATTEMPT_BLOCK, result.reason
            else:
                attempt_state, reason = db.ATTEMPT_ERROR, result.reason

            conn.execute(
                "UPDATE scan_attempts SET state=?, verdict=?, reason=?,"
                " detail=?, pid=?, stdout_bytes=?, stderr_tail=?, exit_code=?,"
                " finished_at=? WHERE scan_id=?",
                (
                    attempt_state,
                    result.verdict,
                    reason,
                    result.detail or None,
                    result.pid,
                    result.stdout_bytes,
                    result.stderr_tail,
                    result.exit_code,
                    db._now(),
                    job.scan_id,
                ),
            )
            if attempt_state == db.ATTEMPT_ALLOW:
                new_state = db.READY
            elif attempt_state == db.ATTEMPT_BLOCK:
                new_state = db.BLOCKED
            else:
                new_state = db.ERROR
            conn.execute(
                "UPDATE uploads SET state=?, error_reason=?, updated_at=?"
                " WHERE upload_id=? AND state=? AND generation=?",
                (
                    new_state,
                    None if attempt_state == db.ATTEMPT_ALLOW else reason,
                    db._now(),
                    job.upload_id,
                    db.SCANNING,
                    job.generation,
                ),
            )

    def _abandon(self, job: Job, detail: str) -> None:
        with self.db.txn() as conn:
            conn.execute(
                "UPDATE scan_attempts SET state='aborted', detail=?, finished_at=?"
                " WHERE scan_id=? AND state='running'",
                (detail, db._now(), job.scan_id),
            )
            row = conn.execute(
                "SELECT state FROM uploads WHERE upload_id=?", (job.upload_id,)
            ).fetchone()
            if row is not None and row["state"] == db.SCANNING:
                conn.execute(
                    "UPDATE uploads SET state=?, error_reason=?, updated_at=?"
                    " WHERE upload_id=? AND state=? AND generation=?",
                    (db.RECEIVED, None, db._now(), job.upload_id,
                     db.SCANNING, job.generation),
                )
        with self._jobs_lock:
            self._jobs.pop(job.scan_id, None)

    # ------------------------------------------------------------------
    # cancel
    # ------------------------------------------------------------------
    def cancel(self, upload_id: str, *, timeout: float = 5.0) -> dict:
        """Cancel a scanning upload and reap its child process.

        The state transition to ``error/cancelled`` is committed *before* the
        child is signalled, so a late ALLOW record can never finalize this
        attempt.  Imported uploads are refused: committed rows are not deleted.
        """
        with self.db.txn() as conn:
            row = conn.execute(
                "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
            ).fetchone()
            if row is None:
                raise UploadNotFound(upload_id)
            if row["state"] == db.IMPORTED:
                raise InvalidState(upload_id, row["state"], "cancel")
            if row["state"] != db.SCANNING:
                raise InvalidState(upload_id, row["state"], "cancel")
            generation = row["generation"]
            now = db._now()
            conn.execute(
                "UPDATE uploads SET state=?, error_reason='cancelled', updated_at=?"
                " WHERE upload_id=? AND state=? AND generation=?",
                (db.ERROR, now, upload_id, db.SCANNING, generation),
            )
            attempts = conn.execute(
                "SELECT scan_id FROM scan_attempts WHERE upload_id=?"
                " AND generation=? AND state='running'",
                (upload_id, generation),
            ).fetchall()
            for attempt in attempts:
                conn.execute(
                    "UPDATE scan_attempts SET state='aborted', reason='cancelled',"
                    " finished_at=? WHERE scan_id=? AND state='running'",
                    (now, attempt["scan_id"]),
                )
        jobs = []
        with self._jobs_lock:
            for scan_id in {a["scan_id"] for a in attempts}:
                job = self._jobs.get(scan_id)
                if job is not None:
                    jobs.append(job)
        for job in jobs:
            job.cancel.set()
        for job in jobs:
            if job.future is not None:
                try:
                    job.future.result(timeout=timeout)
                except Exception:
                    pass
        return self.status(upload_id)

    # ------------------------------------------------------------------
    # import
    # ------------------------------------------------------------------
    def import_upload(self, upload_id: str) -> dict:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
            ).fetchone()
        if row is None:
            raise UploadNotFound(upload_id)
        if row["state"] == db.IMPORTED:
            return self.status(upload_id)  # idempotent, no second write
        if row["state"] != db.READY:
            raise InvalidState(upload_id, row["state"], "import")

        content_id = row["content_id"]
        generation = row["generation"]
        try:
            data = self.store.read_bytes(content_id, row["size"])
        except (ObjectIntegrityError, OSError) as exc:
            return self._fail_import(upload_id, generation, "INTEGRITY", str(exc))
        try:
            rows = parse_csv(data)
        except CsvValidationError as exc:
            return self._fail_import(
                upload_id, generation, exc.code, exc.detail or str(exc)
            )

        ids = [r.id for r in rows]
        try:
            with self.db.txn() as conn:
                current = conn.execute(
                    "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
                ).fetchone()
                if current is None:
                    raise UploadNotFound(upload_id)
                if current["state"] == db.IMPORTED:
                    return self._status_row(conn, current)
                if (
                    current["state"] != db.READY
                    or current["generation"] != generation
                    or current["content_id"] != content_id
                ):
                    raise InvalidState(upload_id, current["state"], "import")

                conflicts = []
                for start in range(0, len(ids), 500):
                    batch = ids[start:start + 500]
                    placeholders = ",".join("?" * len(batch))
                    conflicts.extend(
                        r["business_id"]
                        for r in conn.execute(
                            f"SELECT business_id FROM imported_rows"
                            f" WHERE business_id IN ({placeholders})",
                            batch,
                        ).fetchall()
                    )
                if conflicts:
                    reason = "CONFLICT: business id(s) already imported: " + ", ".join(
                        sorted(conflicts)[:10]
                    )
                    conn.execute(
                        "UPDATE uploads SET state=?, error_reason=?, updated_at=?"
                        " WHERE upload_id=? AND state=?",
                        (db.ERROR, reason, db._now(), upload_id, db.READY),
                    )
                    return self._status_row(conn, conn.execute(
                        "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
                    ).fetchone())

                # Rows and the terminal state commit together, atomically.
                conn.executemany(
                    "INSERT INTO imported_rows(business_id, upload_id, value)"
                    " VALUES (?,?,?)",
                    [(r.id, upload_id, r.value) for r in rows],
                )
                conn.execute(
                    "UPDATE uploads SET state=?, error_reason=NULL,"
                    " imported_at=?, updated_at=? WHERE upload_id=? AND state=?",
                    (db.IMPORTED, db._now(), db._now(), upload_id, db.READY),
                )
                return self._status_row(conn, conn.execute(
                    "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
                ).fetchone())
        except sqlite3.IntegrityError as exc:
            return self._fail_import(
                upload_id, generation, "CONSTRAINT", f"constraint failed: {exc}"
            )

    def _fail_import(
        self, upload_id: str, generation: int, code: str, detail: str
    ) -> dict:
        reason = f"{code}: {detail}" if detail else code
        with self.db.txn() as conn:
            conn.execute(
                "UPDATE uploads SET state=?, error_reason=?, updated_at=?"
                " WHERE upload_id=? AND state=? AND generation=?",
                (db.ERROR, reason, db._now(), upload_id, db.READY, generation),
            )
            row = conn.execute(
                "SELECT * FROM uploads WHERE upload_id=?", (upload_id,)
            ).fetchone()
            return self._status_row(conn, row)

    # ------------------------------------------------------------------
    # inspection / maintenance
    # ------------------------------------------------------------------
    def inspect_rows(self, upload_id: str | None = None) -> list[dict]:
        with self.db.read() as conn:
            if upload_id is None:
                cur = conn.execute(
                    "SELECT business_id, upload_id, value FROM imported_rows"
                    " ORDER BY upload_id, business_id"
                )
            else:
                cur = conn.execute(
                    "SELECT business_id, upload_id, value FROM imported_rows"
                    " WHERE upload_id=? ORDER BY business_id",
                    (upload_id,),
                )
            return [dict(r) for r in cur.fetchall()]

    def _referenced_content_ids(self) -> list[str]:
        with self.db.read() as conn:
            return [
                r["content_id"]
                for r in conn.execute("SELECT DISTINCT content_id FROM uploads")
            ]

    def cleanup_objects(self) -> list[str]:
        """Garbage-collect only service-created, unreferenced objects.

        Never receives user paths; names come from enumerating our own store
        and are validated as digest-shaped regular files.
        """
        return self.store.collect_garbage(self._referenced_content_ids())
