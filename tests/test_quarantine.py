"""End-to-end tests exercising real subprocesses, SQLite and managed objects."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from quarantine import database as db  # noqa: E402
from quarantine.errors import (  # noqa: E402
    CsvValidationError,
    ObjectIntegrityError,
    UploadConflict,
    UploadNotFound,
    UploadTooLarge,
)
from quarantine.scanner import ScanAdapter, ScanResult  # noqa: E402
from quarantine.service import InvalidState, QuarantineService  # noqa: E402

FIXTURE = ROOT / "materials" / "521" / "source_fixture.py"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name) / "state"
        self.work = Path(self.tmpdir.name) / "work"
        self.work.mkdir()
        self.service = QuarantineService(self.root, FIXTURE, scan_timeout=10.0)

    def use_slow_scanner(self, delay: float = 3.0) -> None:
        """Install a scanner that stays in flight long enough to act on."""
        script = self.work / "slow_scanner.py"
        script.write_text(
            "import sys, json, hashlib, time\n"
            "from pathlib import Path\n"
            "mode, path, scan_id = sys.argv[1:]\n"
            "time.sleep(%r)\n"
            "data = Path(path).read_bytes()\n"
            "print(json.dumps({'scan_id': scan_id,"
            " 'content_sha256': hashlib.sha256(data).hexdigest(),"
            " 'size': len(data), 'verdict': 'ALLOW', 'reason': 'slow'}),"
            " flush=True)\n" % delay
        )
        from quarantine.scanner import ScanAdapter

        self.service.adapter = ScanAdapter(script, timeout=15.0)

    def tearDown(self):
        try:
            self.service.close(wait=True, timeout=5)
        finally:
            self.tmpdir.cleanup()

    def csv(self, name: str, text: str) -> Path:
        path = self.work / name
        path.write_bytes(text.encode("utf-8"))
        return path

    def admit(self, upload_id="u1", text="id,value\na,1\n", name="a.csv"):
        return self.service.submit(upload_id, self.csv(name, text), name)


class TestFixtureModes(Base):
    def test_normal_allow_then_import(self):
        self.admit()
        status = self.service.scan("u1")
        self.assertEqual(status["state"], db.READY)
        self.assertEqual(status["attempts"][-1]["state"], "allow")
        imported = self.service.import_upload("u1")
        self.assertEqual(imported["state"], db.IMPORTED)
        self.assertEqual(imported["imported_row_count"], 1)
        self.assertEqual(
            self.service.inspect_rows("u1"),
            [{"business_id": "a", "upload_id": "u1", "value": 1}],
        )

    def test_block_never_imports(self):
        self.admit()
        status = self.service.scan("u1", mode="block")
        self.assertEqual(status["state"], db.BLOCKED)
        self.assertEqual(self.service.inspect_rows("u1"), [])
        with self.assertRaises(InvalidState):
            self.service.import_upload("u1")

    def test_partial_output_is_error(self):
        self.admit()
        status = self.service.scan("u1", mode="partial")
        self.assertEqual(status["state"], db.ERROR)
        self.assertEqual(status["attempts"][-1]["reason"], "invalid_record")
        self.assertEqual(self.service.inspect_rows("u1"), [])

    def test_bad_exit_is_error_not_allow(self):
        self.admit()
        status = self.service.scan("u1", mode="bad_exit")
        self.assertEqual(status["state"], db.ERROR)
        self.assertIn("nonzero_exit", status["attempts"][-1]["reason"])
        self.assertEqual(self.service.inspect_rows("u1"), [])

    def test_stderr_flood_does_not_hang_and_succeeds(self):
        self.admit()
        start = time.monotonic()
        status = self.service.scan("u1", mode="stderr_flood")
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 10)
        self.assertEqual(status["state"], db.READY)
        attempt = status["attempts"][-1]
        self.assertEqual(attempt["state"], "allow")
        # stderr is retained only as a bounded tail, never parsed as a result.
        tail = self.service.db.conn.execute(
            "SELECT stderr_tail, length(stderr_tail) FROM scan_attempts"
            " WHERE scan_id=?", (attempt["scan_id"],)
        ).fetchone()
        self.assertLessEqual(tail[1], 8 * 1024)
        self.assertIn("diagnostic", tail[0])


class TestAdapterContract(unittest.TestCase):
    """Direct adapter tests for records the fixture cannot naturally emit."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "obj"
        self.data = b"id,value\na,1\n"
        self.path.write_bytes(self.data)
        self.cid = hashlib.sha256(self.data).hexdigest()
        self.size = len(self.data)

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, body: str):
        script = Path(self.tmp.name) / "fake.py"
        script.write_text(body)
        adapter = ScanAdapter(script, timeout=8.0)
        return adapter.run(
            scan_id="sid1",
            content_id=self.cid,
            size=self.size,
            object_path=self.path,
        )

    def record(self, **over):
        base = {
            "scan_id": "sid1",
            "content_sha256": self.cid,
            "size": self.size,
            "verdict": "ALLOW",
            "reason": "ok",
        }
        base.update(over)
        return json.dumps(base)

    def test_duplicate_terminal_record_is_error(self):
        r = self.record()
        res = self.run_script(
            "import sys\nsys.stdout.write(%r + %r)\n" % (r + "\n", r + "\n")
        )
        self.assertEqual(res.state, "error")
        self.assertEqual(res.reason, "invalid_record")

    def test_unknown_scan_id_is_error(self):
        res = self.run_script(
            "import sys\nsys.stdout.write(%r)\n" % self.record(scan_id="other")
        )
        self.assertEqual(res.state, "error")
        self.assertEqual(res.reason, "scan_id_mismatch")

    def test_digest_mismatch_is_error(self):
        res = self.run_script(
            "import sys\nsys.stdout.write(%r)\n"
            % self.record(content_sha256="0" * 64)
        )
        self.assertEqual(res.state, "error")
        self.assertEqual(res.reason, "digest_mismatch")

    def test_size_mismatch_is_error(self):
        res = self.run_script(
            "import sys\nsys.stdout.write(%r)\n" % self.record(size=self.size + 1)
        )
        self.assertEqual(res.state, "error")
        self.assertEqual(res.reason, "size_mismatch")

    def test_record_then_nonzero_exit_is_error(self):
        res = self.run_script(
            "import sys\nsys.stdout.write(%r)\nsys.exit(3)\n" % self.record()
        )
        self.assertEqual(res.state, "error")
        self.assertEqual(res.reason, "nonzero_exit:3")

    def test_stdout_overflow_is_error(self):
        res = self.run_script(
            "import sys\nsys.stdout.write('x'*20000)\n"
        )
        self.assertEqual(res.state, "error")
        self.assertEqual(res.reason, "stdout_overflow")

    def test_timeout_is_error(self):
        script = Path(self.tmp.name) / "slow.py"
        script.write_text("import time\ntime.sleep(30)\n")
        adapter = ScanAdapter(script, timeout=0.3)
        res = adapter.run(
            scan_id="sid1", content_id=self.cid, size=self.size,
            object_path=self.path,
        )
        self.assertEqual(res.state, "error")
        self.assertEqual(res.reason, "timeout")

    def test_stderr_flood_streams_without_deadlock(self):
        script = Path(self.tmp.name) / "flood.py"
        script.write_text(
            "import sys\nsys.stderr.write('e'*200000)\n"
            "sys.stdout.write(%r)\n" % self.record()
        )
        adapter = ScanAdapter(script, timeout=8.0)
        res = adapter.run(
            scan_id="sid1", content_id=self.cid, size=self.size,
            object_path=self.path,
        )
        self.assertEqual(res.state, "allow")
        self.assertLessEqual(len(res.stderr_tail), 8 * 1024)


class TestIdentityAndAdmission(Base):
    def test_same_upload_same_content_is_idempotent(self):
        a = self.admit()
        b = self.service.submit(
            "u1", self.csv("copy.csv", "id,value\na,1\n"), "other-name.csv"
        )
        self.assertEqual(a["content_id"], b["content_id"])
        self.assertEqual(b["state"], a["state"])
        rows = self.service.db.conn.execute(
            "SELECT COUNT(*) FROM uploads"
        ).fetchone()[0]
        self.assertEqual(rows, 1)

    def test_same_upload_different_content_conflicts(self):
        self.admit()
        with self.assertRaises(UploadConflict):
            self.service.submit(
                "u1", self.csv("b.csv", "id,value\nb,2\n"), "b.csv"
            )

    def test_replacing_source_after_admission_does_not_change_object(self):
        source = self.csv("swap.csv", "id,value\na,1\n")
        admitted = self.service.submit("u1", source, "swap.csv")
        original = admitted["content_id"]
        # Replace the caller's path with different bytes after admission.
        source.write_bytes(b"id,value\nb,2\n")
        self.service.scan("u1")
        imported = self.service.import_upload("u1")
        self.assertEqual(imported["state"], db.IMPORTED)
        self.assertEqual(imported["content_id"], original)
        # The imported row is from the admitted bytes, not the swapped path.
        self.assertEqual(
            self.service.inspect_rows("u1"),
            [{"business_id": "a", "upload_id": "u1", "value": 1}],
        )
        stored = self.service.store.read_bytes(original)
        self.assertEqual(stored, b"id,value\na,1\n")

    def test_display_name_does_not_define_identity(self):
        a = self.service.submit(
            "u1", self.csv("one.csv", "id,value\na,1\n"), "same-name.csv"
        )
        b = self.service.submit(
            "u2", self.csv("two.csv", "id,value\na,1\n"), "same-name.csv"
        )
        self.assertEqual(a["content_id"], b["content_id"])

    def test_object_is_content_addressed_and_readonly(self):
        st = self.admit()
        path = self.service.store.path_for(st["content_id"])
        self.assertTrue(path.exists())
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), st["content_id"])
        self.assertEqual(path.stat().st_mode & 0o222, 0)

    def test_oversized_upload_rejected(self):
        big = self.work / "big.csv"
        big.write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(UploadTooLarge):
            self.service.submit("big", big, "big.csv")
        self.assertIsNone(
            self.service.db.conn.execute(
                "SELECT * FROM uploads WHERE upload_id='big'"
            ).fetchone()
        )


class TestImportValidation(Base):
    def _ready(self, text, upload_id="u1"):
        self.admit(upload_id, text)
        st = self.service.scan(upload_id)
        self.assertEqual(st["state"], db.READY)
        return st

    def assert_rejected(self, text, code_prefix):
        self._ready(text)
        st = self.service.import_upload("u1")
        self.assertEqual(st["state"], db.ERROR)
        self.assertTrue(
            st["error_reason"].startswith(code_prefix),
            f"expected {code_prefix}, got {st['error_reason']}",
        )
        self.assertEqual(self.service.inspect_rows("u1"), [])

    def test_duplicate_id(self):
        self.assert_rejected("id,value\na,1\na,2\n", "DUPLICATE_ID")

    def test_empty_id(self):
        self.assert_rejected("id,value\n,1\n", "EMPTY_ID")

    def test_negative_value(self):
        self.assert_rejected("id,value\na,-1\n", "BAD_VALUE")

    def test_bool_value(self):
        self.assert_rejected("id,value\na,true\n", "BAD_VALUE")

    def test_missing_column(self):
        self.assert_rejected("id,value\na\n", "BAD_COLUMN_COUNT")

    def test_wrong_header(self):
        self.assert_rejected("id,val\na,1\n", "BAD_HEADER")

    def test_bad_utf8(self):
        path = self.work / "bad.csv"
        path.write_bytes(b"id,value\na,\xff\n")
        self.service.submit("u1", path, "bad.csv")
        self.assertEqual(self.service.scan("u1")["state"], db.READY)
        st = self.service.import_upload("u1")
        self.assertEqual(st["state"], db.ERROR)
        self.assertTrue(st["error_reason"].startswith("DECODE_ERROR"))

    def test_value_over_int64(self):
        self.assert_rejected(
            "id,value\na,9223372036854775808\n", "VALUE_OUT_OF_RANGE"
        )

    def test_leading_zero_is_still_nonnegative_int(self):
        self._ready("id,value\na,007\n")
        st = self.service.import_upload("u1")
        self.assertEqual(st["state"], db.IMPORTED)
        self.assertEqual(self.service.inspect_rows("u1")[0]["value"], 7)

    def test_mixed_valid_invalid_leaves_no_prefix_rows(self):
        self._ready("id,value\na,1\nb,2\nc,-3\n")
        st = self.service.import_upload("u1")
        self.assertEqual(st["state"], db.ERROR)
        self.assertEqual(self.service.inspect_rows("u1"), [])


class TestConflictsAndIdempotency(Base):
    def test_business_id_conflict_between_uploads(self):
        for uid, text in [("u1", "id,value\na,1\n"), ("u2", "id,value\na,9\nb,2\n")]:
            self.service.submit(uid, self.csv(f"{uid}.csv", text), f"{uid}.csv")
            self.assertEqual(self.service.scan(uid)["state"], db.READY)
        first = self.service.import_upload("u1")
        self.assertEqual(first["state"], db.IMPORTED)
        second = self.service.import_upload("u2")
        self.assertEqual(second["state"], db.ERROR)
        self.assertIn("CONFLICT", second["error_reason"])
        # No partial write: b was not inserted, a still belongs to u1.
        self.assertEqual(
            self.service.inspect_rows(),
            [{"business_id": "a", "upload_id": "u1", "value": 1}],
        )

    def test_import_is_idempotent_and_does_not_rewrite(self):
        self.admit()
        self.service.scan("u1")
        self.service.import_upload("u1")
        again = self.service.import_upload("u1")
        self.assertEqual(again["state"], db.IMPORTED)
        self.assertEqual(again["imported_row_count"], 1)
        self.assertEqual(len(self.service.inspect_rows("u1")), 1)

    def test_import_requires_ready(self):
        self.admit()
        with self.assertRaises(InvalidState):
            self.service.import_upload("u1")


class TestCancelAndStaleResults(Base):
    def test_cancel_terminates_child_and_late_allow_cannot_reactivate(self):
        self.use_slow_scanner(2.0)
        self.admit()
        self.service.scan("u1", mode="normal", wait=False)
        self.assertEqual(self.service.status("u1")["state"], db.SCANNING)
        st = self.service.cancel("u1")
        self.assertEqual(st["state"], db.ERROR)
        self.assertEqual(st["error_reason"], "cancelled")
        # Wait past when a normal scan would have finished and confirm the
        # late ALLOW cannot move it to ready.
        time.sleep(2.5)
        final = self.service.status("u1")
        self.assertEqual(final["state"], db.ERROR)
        self.assertEqual(self.service.inspect_rows("u1"), [])
        with self.assertRaises(InvalidState):
            self.service.import_upload("u1")

    def test_cancel_reaps_child_process(self):
        self.use_slow_scanner(2.0)
        self.admit()
        self.service.scan("u1", mode="normal", wait=False)
        self.assertEqual(self.service.status("u1")["state"], db.SCANNING)
        pid = None
        with self.service._jobs_lock:
            for job in self.service._jobs.values():
                proc = job.proc()
                if proc is not None:
                    pid = proc.pid
        self.assertIsNotNone(pid)
        self.service.cancel("u1")
        # Process should be gone (reaped by adapter -> poll not None).
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.05)
        else:
            self.fail("child scan process was not terminated")

    def test_cancel_imported_refused_and_rows_kept(self):
        self.admit()
        self.service.scan("u1")
        self.service.import_upload("u1")
        with self.assertRaises(InvalidState):
            self.service.cancel("u1")
        self.assertEqual(len(self.service.inspect_rows("u1")), 1)

    def test_cancel_then_inject_stale_allow_receipt(self):
        """After cancel, replaying an old ALLOW receipt must not reactivate."""
        self.use_slow_scanner(1.5)
        self.admit()
        self.service.scan("u1", wait=False)
        with self.service._jobs_lock:
            job = next(iter(self.service._jobs.values()))
        old_scan_id = job.scan_id
        content_id = self.service.status("u1")["content_id"]
        size = self.service.status("u1")["size"]
        self.service.cancel("u1")
        # Forge the ALLOW receipt that the terminated child would have emitted.
        from quarantine.scanner import ScanResult
        from quarantine.service import Job

        stale = ScanResult(
            scan_id=old_scan_id,
            content_id=content_id,
            size=size,
            state="allow",
            verdict="ALLOW",
            reason="late allow",
        )
        self.service._finalize(Job(old_scan_id, "u1", 1, content_id), stale)
        st = self.service.status("u1")
        self.assertEqual(st["state"], db.ERROR)
        self.assertEqual(st["error_reason"], "cancelled")
        self.assertEqual(self.service.inspect_rows("u1"), [])

    def test_replace_source_between_scan_and_import(self):
        """Swapping the original path after scan cannot change imported bytes."""
        source = self.csv("victim.csv", "id,value\na,1\n")
        admitted = self.service.submit("u1", source, "victim.csv")
        content_id = admitted["content_id"]
        self.assertEqual(self.service.scan("u1")["state"], db.READY)
        # The user mutates the original path after the scan, before import.
        source.write_bytes(b"id,value\nz,999\n")
        imported = self.service.import_upload("u1")
        self.assertEqual(imported["state"], db.IMPORTED)
        self.assertEqual(imported["content_id"], content_id)
        self.assertEqual(
            self.service.inspect_rows("u1"),
            [{"business_id": "a", "upload_id": "u1", "value": 1}],
        )
        # Managed object still holds the admitted bytes.
        self.assertEqual(
            self.service.store.read_bytes(content_id), b"id,value\na,1\n"
        )

    def test_old_scan_id_cannot_settle_new_attempt(self):
        self.admit()
        first = self.service.scan("u1", mode="block")
        old_scan_id = first["attempts"][-1]["scan_id"]
        self.assertEqual(len(first["attempts"]), 1)
        # Re-scan: a fresh scan_id must be issued.
        second = self.service.scan("u1", mode="normal")
        self.assertEqual(second["state"], db.READY)
        new_scan_id = second["attempts"][-1]["scan_id"]
        self.assertNotEqual(old_scan_id, new_scan_id)
        # A forged finalize using the old scan_id is rejected.
        from quarantine.scanner import ScanResult

        with self.service._jobs_lock:
            job = None
        # Simulate a stale result bound to the old id.
        fake = ScanResult(
            scan_id=old_scan_id,
            content_id=second["content_id"],
            size=second["size"],
            state="block",
            verdict="BLOCK",
            reason="late",
        )
        # _finalize with a job that owns the old scan id must not change state.
        from quarantine.service import Job

        stale_job = Job(old_scan_id, "u1", 1, second["content_id"])
        self.service._finalize(stale_job, fake)
        self.assertEqual(self.service.status("u1")["state"], db.READY)


class TestResultOwnership(Base):
    def test_result_for_content_a_rejected_for_upload_b(self):
        self.service.submit("u1", self.csv("a.csv", "id,value\na,1\n"), "a.csv")
        self.service.submit("u2", self.csv("b.csv", "id,value\nb,2\n"), "b.csv")
        self.service.scan("u1")
        st1 = self.service.status("u1")
        st2 = self.service.status("u2")
        self.assertNotEqual(st1["content_id"], st2["content_id"])
        # Adapter-level: a record for u1's object cannot pass for u2's object.
        adapter = ScanAdapter(FIXTURE, timeout=5.0)
        from quarantine.scanner import ScanResult

        res = adapter.run(
            scan_id="x",
            content_id=st2["content_id"],
            size=st2["size"],
            object_path=self.service.store.path_for(st1["content_id"]),
        )
        # Fixture hashes the object it was pointed at; identity check fails
        # because that digest is u1's, not the bound u2 digest.
        self.assertEqual(res.state, "error")
        self.assertEqual(res.reason, "digest_mismatch")


class TestRecoveryAndShutdown(Base):
    def test_shutdown_leaves_pending_and_restart_reschedules(self):
        self.use_slow_scanner(2.0)
        self.admit()
        self.service.scan("u1", mode="normal", wait=False)
        self.assertEqual(self.service.status("u1")["state"], db.SCANNING)
        self.service.close(wait=True, timeout=5)
        # Reopen: a merely-started scan is pending (received), not passed.
        svc2 = QuarantineService(self.root, FIXTURE)
        try:
            st = svc2.status("u1")
            self.assertEqual(st["state"], db.RECEIVED)
            self.assertEqual(st["attempts"][-1]["state"], "aborted")
            # Explicit rescheduling succeeds and is what produces ALLOW.
            st = svc2.scan("u1")
            self.assertEqual(st["state"], db.READY)
        finally:
            svc2.close()

    def test_orphan_running_attempt_becomes_pending(self):
        self.admit()
        # Simulate a crashed process: insert a running attempt directly.
        with self.service.db.txn() as conn:
            conn.execute(
                "UPDATE uploads SET state='scanning', generation=1 WHERE upload_id='u1'"
            )
            conn.execute(
                "INSERT INTO scan_attempts(scan_id, upload_id, content_id,"
                " generation, state, created_at) VALUES ('crashed','u1',"
                " (SELECT content_id FROM uploads WHERE upload_id='u1'), 1,"
                " 'running', '2020-01-01T00:00:00+00:00')"
            )
        # Reopening in-process must recover the orphan; use a fresh service.
        svc2 = QuarantineService(self.root, FIXTURE)
        try:
            st = svc2.status("u1")
            self.assertEqual(st["state"], db.RECEIVED)
            self.assertEqual(st["attempts"][-1]["state"], "aborted")
        finally:
            svc2.close()
        self.service.close(wait=False)  # now a no-op; already idempotent


class TestResponsivenessAndLimits(Base):
    def test_status_works_while_two_scans_occupy_pool(self):
        self.use_slow_scanner(3.0)
        for uid in ("u1", "u2", "u3"):
            self.service.submit(
                uid, self.csv(f"{uid}.csv", f"id,value\n{uid},1\n"), f"{uid}.csv"
            )
            self.service.scan(uid, wait=False)
        time.sleep(0.1)
        start = time.monotonic()
        st = self.service.status("u1")
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.0)
        self.assertEqual(st["state"], db.SCANNING)
        # Cancel one of the stuck ones while others still occupy workers.
        c = self.service.cancel("u2")
        self.assertEqual(c["state"], db.ERROR)

    def test_at_most_two_scan_processes(self):
        marker_dir = self.work / "running"
        marker_dir.mkdir()
        script = self.work / "counting_scanner.py"
        script.write_text(
            "import sys, json, hashlib, time, os\n"
            "from pathlib import Path\n"
            "mode, path, scan_id = sys.argv[1:]\n"
            "marker = Path(%r) / scan_id\n"
            "marker.write_text('x')\n"
            "time.sleep(1.5)\n"
            "data = Path(path).read_bytes()\n"
            "print(json.dumps({'scan_id': scan_id,"
            " 'content_sha256': hashlib.sha256(data).hexdigest(),"
            " 'size': len(data), 'verdict': 'ALLOW', 'reason': 'ok'}),"
            " flush=True)\n"
            "marker.unlink()\n" % str(marker_dir)
        )
        from quarantine.scanner import ScanAdapter

        self.service.adapter = ScanAdapter(script, timeout=15.0)
        for i in range(4):
            uid = f"u{i}"
            self.service.submit(
                uid, self.csv(f"{uid}.csv", f"id,value\n{uid},1\n"), f"{uid}.csv"
            )
            self.service.scan(uid, wait=False)
        # Sample how many children run at once.
        peak = 0
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            peak = max(peak, len(list(marker_dir.iterdir())))
            time.sleep(0.05)
            if peak > 2:
                break
        self.assertLessEqual(peak, 2, f"saw {peak} concurrent scan processes")
        self.assertGreaterEqual(peak, 1)

    def test_row_limit(self):
        lines = ["id,value"] + [f"r{i},{i}" for i in range(1001)]
        path = self.work / "many.csv"
        path.write_text("\n".join(lines) + "\n")
        self.service.submit("u1", path, "many.csv")
        self.assertEqual(self.service.scan("u1")["state"], db.READY)
        st = self.service.import_upload("u1")
        self.assertEqual(st["state"], db.ERROR)
        self.assertTrue(st["error_reason"].startswith("TOO_MANY_ROWS"))
        self.assertEqual(self.service.inspect_rows("u1"), [])

    def test_exactly_1000_rows_ok(self):
        lines = ["id,value"] + [f"r{i},{i}" for i in range(1000)]
        path = self.work / "exact.csv"
        path.write_text("\n".join(lines) + "\n")
        self.service.submit("u1", path, "exact.csv")
        self.service.scan("u1")
        st = self.service.import_upload("u1")
        self.assertEqual(st["state"], db.IMPORTED)
        self.assertEqual(st["imported_row_count"], 1000)


class TestDirectSQLiteAndObjects(Base):
    def test_inspect_sqlite_directly(self):
        self.admit()
        self.service.scan("u1")
        self.service.import_upload("u1")
        conn = sqlite3.connect(self.root / "quarantine.sqlite3")
        try:
            rows = conn.execute(
                "SELECT business_id, value FROM imported_rows"
            ).fetchall()
            state = conn.execute(
                "SELECT state FROM uploads WHERE upload_id='u1'"
            ).fetchone()[0]
            attempts = conn.execute(
                "SELECT state, verdict FROM scan_attempts WHERE upload_id='u1'"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(rows, [("a", 1)])
        self.assertEqual(state, "imported")
        self.assertEqual(attempts, [("allow", "ALLOW")])

    def test_managed_object_digest_matches_content_id(self):
        st = self.admit()
        path = self.service.store.path_for(st["content_id"])
        self.assertEqual(
            hashlib.sha256(path.read_bytes()).hexdigest(), st["content_id"]
        )
        self.assertEqual(path.stat().st_size, st["size"])

    def test_cleanup_only_removes_unreferenced_objects(self):
        self.admit()
        # Create an unreferenced object directly in the store.
        orphan_id, _, _ = self.service.store.admit_from_path(
            self.csv("orphan.csv", "id,value\nz,9\n"), 1024
        )
        self.assertNotEqual(orphan_id, self.service.status("u1")["content_id"])
        # A user file placed inside the objects tree with a non-digest name
        # must never be treated as a deletion target.
        user_file = self.service.store.objects / "user-notes.txt"
        user_file.write_text("keep me")
        removed = self.service.cleanup_objects()
        self.assertIn(orphan_id, removed)
        self.assertNotIn(self.service.status("u1")["content_id"], removed)
        self.assertTrue(user_file.exists())
        self.assertTrue(
            self.service.store.path_for(
                self.service.status("u1")["content_id"]
            ).exists()
        )

    def test_corrupted_object_blocks_import(self):
        self.admit()
        self.service.scan("u1")
        cid = self.service.status("u1")["content_id"]
        path = self.service.store.path_for(cid)
        os.chmod(path, 0o644)
        path.write_bytes(b"id,value\na,999\n")
        st = self.service.import_upload("u1")
        self.assertEqual(st["state"], db.ERROR)
        self.assertTrue(st["error_reason"].startswith("INTEGRITY"))
        self.assertEqual(self.service.inspect_rows("u1"), [])


class TestCli(Base):
    def _cli(self, *args):
        env = dict(os.environ)
        return subprocess.run(
            [sys.executable, "-m", "quarantine.cli", "--root", str(self.root),
             "--fixture", str(FIXTURE), *args],
            cwd=str(ROOT), capture_output=True, text=True, env=env,
        )

    def test_end_to_end_cli(self):
        src = self.csv("cli.csv", "id,value\na,1\n")
        r = self._cli("submit", "u1", str(src), "--display-name", "cli.csv")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self._cli("scan", "u1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["state"], "ready")
        r = self._cli("import", "u1")
        self.assertEqual(json.loads(r.stdout)["state"], "imported")
        r = self._cli("inspect_rows", "u1")
        self.assertEqual(json.loads(r.stdout)[0]["business_id"], "a")
        r = self._cli("status", "u1")
        self.assertEqual(json.loads(r.stdout)["state"], "imported")


if __name__ == "__main__":
    unittest.main(verbosity=2)
