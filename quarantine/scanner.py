"""Subprocess scan adapter.

The adapter owns one child process per scan attempt and treats the child's
stdout as data, not as a status channel implicitly.  It:

* drains stdout and stderr concurrently so a child that floods stderr cannot
  block the parent forever;
* caps retained stdout at 16 KiB and keeps only the last 8 KiB of stderr;
* requires exactly one complete UTF-8 JSON final record;
* requires the record to carry the expected ``scan_id`` and to match the
  bound object's digest/size;
* requires a zero exit status *after* the record;
* maps every deviation (partial JSON, duplicate terminal records, wrong
  identity, timeout, overflow, non-zero exit) to ERROR, never ALLOW.

A fresh ``scan_id`` is generated for each attempt.  A record from an older
attempt therefore fails the identity check and cannot settle a newer one.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

STDOUT_LIMIT = 16 * 1024
STDERR_TAIL_LIMIT = 8 * 1024


@dataclass
class ScanResult:
    scan_id: str
    content_id: str
    size: int
    state: str  # "allow" | "block" | "error"
    verdict: str | None
    reason: str
    exit_code: int | None = None
    pid: int | None = None
    stdout_bytes: int = 0
    stderr_tail: str = ""
    timed_out: bool = False
    cancelled: bool = False
    detail: str = ""

    @property
    def allowed(self) -> bool:
        return self.state == "allow"


def _pump(pipe, on_chunk) -> None:
    try:
        while True:
            chunk = pipe.read(4096)
            if not chunk:
                break
            on_chunk(chunk)
    except (ValueError, OSError):
        pass
    finally:
        try:
            pipe.close()
        except OSError:
            pass


class ScanAdapter:
    def __init__(
        self,
        fixture: Path,
        *,
        python: str | None = None,
        timeout: float = 10.0,
        stdout_limit: int = STDOUT_LIMIT,
        stderr_tail_limit: int = STDERR_TAIL_LIMIT,
    ):
        self.fixture = Path(fixture)
        self.python = python or sys.executable
        self.timeout = timeout
        self.stdout_limit = stdout_limit
        self.stderr_tail_limit = stderr_tail_limit

    def command(self, mode: str, object_path: Path, scan_id: str) -> list[str]:
        return [self.python, str(self.fixture), mode, str(object_path), scan_id]

    def run(
        self,
        *,
        scan_id: str,
        content_id: str,
        size: int,
        object_path: Path,
        mode: str = "normal",
        proc_register=None,
        cancel_event: threading.Event | None = None,
    ) -> ScanResult:
        """Execute one scan attempt and return its *own* terminal result."""
        argv = self.command(mode, object_path, scan_id)
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # enables whole-group kill
            )
        except OSError as exc:
            return ScanResult(
                scan_id=scan_id,
                content_id=content_id,
                size=size,
                state="error",
                verdict=None,
                reason="spawn_failed",
                detail=str(exc),
            )

        if proc_register is not None:
            proc_register(proc)

        stdout_buf = bytearray()
        stdout_count = 0
        stdout_overflow = False
        stderr_buf = bytearray()

        def take_stdout(chunk: bytes) -> None:
            nonlocal stdout_count, stdout_overflow
            stdout_count += len(chunk)
            room = self.stdout_limit - len(stdout_buf)
            if room > 0:
                stdout_buf.extend(chunk[:room])
            if len(chunk) > room:
                stdout_overflow = True

        def take_stderr(chunk: bytes) -> None:
            stderr_buf.extend(chunk)
            excess = len(stderr_buf) - self.stderr_tail_limit
            if excess > 0:
                del stderr_buf[:excess]

        t_out = threading.Thread(target=_pump, args=(proc.stdout, take_stdout), daemon=True)
        t_err = threading.Thread(target=_pump, args=(proc.stderr, take_stderr), daemon=True)
        t_out.start()
        t_err.start()

        stop = {"reason": None}

        def stop_process(reason: str) -> None:
            # Do not mislabel a process that already exited on its own.
            if proc.poll() is not None:
                return
            if stop["reason"] is None:
                stop["reason"] = reason
            _kill_group(proc)

        timer = threading.Timer(self.timeout, stop_process, args=("timeout",))
        timer.daemon = True
        timer.start()
        try:
            while proc.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    stop_process("cancelled")
                try:
                    proc.wait(timeout=0.02)
                except subprocess.TimeoutExpired:
                    continue
        finally:
            timer.cancel()
        rc = proc.returncode
        # Give the pumps a moment to drain what the OS already buffered.
        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)

        err_tail = stderr_buf.decode("utf-8", "replace")
        base = dict(
            scan_id=scan_id,
            content_id=content_id,
            size=size,
            exit_code=rc,
            pid=proc.pid,
            stdout_bytes=stdout_count,
            stderr_tail=err_tail,
            timed_out=stop["reason"] == "timeout",
            cancelled=stop["reason"] == "cancelled",
        )

        if stop["reason"] == "cancelled":
            return ScanResult(
                state="error", verdict=None, reason="cancelled",
                detail="scan cancelled; child process group terminated", **base
            )
        if stop["reason"] == "timeout":
            return ScanResult(
                state="error", verdict=None, reason="timeout",
                detail=f"scan exceeded {self.timeout}s", **base
            )
        if stdout_overflow:
            return ScanResult(
                state="error", verdict=None, reason="stdout_overflow",
                detail=f"stdout exceeded {self.stdout_limit} bytes", **base
            )
        if rc != 0:
            return ScanResult(
                state="error", verdict=None, reason=f"nonzero_exit:{rc}",
                detail="scanner exited non-zero; its output is not trusted", **base
            )

        try:
            record = _parse_single_record(bytes(stdout_buf))
        except ValueError as exc:
            return ScanResult(
                state="error", verdict=None, reason="invalid_record",
                detail=str(exc), **base
            )

        required = {"scan_id", "content_sha256", "size", "verdict", "reason"}
        missing = sorted(required - set(record))
        if missing:
            return ScanResult(
                state="error", verdict=None, reason="record_missing_fields",
                detail=f"missing {missing}", **base
            )
        if record["scan_id"] != scan_id:
            return ScanResult(
                state="error", verdict=None, reason="scan_id_mismatch",
                detail=f"record scan_id {record['scan_id']!r} != {scan_id!r}", **base
            )
        if record["content_sha256"] != content_id:
            return ScanResult(
                state="error", verdict=None, reason="digest_mismatch",
                detail="record digest does not match the bound object", **base
            )
        if record["size"] != size:
            return ScanResult(
                state="error", verdict=None, reason="size_mismatch",
                detail=f"record size {record['size']!r} != {size}", **base
            )
        verdict = record["verdict"]
        if verdict not in ("ALLOW", "BLOCK"):
            return ScanResult(
                state="error", verdict=None, reason="invalid_verdict",
                detail=f"verdict {verdict!r} is not ALLOW/BLOCK", **base
            )
        reason = record["reason"]
        if not isinstance(reason, str):
            return ScanResult(
                state="error", verdict=None, reason="invalid_reason",
                detail="reason must be a string", **base
            )
        return ScanResult(
            state="allow" if verdict == "ALLOW" else "block",
            verdict=verdict,
            reason=reason,
            **base,
        )


def _parse_single_record(payload: bytes) -> dict:
    try:
        text = payload.lstrip().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"stdout is not valid UTF-8: {exc}") from exc
    decoder = json.JSONDecoder()
    try:
        obj, end = decoder.raw_decode(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"incomplete or invalid JSON record: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("final record is not a JSON object")
    if text[end:].strip():
        # A second terminal record, trailing garbage, or a doubled verdict.
        raise ValueError("trailing data after final record (duplicate terminal?)")
    return obj


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
        return
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.kill()
    except OSError:
        pass
