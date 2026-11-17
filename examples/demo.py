"""Runnable walkthrough of the attack sequences from the task.

Run from the repo root::

    python3 examples/demo.py

It uses real subprocesses, real SQLite and prints the managed-object digest so
the identity/allocation claims can be checked by eye.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from quarantine.service import QuarantineService

FIXTURE = Path(__file__).resolve().parent.parent / "materials" / "521" / "source_fixture.py"


def show(label, value):
    print(f"\n== {label} ==")
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


def main():
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name) / "state"
    work = Path(tmp.name) / "work"
    work.mkdir()
    svc = QuarantineService(root, FIXTURE, scan_timeout=10.0)
    try:
        # 1. Normal admit -> scan -> import.
        victim = work / "victim.csv"
        victim.write_text("id,value\na,1\n")
        admitted = svc.submit("u1", victim, "victim.csv")
        show("admitted", admitted)
        obj = svc.store.path_for(admitted["content_id"])
        print("managed object digest:",
              hashlib.sha256(obj.read_bytes()).hexdigest())

        # 2. Replace the caller's path *before* scanning: object is unchanged.
        victim.write_text("id,value\nSWAPPED,9\n")
        show("scan after swap", svc.scan("u1"))  # fixture still sees a,1

        # 3. Replace again between scan and import.
        victim.write_text("id,value\nz,999\n")
        show("import after second swap", svc.import_upload("u1"))
        show("rows", svc.inspect_rows("u1"))

        # 4. Direct SQLite glance.
        conn = sqlite3.connect(root / "quarantine.sqlite3")
        conn.row_factory = sqlite3.Row
        print("\n== raw SQLite ==")
        print("uploads:", [dict(r) for r in conn.execute(
            "SELECT upload_id, content_id, state, generation FROM uploads")])
        print("imported_rows:", [dict(r) for r in conn.execute(
            "SELECT business_id, upload_id, value FROM imported_rows")])
        conn.close()

        # 5. BLOCK / partial / bad_exit / stderr_flood on fresh uploads.
        for i, mode in enumerate(["block", "partial", "bad_exit", "stderr_flood"]):
            uid = f"mode{i}"
            src = work / f"{uid}.csv"
            src.write_text(f"id,value\n{uid},1\n")
            svc.submit(uid, src, f"{uid}.csv")
            st = svc.scan(uid, mode=mode)
            attempt = st["attempts"][-1]
            print(f"\nmode={mode:13s} upload={st['state']:8s}"
                  f" attempt={attempt['state']:6s} reason={attempt['reason']}")

        # 6. Cancel in-flight scan; a late ALLOW cannot reactivate it.
        slow = work / "slow.py"
        slow.write_text(
            "import sys,json,hashlib,time\n"
            "from pathlib import Path\n"
            "mode,path,sid=sys.argv[1:]\ntime.sleep(2)\n"
            "d=Path(path).read_bytes()\n"
            "print(json.dumps({'scan_id':sid,'content_sha256':"
            "hashlib.sha256(d).hexdigest(),'size':len(d),"
            "'verdict':'ALLOW','reason':'slow'}),flush=True)\n"
        )
        from quarantine.scanner import ScanAdapter
        svc.adapter = ScanAdapter(slow, timeout=15.0)
        src = work / "cancel.csv"
        src.write_text("id,value\nc,1\n")
        svc.submit("uc", src, "cancel.csv")
        svc.scan("uc", wait=False)
        time.sleep(0.1)
        show("cancelled", svc.cancel("uc"))
        time.sleep(2.4)  # past when the late ALLOW would have arrived
        show("after late ALLOW window", svc.status("uc"))

        # 7. Business-id CONFLICT across uploads.
        for uid, text in [("c1", "id,value\ndup,1\n"), ("c2", "id,value\ndup,2\ne,3\n")]:
            p = work / f"{uid}.csv"
            p.write_text(text)
            svc.submit(uid, p, f"{uid}.csv")
            svc.scan(uid)
        svc.import_upload("c1")
        show("conflicting import", svc.import_upload("c2"))
        show("rows unchanged", svc.inspect_rows())

        # 8. Cleanup only removes unreferenced, service-created objects.
        orphan_id, _, _ = svc.store.admit_from_path(work / "victim.csv", 1 << 20)
        notes = svc.store.objects / "user-notes.txt"
        notes.write_text("not ours to delete")
        show("cleanup", {"removed": svc.cleanup_objects(),
                         "user_file_survived": notes.exists()})
    finally:
        svc.close()
        tmp.cleanup()


if __name__ == "__main__":
    main()
