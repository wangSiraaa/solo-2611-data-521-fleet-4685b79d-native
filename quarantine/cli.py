"""Command-line interface and programmatic entry point.

Commands
--------
submit   admit a local file under an upload_id + display name
scan     run one explicit scan attempt (new scan_id) on an upload
cancel   cancel an in-flight scan and reap its child
status   show upload state plus its scan attempts
import   validate and atomically import a READY upload
inspect_rows   dump imported rows (optionally for one upload)
cleanup  garbage-collect unreferenced managed objects
recover  report uploads left pending by a previous process
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import QuarantineError
from .service import QuarantineService


def _dump(obj) -> None:
    json.dump(obj, sys.stdout, indent=2, sort_keys=True, ensure_ascii=False)
    sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="quarantine", description=__doc__)
    parser.add_argument(
        "--root",
        default=".quarantine",
        help="service state root (objects, tmp, SQLite)",
    )
    parser.add_argument(
        "--fixture",
        default=str(Path(__file__).resolve().parent.parent
                    / "materials" / "521" / "source_fixture.py"),
        help="path to the synthetic scanner fixture",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("submit")
    p.add_argument("upload_id")
    p.add_argument("path")
    p.add_argument("--display-name", default=None)

    p = sub.add_parser("scan")
    p.add_argument("upload_id")
    p.add_argument("--mode", default="normal")
    p.add_argument("--no-wait", action="store_true")

    p = sub.add_parser("cancel")
    p.add_argument("upload_id")

    p = sub.add_parser("status")
    p.add_argument("upload_id")

    p = sub.add_parser("import")
    p.add_argument("upload_id")

    p = sub.add_parser("inspect_rows")
    p.add_argument("upload_id", nargs="?")

    sub.add_parser("cleanup")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    service = QuarantineService(
        Path(args.root), Path(args.fixture), scan_timeout=args.timeout
    )
    try:
        if args.command == "submit":
            display = args.display_name or Path(args.path).name
            _dump(service.submit(args.upload_id, Path(args.path), display))
        elif args.command == "scan":
            _dump(
                service.scan(
                    args.upload_id, mode=args.mode, wait=not args.no_wait
                )
            )
        elif args.command == "cancel":
            _dump(service.cancel(args.upload_id))
        elif args.command == "status":
            _dump(service.status(args.upload_id))
        elif args.command == "import":
            _dump(service.import_upload(args.upload_id))
        elif args.command == "inspect_rows":
            _dump(service.inspect_rows(args.upload_id))
        elif args.command == "cleanup":
            _dump({"removed": service.cleanup_objects()})
        return 0
    except QuarantineError as exc:
        _dump({"error": type(exc).__name__, "detail": str(exc)})
        return 2
    finally:
        service.close()


if __name__ == "__main__":
    raise SystemExit(main())
