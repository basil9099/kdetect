"""Command-line interface for kdetect."""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from kdetect import __version__, hostfacts
from kdetect.collectors.procfs import ProcfsProcessCollector
from kdetect.collectors.sources import LiveProcSource
from kdetect.models import SCHEMA_VERSION, CaptureMeta, Snapshot

#: Exit codes. 3 is reserved for "analysis produced findings" so that phase 2
#: can introduce it without breaking anything scripted against phase 1.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def _iso_millis(now: datetime) -> str:
    """UTC ISO-8601 with millisecond precision and a Z suffix.

    isoformat() gives microseconds, which is more precision than /proc can
    justify, and varies in width. Fixing the format keeps captured_at
    comparable across snapshots.
    """
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def cmd_capture(args) -> int:
    host = hostfacts.gather()
    euid = os.geteuid()

    if euid != 0:
        # Warn, do not refuse. The snapshot records euid and lets analysis
        # decide what it means (principle P1). This goes to stderr because
        # --out - writes the snapshot to stdout, and a warning there would
        # corrupt a piped capture.
        print(
            f"warning: running as euid {euid}, not root. Kernel addresses in "
            "/proc/modules and /proc/kallsyms will read as zero, and some "
            "per-process reads will be denied. See docs/limitations.md L4.",
            file=sys.stderr,
        )

    observation = ProcfsProcessCollector().collect(LiveProcSource())

    now = datetime.now(timezone.utc)
    snapshot = Snapshot(
        schema_version=SCHEMA_VERSION,
        snapshot_id=str(uuid.uuid4()),
        captured_at=_iso_millis(now),
        host=host,
        capture=CaptureMeta(tool_version=__version__, euid=euid),
        observations=[observation],
    )

    payload = snapshot.to_json(pretty=args.pretty)

    if args.out == "-":
        print(payload)
        return EXIT_OK

    if args.out:
        path = Path(args.out)
    else:
        # No ':' - illegal in Windows filenames, and these files get copied to
        # the Windows host as fixtures. Sortable, and the boot_id prefix makes
        # it visible at a glance which captures share a boot.
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        path = Path("captures") / f"{stamp}_{host.hostname}_{host.boot_id[:8]}.json"

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload + "\n", encoding="utf-8")
    print(path)
    return EXIT_OK


def cmd_analyze(args) -> int:
    return EXIT_OK  # Task 10 implements this


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="kdetect",
        description="Linux kernel rootkit detection via cross-view comparison.",
    )

    subparsers = parser.add_subparsers(dest="command")

    capture = subparsers.add_parser("capture", help="Snapshot the live system.")
    capture.add_argument(
        "--out",
        default=None,
        help="Output path. Use '-' for stdout. Default: a generated name in captures/.",
    )
    capture.add_argument(
        "--pretty", action="store_true", help="Indent the JSON output."
    )

    analyze = subparsers.add_parser("analyze", help="Summarise a snapshot file.")
    analyze.add_argument("snapshot", help="Path to a snapshot JSON file.")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_USAGE

    if args.command == "capture":
        return cmd_capture(args)

    if args.command == "analyze":
        return cmd_analyze(args)

    return EXIT_USAGE


def cli_entry() -> None:
    """Console-script entry point named in pyproject.toml."""
    raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
