#!/usr/bin/env python3
"""Redact a capture before committing it as a test fixture (L13).

Thin wrapper over kdetect.reporting.redact; see that module and `kdetect redact`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from kdetect.models import Snapshot
from kdetect.reporting.redact import redact_snapshot


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: redact_snapshot.py <in.json> <out.json>", file=sys.stderr)
        return 2
    raw = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    snapshot = Snapshot.from_dict(redact_snapshot(raw))
    Path(argv[2]).write_text(snapshot.to_json(pretty=True) + "\n", encoding="utf-8")
    print(argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
