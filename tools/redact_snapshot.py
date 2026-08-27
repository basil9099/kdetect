#!/usr/bin/env python3
"""Redact a capture before committing it as a test fixture (limitation L13).

`/proc/[pid]/cmdline` is captured verbatim, so a snapshot can carry any
credential a process was handed as an argument -- VS Code Remote-SSH tokens,
database passwords, bearer tokens. A snapshot must therefore be scrubbed before
it lands in the repo as a fixture.

Cross-view findings depend on pids, tgids, and module/hook data -- never on
cmdline -- so replacing every process cmdline wholesale removes the secrets
without changing anything the differ concludes. The output is re-serialised
through the real Snapshot model, which both canonicalises it and proves the
redacted file is still schema-valid.

Usage:
    python tools/redact_snapshot.py <in.json> <out.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from kdetect.models import Snapshot

_PLACEHOLDER = ["[redacted]"]


def redact_dict(snap: dict) -> dict:
    """Replace every process entity's cmdline with a placeholder, in place."""
    for obs in snap.get("observations", []):
        for entity in obs.get("entities", {}).values():
            if isinstance(entity, dict) and "cmdline" in entity:
                entity["cmdline"] = list(_PLACEHOLDER)
    return snap


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: redact_snapshot.py <in.json> <out.json>", file=sys.stderr)
        return 2
    raw = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    snapshot = Snapshot.from_dict(redact_dict(raw))     # also validates schema
    Path(argv[2]).write_text(snapshot.to_json(pretty=True) + "\n", encoding="utf-8")
    print(argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
