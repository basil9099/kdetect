import json
from pathlib import Path
from kdetect.reporting.redact import redact_snapshot
from kdetect.models import Snapshot

SNAP = Path(__file__).parent.parent / "fixtures" / "snapshots"

def test_redacts_every_cmdline():
    raw = json.loads((SNAP / "clean-phase2.json").read_text(encoding="utf-8"))
    out = redact_snapshot(raw)
    cmds = [e.get("cmdline") for o in out["observations"]
            for e in o.get("entities", {}).values() if "cmdline" in e]
    assert cmds and all(c == ["[redacted]"] for c in cmds)

def test_redacted_snapshot_still_loads():
    raw = json.loads((SNAP / "clean-phase2.json").read_text(encoding="utf-8"))
    Snapshot.from_dict(redact_snapshot(raw))     # must not raise

def test_no_cmdline_is_a_noop():
    snap = {"observations": [{"entities": {"1": {"inode": 5}}}]}
    assert redact_snapshot(snap) == snap
