"""Ground-truth regression tests (spec §9).

Two paired real captures anchor the differ to reality:

- clean-phase2.json  - a full root capture from the clean-baseline VM. It MUST
  produce zero findings. This is the false-positive guard: the ~90-thread
  class, the sysfs-built-in class, and the kallsyms [bpf] class must all stay
  silent on a real machine, and stay silent under future refactoring.
- infected-diamorphine.json - a capture taken with Diamorphine loaded and a PID
  hidden. Added in the infected half of the ground-truth run; asserts the
  differ actually detects a real rootkit.

Both fixtures are redacted of session secrets before commit (limitation L13).
"""

import json
from pathlib import Path

from kdetect.analysis.crossview import diff_all
from kdetect.models import Snapshot

SNAP = Path(__file__).parent.parent / "fixtures" / "snapshots"


def _load(name: str) -> Snapshot:
    return Snapshot.from_dict(json.loads((SNAP / name).read_text(encoding="utf-8")))


def test_clean_phase2_has_zero_findings():
    # The single most important behaviour: a detector that fires on a clean
    # machine is worse than none. A root capture with every channel live still
    # yields nothing, because threads fold to their leader, sysfs built-ins are
    # not in /proc/modules, taint is clear, and ftrace is a subset of the
    # listing.
    assert diff_all(_load("clean-phase2.json")) == []
