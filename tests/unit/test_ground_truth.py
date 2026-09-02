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

import pytest

from kdetect.analysis.scoring import analyze
from kdetect.analysis.models import Confidence, FindingKind
from kdetect.models import Snapshot

SNAP = Path(__file__).parent.parent / "fixtures" / "snapshots"

# Phase-3a fixtures are captured on the VM and committed separately (they are
# real root captures, redacted via tools/redact_snapshot.py per L13). Until they
# land, these guards skip; once the JSON is present the assertions run for real.
needs_clean3a = pytest.mark.skipif(
    not (SNAP / "clean-phase3a.json").exists(),
    reason="clean-phase3a.json fixture not captured yet",
)
needs_hooktest = pytest.mark.skipif(
    not (SNAP / "infected-hooktest.json").exists(),
    reason="infected-hooktest.json fixture not captured yet",
)


def _load(name: str) -> Snapshot:
    return Snapshot.from_dict(json.loads((SNAP / name).read_text(encoding="utf-8")))


def test_clean_phase2_has_zero_findings():
    assert analyze(_load("clean-phase2.json")) == []


@needs_clean3a
def test_clean_phase3a_has_zero_findings():
    assert analyze(_load("clean-phase3a.json")) == []


def test_infected_diamorphine_is_one_high_hidden_module():
    findings = analyze(_load("infected-diamorphine.json"))
    hidden = [f for f in findings if f.kind is FindingKind.HIDDEN_MODULE]
    assert len(hidden) == 1
    f = hidden[0]
    assert f.subject == "module diamorphine"
    assert f.confidence is Confidence.HIGH
    assert {"taint", "vmalloc_region", "ftrace_orphan"} <= set(f.channels_agree)


def test_infected_diamorphine_no_false_hidden_process():
    findings = analyze(_load("infected-diamorphine.json"))
    assert not any(f.kind is FindingKind.HIDDEN_PROCESS for f in findings)


@needs_hooktest
def test_infected_hooktest_is_one_high_hidden_module():
    findings = analyze(_load("infected-hooktest.json"))
    hidden = [f for f in findings if f.kind is FindingKind.HIDDEN_MODULE]
    assert len(hidden) == 1
    f = hidden[0]
    assert f.subject == "module kdetect_hooktest"
    assert f.confidence is Confidence.HIGH
    assert {"unexpected_hook", "taint", "vmalloc_region"} <= set(f.channels_agree)


@needs_hooktest
def test_infected_hooktest_no_false_hidden_process():
    findings = analyze(_load("infected-hooktest.json"))
    assert not any(f.kind is FindingKind.HIDDEN_PROCESS for f in findings)


def test_clean_fixtures_have_no_socket_findings():
    for name in ("clean-phase2.json", "clean-phase3a.json"):
        findings = analyze(_load(name))
        kinds = {f.kind for f in findings}
        assert FindingKind.HIDDEN_CONNECTION not in kinds
        assert not any(f.subject.startswith("socket ") for f in findings)
