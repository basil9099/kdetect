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

import copy
import json
from pathlib import Path

import pytest

from kdetect.analysis.scoring import analyze
from kdetect.analysis.models import Confidence, FindingKind
from kdetect.cli import main
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


def _phantom_row_raw() -> dict:
    """infected-hooktest.json with one phantom /proc/modules row injected.

    The listing's real names are split across ftrace and kallsyms so neither
    channel alone covers the listing -- the phantom sits in neither half, so it
    is the only uncorroborated name and the note guard (which needs EVERY module
    uncorroborated) stays out of the way.
    """
    raw = copy.deepcopy(json.loads(
        (SNAP / "infected-hooktest.json").read_text(encoding="utf-8")))

    def obs(collector):
        return next(o for o in raw["observations"] if o["collector"] == collector)

    mods = obs("procfs.modules")
    original = list(mods["entity_ids"])
    mods["entities"]["phantom_mod"] = {
        "name": "phantom_mod", "size": 1, "refcount": 0, "dependents": [],
        "state": "Live", "base_addr": "0x0", "taint": None,
    }
    mods["entity_ids"] = sorted(original + ["phantom_mod"])

    ev = obs("kernel.module_evidence")
    ev["stats"]["ftrace_available"] = True
    ev["extra"]["ftrace_modules"] = original[:1]
    hooks = obs("kernel.hooks")
    hooks["stats"]["kallsyms_available"] = True
    hooks["extra"]["kallsyms_modules"] = original[1:]
    return raw


@needs_hooktest
def test_a_phantom_modules_row_reaches_analyze_as_an_over_listed_finding():
    """Spec section 8.1 criterion 6, through analyze() rather than the detector.

    Every other over_listed test calls signals_over_listed directly or
    hand-builds Signals and calls score, so the whole channel was unwired-able
    with a green suite: deleting `+ signals_over_listed(snapshot)` from
    all_signals (src/kdetect/analysis/signals.py) left 390 passed, 15 skipped.
    This test is the one that fails on that deletion.
    """
    findings = analyze(Snapshot.from_dict(_phantom_row_raw()))
    over = [f for f in findings if f.kind is FindingKind.OVER_LISTED_MODULE]
    assert len(over) == 1
    f = over[0]
    assert f.subject == "module phantom_mod"
    assert f.confidence is Confidence.LOW          # provisional, spec section 5.2
    assert f.channels_agree == ["over_listed"]


@needs_hooktest
def test_a_phantom_modules_row_is_visible_through_the_analyze_command(
        tmp_path, capsys):
    """The CLI half of the same wiring: exit 3 AND the finding on stdout.

    rc == 3 alone is vacuous here -- this capture already yields a HIGH
    hidden_module -- so the over-listed finding must be named in the output.
    """
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(_phantom_row_raw()), encoding="utf-8")

    rc = main(["analyze", str(snap)])
    out = capsys.readouterr().out
    assert rc == 3, out
    assert "over_listed_module   module phantom_mod" in out


@needs_clean3a
def test_clean_fixtures_have_no_socket_findings():
    for name in ("clean-phase2.json", "clean-phase3a.json"):
        findings = analyze(_load(name))
        # No socket-derived finding (no socket suspect, no socket_visible-only
        # process finding) on a clean capture.
        assert not any(f.subject.startswith("socket ") for f in findings)
