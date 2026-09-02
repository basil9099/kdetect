import json
from pathlib import Path

from kdetect.analysis.models import Suspect
from kdetect.analysis.signals import (
    signals_modules, signals_hooks, signals_processes, signals_baseline, all_signals,
)
from kdetect.models import Snapshot

SNAP = Path(__file__).parent.parent / "fixtures" / "snapshots"


def _load(name):
    return Snapshot.from_dict(json.loads((SNAP / name).read_text(encoding="utf-8")))


def test_clean_yields_no_signals():
    assert all_signals(_load("clean-phase2.json")) == []
    assert all_signals(_load("clean-phase3a.json")) == []


def test_diamorphine_module_signals_include_named_and_anonymous():
    sigs = signals_modules(_load("infected-diamorphine.json"))
    channels = {s.channel for s in sigs}
    assert "taint" in channels and "vmalloc_region" in channels
    assert "ftrace_orphan" in channels
    # taint/region are anonymous; ftrace_orphan names the module
    anon = {s.channel for s in sigs if s.suspect.name is None}
    named = {s.suspect.name for s in sigs if s.channel == "ftrace_orphan"}
    assert anon == {"taint", "vmalloc_region"}
    assert "diamorphine" in named


def test_hooktest_hook_signal_names_owner_module():
    sigs = signals_hooks(_load("infected-hooktest.json"))
    assert len(sigs) == 1
    s = sigs[0]
    assert s.channel == "unexpected_hook"
    assert s.suspect == Suspect("module", "kdetect_hooktest")
    assert s.evidence["function"] == "__x64_sys_newuname"


def test_baseline_drift_emits_added_modules_only():
    cur = _load("infected-hooktest.json")
    base = _load("clean-phase3a.json")
    sigs = signals_baseline(cur, base)
    assert all(s.channel == "baseline_drift" for s in sigs)
    names = {s.suspect.name for s in sigs}
    assert "kdetect_hooktest" in names          # newly loaded module drifted
    assert all(s.suspect.name is not None for s in sigs)   # named, added only
