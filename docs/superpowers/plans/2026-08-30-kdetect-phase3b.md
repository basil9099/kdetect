# kdetect Phase 3b — Per-Suspect Scoring & Cross-Pass Composition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the analysis layer into a two-stage detect → score pipeline so corroboration is counted per suspect and composes across passes, turning the scattered per-channel findings for one hidden module into a single composed verdict.

**Architecture:** Pure detectors emit `Signal`s (channel + suspect + dissent + evidence) with no confidence judgment; a single pure `score()` groups signals by suspect, attributes anonymous signals to a named suspect when exactly one module is hidden, counts distinct channels for per-suspect confidence, and emits one `Finding` per suspect. Build the new pipeline alongside the old, cut the CLI over, then delete the old differ — the suite stays green at every task.

**Tech Stack:** Python 3.11+ (lab VM is 3.11), pytest, stdlib only. No new dependencies, no new collectors.

**Spec:** `docs/superpowers/specs/2026-08-30-kdetect-phase3b-design.md` (read it alongside this plan; principles P8–P9, the anonymous-attribution rule, and the retired/added `FindingKind`s are argued there and cited by task).

## Global Constraints

- **P8 — detectors observe, the scorer concludes.** A detector returns `list[Signal]` and never constructs a `Finding` or a `Confidence`. All confidence and composition lives in `score()`.
- **P9 — confidence is a per-suspect count of distinct channels.** No weights. `_confidence`: 1 → LOW, 2 → MEDIUM, ≥3 → HIGH (unchanged from phase 2).
- **P1/P5 — evidence only, and every finding cites it.** `Signal.evidence` and the composed `Finding.evidence` (keyed by channel) hold the exact snapshot values behind the conclusion.
- **Determinism.** Signal lists and findings sort deterministically; `score()` on the same signals gives byte-identical output. Group iteration is over sorted suspects.
- **Stdlib only.** No new runtime dependency (`cryptography` from 3a stays; nothing added).
- **Python 3.11 compatible (L20).** No multi-line expressions inside f-string replacement fields (that is a 3.12-only feature and a SyntaxError on the VM). The `tests/unit/test_python311_compat.py` guard enforces this — keep it green.
- **Capability-gated tests, not OS-gated.** All analysis tests are pure and run on Windows with the VM off (V1). Only `@needs_procfs` live-capture tests need Linux.
- **Exit codes unchanged:** 0 ok, 1 error, 2 usage, 3 = any finding.
- **Fixtures do not change.** `clean-phase2.json`, `clean-phase3a.json`, `infected-diamorphine.json`, `infected-hooktest.json` are reused as-is; only assertions about them change.
- **Angus commits.** During subagent execution, work on a feature branch (e.g. `phase-3b`) where subagents commit per task and Angus merges (as in phase 3a). For inline/manual execution, stage files and let Angus commit. Never `git push` from the VM while a module is loaded.

---

## File Structure

**Create:**
- `src/kdetect/analysis/signals.py` — the detectors: `_observations`, `_module_ids`, `signals_modules`, `signals_hooks`, `signals_processes`, `signals_baseline`, `all_signals`. Each returns `list[Signal]`.
- `src/kdetect/analysis/scoring.py` — `score(signals) -> list[Finding]`, `_confidence`, `_compose`, `_classify`, and the top-level `analyze(snapshot, baseline=None) -> list[Finding]`.
- Tests: `tests/unit/test_signals.py`, `tests/unit/test_scoring.py`.

**Modify:**
- `src/kdetect/analysis/models.py` — add `Suspect`, `Signal`; add `HIDDEN_MODULE`, `SUSPECTED_HIDDEN_MODULE` to `FindingKind`; (Task 5) remove the four retired kinds.
- `src/kdetect/cli.py` — `cmd_analyze` calls `analyze()` from `scoring` instead of `diff_all` from `crossview`.
- `tests/unit/test_ground_truth.py` — assertions move to composed findings.
- `tests/integration/test_phase3a_live.py` — swap `diff_all` import for `analyze`.
- `tests/unit/test_finding_model.py` — drop references to retired kinds.

**Delete (Task 5):**
- `src/kdetect/analysis/crossview.py`, `src/kdetect/analysis/baseline_diff.py`.
- `tests/unit/test_diff_modules.py`, `tests/unit/test_diff_processes.py`, `tests/unit/test_diff_hooks.py`, `tests/unit/test_baseline_diff.py` (their behaviour is covered by `test_signals.py` + `test_scoring.py` + `test_ground_truth.py`).

---

## Task 1: Suspect, Signal, and the new FindingKinds

**Files:**
- Modify: `src/kdetect/analysis/models.py`
- Test: `tests/unit/test_finding_model.py` (extend)

**Interfaces:**
- Consumes: nothing.
- Produces: `Suspect(kind: str, name: str | None)` (frozen); `Signal(channel: str, suspect: Suspect, dissent: str, evidence: dict)` (frozen); `FindingKind.HIDDEN_MODULE == "hidden_module"` and `FindingKind.SUSPECTED_HIDDEN_MODULE == "suspected_hidden_module"`. The four retired kinds stay defined for now (removed in Task 5) so the existing differ and its tests keep importing.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_finding_model.py`:

```python
from kdetect.analysis.models import Suspect, Signal, FindingKind

def test_suspect_and_signal_are_frozen_value_types():
    s = Suspect("module", "diamorphine")
    assert s == Suspect("module", "diamorphine")
    sig = Signal("ftrace_orphan", s, "procfs.modules listing", {"in_listing": False})
    assert sig.channel == "ftrace_orphan"
    assert sig.suspect.name == "diamorphine"
    assert sig.evidence == {"in_listing": False}

def test_anonymous_suspect_has_no_name():
    assert Suspect("module", None).name is None

def test_new_finding_kinds_exist():
    assert FindingKind.HIDDEN_MODULE.value == "hidden_module"
    assert FindingKind.SUSPECTED_HIDDEN_MODULE.value == "suspected_hidden_module"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_finding_model.py -v`
Expected: FAIL with `ImportError: cannot import name 'Suspect'`.

- [ ] **Step 3: Add the types and kinds**

In `src/kdetect/analysis/models.py`, extend the enum:

```python
class FindingKind(str, Enum):
    HIDDEN_PROCESS = "hidden_process"
    HIDDEN_MODULE = "hidden_module"                       # NEW (phase 3b)
    SUSPECTED_HIDDEN_MODULE = "suspected_hidden_module"   # NEW (phase 3b)
    BASELINE_DRIFT = "baseline_drift"
    # Retired in phase 3b Task 5 once the old differ and its tests are gone:
    MODULE_TAINT_MISMATCH = "module_taint_mismatch"
    UNEXPLAINED_MODULE_REGION = "unexplained_module_region"
    FTRACE_ORPHAN_MODULE = "ftrace_orphan_module"
    UNEXPECTED_HOOK = "unexpected_hook"
```

Add the two dataclasses (after the imports, before `Finding`):

```python
@dataclass(frozen=True)
class Suspect:
    """What a Signal is about. name is None for an anonymous hidden-module
    indicator (taint, vmalloc region) that no channel can name (spec §4)."""

    kind: str            # "module" | "process"
    name: str | None


@dataclass(frozen=True)
class Signal:
    """One channel's raw indication that a suspect is anomalous (P8). Carries no
    confidence and no composition -- the scorer draws those (spec §3)."""

    channel: str
    suspect: Suspect
    dissent: str
    evidence: dict
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_finding_model.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/analysis/models.py tests/unit/test_finding_model.py
git commit -m "feat(models): Suspect, Signal, and HIDDEN_MODULE/SUSPECTED_HIDDEN_MODULE kinds"
```

---

## Task 2: The detectors (signals.py)

**Files:**
- Create: `src/kdetect/analysis/signals.py`
- Test: `tests/unit/test_signals.py`

**Interfaces:**
- Consumes: `Suspect`, `Signal` (Task 1); `Snapshot`.
- Produces: `signals_modules(snapshot) -> list[Signal]`; `signals_hooks(snapshot) -> list[Signal]`; `signals_processes(snapshot) -> list[Signal]`; `signals_baseline(current, baseline) -> list[Signal]`; `all_signals(snapshot, baseline=None) -> list[Signal]`. Channels emitted: `taint`, `vmalloc_region`, `ftrace_orphan` (from modules); `unexpected_hook` (from hooks); `syscall_kill`, `direct_status` (from processes); `baseline_drift` (from baseline). Module hiding-signals dissent `"procfs.modules listing"`; process signals dissent `"procfs readdir (all passes)"`; baseline signals dissent `"signed baseline"`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_signals.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_signals.py -v`
Expected: FAIL with `ModuleNotFoundError: kdetect.analysis.signals`.

- [ ] **Step 3: Write the detectors**

Create `src/kdetect/analysis/signals.py`:

```python
"""Detectors: Snapshot -> [Signal] (spec §3, §4).

Pure and I/O-free. Each detector observes one view and records channels; it
draws no confidence and composes nothing (P8). taint and vmalloc_region are
ANONYMOUS (Suspect name None): the taint word and the hash-obfuscated region
addresses (L15) indicate a hidden module exists but cannot name it. ftrace_orphan
and unexpected_hook name their module. The scorer attributes the anonymous ones
(scoring.py).
"""
from __future__ import annotations

from kdetect.analysis.models import Signal, Suspect
from kdetect.models import Snapshot

_MODULE_DISSENT = "procfs.modules listing"
_PROCESS_DISSENT = "procfs readdir (all passes)"
_BASELINE_DISSENT = "signed baseline"


def _observations(snapshot: Snapshot, collector: str):
    return [o for o in snapshot.observations if o.collector == collector]


def _module_ids(snapshot: Snapshot) -> set[str]:
    obs = _observations(snapshot, "procfs.modules")
    return set(obs[0].entity_ids) if obs else set()


def signals_modules(snapshot: Snapshot) -> list[Signal]:
    listings = _observations(snapshot, "procfs.modules")
    evidences = _observations(snapshot, "kernel.module_evidence")
    if not listings or not evidences:
        return []
    listed = set(listings[0].entity_ids)
    ev = evidences[0]
    taint = ev.stats.get("taint", 0)
    markers = (ev.extra or {}).get("listed_taint_markers", 0)
    regions = ev.stats.get("load_module_regions")
    ftrace = (ev.extra or {}).get("ftrace_modules")

    out: list[Signal] = []
    if bool(taint & ((1 << 12) | (1 << 13))) and markers == 0:
        bits = [b for b in (12, 13) if taint & (1 << b)]
        out.append(Signal("taint", Suspect("module", None), _MODULE_DISSENT,
                          {"taint": taint, "listed_taint_markers": markers, "bits": bits}))
    if regions is not None and regions > len(listed):
        out.append(Signal("vmalloc_region", Suspect("module", None), _MODULE_DISSENT,
                          {"load_module_regions": regions, "listed": len(listed),
                           "unaccounted": regions - len(listed)}))
    if ftrace is not None:
        for name in sorted(set(ftrace) - listed):
            out.append(Signal("ftrace_orphan", Suspect("module", name), _MODULE_DISSENT,
                              {"ftrace_module": name, "in_listing": False}))
    return out


def signals_hooks(snapshot: Snapshot) -> list[Signal]:
    hook_obs = _observations(snapshot, "kernel.hooks")
    if not hook_obs:
        return []
    hooks = hook_obs[0]
    listed = _module_ids(snapshot)
    out: list[Signal] = []
    for key in hooks.entity_ids:
        ent = hooks.entities[key]
        # Orphan only: callback attributes to a named module not in the listing
        # (spec §4). owner_module None (core kernel / kprobe) is not orphaned.
        if ent.owner_module is not None and ent.owner_module not in listed:
            out.append(Signal("unexpected_hook", Suspect("module", ent.owner_module),
                              _MODULE_DISSENT,
                              {"function": ent.function, "hook_type": ent.hook_type,
                               "callback": ent.callback, "owner_module": ent.owner_module}))
    return sorted(out, key=lambda s: (s.suspect.name or "", s.evidence["function"]))


def signals_processes(snapshot: Snapshot) -> list[Signal]:
    procfs = _observations(snapshot, "procfs.processes")
    sweeps = _observations(snapshot, "syscall_sweep.processes")
    if not procfs or not sweeps:
        return []
    listed: set[int] = set()
    for obs in procfs:
        listed |= set(obs.entity_ids)
    sweep = sweeps[0]
    out: list[Signal] = []
    reported: set[int] = set()
    for task_id in sweep.entity_ids:
        ent = sweep.entities[task_id]
        if not ent.status_readable:
            continue                       # no reliable tgid; treated as vanished
        tgid = ent.tgid
        if tgid in listed or tgid in reported:
            continue
        reported.add(tgid)
        evidence = {
            "tgid": tgid, "seen_by_sweep": True, "status_readable": True,
            "in_procfs_passes": sorted(o.pass_ or "?" for o in procfs
                                       if tgid in set(o.entity_ids)),
        }
        suspect = Suspect("process", str(tgid))
        # Two independent reads bypassing readdir -> two channels -> MEDIUM.
        out.append(Signal("syscall_kill", suspect, _PROCESS_DISSENT, dict(evidence)))
        out.append(Signal("direct_status", suspect, _PROCESS_DISSENT, dict(evidence)))
    return out


def signals_baseline(current: Snapshot, baseline: Snapshot) -> list[Signal]:
    now = _module_ids(current)
    was = _module_ids(baseline)
    # Additions are the signal; removals are benign (a rootkit adds capability).
    return [Signal("baseline_drift", Suspect("module", name), _BASELINE_DISSENT,
                   {"direction": "added"})
            for name in sorted(now - was)]


def all_signals(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Signal]:
    sigs = signals_processes(snapshot) + signals_modules(snapshot) + signals_hooks(snapshot)
    if baseline is not None:
        sigs += signals_baseline(snapshot, baseline)
    return sigs
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_signals.py -v`
Expected: PASS (4 tests). Then the full unit suite to confirm no regression (the old differ is untouched):
Run: `python -m pytest tests/unit -q`
Expected: all pass/skip as before, plus the new tests.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/analysis/signals.py tests/unit/test_signals.py
git commit -m "feat(analysis): signal detectors (modules, hooks, processes, baseline)"
```

---

## Task 3: The scorer (scoring.py)

**Files:**
- Create: `src/kdetect/analysis/scoring.py`
- Test: `tests/unit/test_scoring.py`

**Interfaces:**
- Consumes: `Signal`, `Suspect`, `Finding`, `FindingKind`, `Confidence` (models); `all_signals` (Task 2); `Snapshot`.
- Produces: `score(signals: list[Signal]) -> list[Finding]`; `analyze(snapshot, baseline=None) -> list[Finding]`. Confidence via distinct-channel count (`_confidence`). One finding per suspect; anonymous module signals fold into the single hidden-named module when exactly one exists, else become one `SUSPECTED_HIDDEN_MODULE`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_scoring.py`:

```python
from kdetect.analysis.models import Signal, Suspect, FindingKind, Confidence
from kdetect.analysis.scoring import score

def _mod(channel, name, **ev):
    return Signal(channel, Suspect("module", name), "procfs.modules listing", ev or {})

def test_empty_signals_no_findings():
    assert score([]) == []

def test_one_hidden_module_folds_anonymous_to_high():
    sigs = [
        _mod("unexpected_hook", "kdetect_hooktest", function="__x64_sys_newuname"),
        _mod("taint", None, bits=[12, 13]),
        _mod("vmalloc_region", None, unaccounted=1),
    ]
    findings = score(sigs)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.HIDDEN_MODULE
    assert f.subject == "module kdetect_hooktest"
    assert f.confidence is Confidence.HIGH          # 3 distinct channels
    assert set(f.channels_agree) == {"unexpected_hook", "taint", "vmalloc_region"}

def test_two_hidden_modules_do_not_absorb_anonymous():
    sigs = [
        _mod("ftrace_orphan", "modA"),
        _mod("unexpected_hook", "modB", function="x"),
        _mod("taint", None, bits=[12]),
    ]
    findings = score(sigs)
    kinds = {f.subject: f for f in findings}
    # each named module scores on its own channel only (LOW), and the anonymous
    # taint becomes a separate SUSPECTED_HIDDEN_MODULE rather than being guessed
    assert kinds["module modA"].confidence is Confidence.LOW
    assert kinds["module modB"].confidence is Confidence.LOW
    susp = [f for f in findings if f.kind is FindingKind.SUSPECTED_HIDDEN_MODULE]
    assert len(susp) == 1 and susp[0].subject == "unattributed hidden module"

def test_baseline_only_module_is_low_drift_not_hidden():
    findings = score([_mod("baseline_drift", "cfg80211", direction="added")])
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.BASELINE_DRIFT
    assert findings[0].confidence is Confidence.LOW

def test_process_two_channels_is_medium():
    p = Suspect("process", "1234")
    sigs = [Signal("syscall_kill", p, "procfs readdir (all passes)", {"tgid": 1234}),
            Signal("direct_status", p, "procfs readdir (all passes)", {"tgid": 1234})]
    findings = score(sigs)
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.HIDDEN_PROCESS
    assert findings[0].confidence is Confidence.MEDIUM
    assert findings[0].subject == "pid 1234"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_scoring.py -v`
Expected: FAIL with `ModuleNotFoundError: kdetect.analysis.scoring`.

- [ ] **Step 3: Write the scorer**

Create `src/kdetect/analysis/scoring.py`:

```python
"""The scorer: [Signal] -> [Finding] (spec §5). Pure.

Groups signals by suspect, attributes anonymous module signals to the single
hidden-named module when exactly one exists, counts distinct channels per suspect
for confidence (P9), and emits one composed Finding per suspect. All conclusions
live here (P8); detectors only observe.
"""
from __future__ import annotations

from kdetect.analysis.models import (
    Confidence, Finding, FindingKind, Signal, Suspect,
)
from kdetect.analysis.signals import all_signals
from kdetect.models import Snapshot

#: Channels that indicate concealment. Everything except baseline_drift, which
#: alone means only "new since the baseline", not "hidden".
_HIDING = {"taint", "vmalloc_region", "ftrace_orphan", "unexpected_hook",
           "syscall_kill", "direct_status"}
#: Named hiding channels -- the ones that can make a module "hidden_named" and so
#: attract the anonymous taint/region signals.
_HIDING_NAMED = {"ftrace_orphan", "unexpected_hook"}


def _confidence(n: int) -> Confidence:
    return {1: Confidence.LOW, 2: Confidence.MEDIUM}.get(n, Confidence.HIGH)


def _classify(suspect: Suspect, channels: list[str]) -> tuple[FindingKind, str, str]:
    if suspect.kind == "process":
        return (FindingKind.HIDDEN_PROCESS, f"pid {suspect.name}",
                f"pid {suspect.name} answers the syscall sweep but appears in no "
                f"/proc readdir pass")
    if suspect.name is None:
        return (FindingKind.SUSPECTED_HIDDEN_MODULE, "unattributed hidden module",
                "hidden-module indicators fired but no channel can name the module")
    if any(c in _HIDING for c in channels):
        return (FindingKind.HIDDEN_MODULE, f"module {suspect.name}",
                f"module {suspect.name} is concealed from /proc/modules but named "
                f"by {', '.join(channels)}")
    return (FindingKind.BASELINE_DRIFT, f"module {suspect.name}",
            f"module {suspect.name} is loaded now but was absent from the baseline")


def _compose(suspect: Suspect, sigs: list[Signal]) -> Finding:
    ordered = sorted(sigs, key=lambda s: s.channel)
    channels = sorted({s.channel for s in ordered})
    dissent = sorted({s.dissent for s in ordered})
    evidence: dict = {}
    for s in ordered:
        evidence.setdefault(s.channel, []).append(s.evidence)
    kind, subject, summary = _classify(suspect, channels)
    return Finding(kind, subject, _confidence(len(channels)),
                   channels, dissent, evidence, summary)


def score(signals: list[Signal]) -> list[Finding]:
    named = [s for s in signals if s.suspect.name is not None]
    anon = [s for s in signals if s.suspect.name is None]

    groups: dict[Suspect, list[Signal]] = {}
    for s in named:
        groups.setdefault(s.suspect, []).append(s)

    hidden_named = {
        susp.name for susp, sigs in groups.items()
        if susp.kind == "module" and any(s.channel in _HIDING_NAMED for s in sigs)
    }

    # Attribute anonymous module signals only when exactly one module is hidden
    # (spec §5); with 0 or >=2 they cannot be pinned to a name (L15/L21).
    if len(hidden_named) == 1 and anon:
        target = Suspect("module", next(iter(hidden_named)))
        groups.setdefault(target, []).extend(anon)
        anon = []

    findings = [
        _compose(susp, groups[susp])
        for susp in sorted(groups, key=lambda s: (s.kind, s.name or ""))
    ]
    if anon:
        findings.append(_compose(Suspect("module", None), anon))
    return sorted(findings, key=lambda f: f.subject)


def analyze(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Finding]:
    return score(all_signals(snapshot, baseline))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_scoring.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/analysis/scoring.py tests/unit/test_scoring.py
git commit -m "feat(analysis): per-suspect scorer with anonymous attribution"
```

---

## Task 4: Cut the CLI and ground-truth over to analyze()

**Files:**
- Modify: `src/kdetect/cli.py`, `tests/integration/test_phase3a_live.py`, `tests/unit/test_ground_truth.py`

**Interfaces:**
- Consumes: `analyze` (Task 3).
- Produces: `analyze()` is the analysis entry point everywhere. The old `crossview.diff_all` is now unused (deleted in Task 5). Composed findings assert as one `HIDDEN_MODULE` per hidden module.

- [ ] **Step 1: Point the CLI at analyze()**

In `src/kdetect/cli.py`, change the import:

```python
from kdetect.analysis.scoring import analyze
```
(remove `from kdetect.analysis.crossview import diff_all`)

and in `cmd_analyze` change the call:

```python
    findings = analyze(snapshot, baseline)
```
(was `findings = diff_all(snapshot, baseline)`)

- [ ] **Step 2: Point the live integration test at analyze()**

In `tests/integration/test_phase3a_live.py`, replace `from kdetect.analysis.crossview import diff_all` with `from kdetect.analysis.scoring import analyze`, and every `diff_all(` call with `analyze(`. The `test_clean_phase3a_has_no_findings`-style assertions stay `== []`; any `unexpected_hook` kind assertion becomes `hidden_module` (see Step 3 for the mapping).

- [ ] **Step 3: Rewrite the ground-truth assertions**

Replace the phase-2 and phase-3a assertion bodies in `tests/unit/test_ground_truth.py` (import `analyze` from `kdetect.analysis.scoring` instead of `diff_all` from crossview). The fixtures are unchanged; only the expected shape changes — one composed finding per hidden module:

```python
from kdetect.analysis.scoring import analyze
from kdetect.analysis.models import Confidence, FindingKind

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
```

Delete the old per-channel assertion functions in this file (`test_infected_diamorphine_detects_hidden_module`, `test_infected_ftrace_channel_names_diamorphine`, `test_infected_module_findings_are_high_confidence`, `test_infected_capture_raises_no_false_hidden_process`, `test_infected_hooktest_detects_orphan_hook_and_module`, `test_infected_hooktest_hook_names_the_unlisted_module`, `test_infected_hooktest_no_false_hidden_process`) — they are replaced by the composed versions above. Keep the `needs_clean3a` / `needs_hooktest` skip marks and `_load`.

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/unit/test_ground_truth.py tests/unit/test_analyze.py -q`
Expected: PASS. The composed findings match the fixtures' real evidence.
Run: `python -m pytest tests/unit -q`
Expected: all pass (the old differ tests still pass — crossview/baseline_diff still exist until Task 5).

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/cli.py tests/integration/test_phase3a_live.py tests/unit/test_ground_truth.py
git commit -m "feat(cli): analyze() replaces diff_all; ground-truth asserts composed findings"
```

---

## Task 5: Delete the old differ and retire its kinds

**Files:**
- Delete: `src/kdetect/analysis/crossview.py`, `src/kdetect/analysis/baseline_diff.py`, `tests/unit/test_diff_modules.py`, `tests/unit/test_diff_processes.py`, `tests/unit/test_diff_hooks.py`, `tests/unit/test_baseline_diff.py`
- Modify: `src/kdetect/analysis/models.py`, `tests/unit/test_finding_model.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `FindingKind` no longer defines `MODULE_TAINT_MISMATCH`, `UNEXPLAINED_MODULE_REGION`, `FTRACE_ORPHAN_MODULE`, `UNEXPECTED_HOOK`. Nothing imports `crossview` or `baseline_diff`.

- [ ] **Step 1: Confirm nothing references what you're about to delete**

Run: `grep -rn "crossview\|baseline_diff\|diff_all\|MODULE_TAINT_MISMATCH\|UNEXPLAINED_MODULE_REGION\|FTRACE_ORPHAN_MODULE\|UNEXPECTED_HOOK" src tests`
Expected: only the four files being deleted and the four `FindingKind` lines in `models.py`. If anything else appears (a missed test/import), fix it before deleting — that is a real gap.

- [ ] **Step 2: Delete the old files**

```bash
git rm src/kdetect/analysis/crossview.py src/kdetect/analysis/baseline_diff.py \
       tests/unit/test_diff_modules.py tests/unit/test_diff_processes.py \
       tests/unit/test_diff_hooks.py tests/unit/test_baseline_diff.py
```

- [ ] **Step 3: Remove the retired kinds**

In `src/kdetect/analysis/models.py`, delete the four retired members so `FindingKind` is exactly:

```python
class FindingKind(str, Enum):
    HIDDEN_PROCESS = "hidden_process"
    HIDDEN_MODULE = "hidden_module"
    SUSPECTED_HIDDEN_MODULE = "suspected_hidden_module"
    BASELINE_DRIFT = "baseline_drift"
```

If `tests/unit/test_finding_model.py` still names any retired kind, remove those references.

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest -q`
Expected: all green (unit passing, integration skipped on Windows, `test_python311_compat.py` green). No import errors, no references to deleted names.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: delete crossview/baseline_diff differ and retire per-channel kinds"
```

---

## Task 6: Docs — L21 and detection-methods update

**Files:**
- Modify: `docs/limitations.md`, `docs/detection-methods.md`, `docs/architecture.md`

**Interfaces:**
- Consumes: nothing.
- Produces: L21 recorded; detection docs describe the detect→score model.

- [ ] **Step 1: Add L21 to `docs/limitations.md`**

Under the phase-3 section, append (verbatim from spec §12):

```markdown
**L21 — Anonymous hidden-module signals cannot be attributed when more than one
module is hidden.** The taint word is a single global bit set, and vmalloc region
addresses are hash-obfuscated (L15), so `taint` and `vmalloc_region` indicate
*that* a module is hidden, never *which*. The scorer folds them into a named
suspect only when exactly one module is hidden; with two or more hidden modules
they collapse into a single `suspected_hidden_module` finding that counts the
anonymous channels but names no module.
```

- [ ] **Step 2: Update `docs/detection-methods.md` and `docs/architecture.md`**

In `docs/detection-methods.md`, add a short "Scoring" subsection (or amend the existing cross-view section) stating: findings are composed per suspect; confidence is the count of distinct corroborating channels across passes; the retired per-channel kinds are now channels of `hidden_module`. In `docs/architecture.md`, replace any `crossview.py`/`diff_all` description with the `signals.py` → `scoring.py` (`analyze`) two-stage pipeline. Cite the phase-3b spec.

- [ ] **Step 3: Commit**

```bash
git add docs/limitations.md docs/detection-methods.md docs/architecture.md
git commit -m "docs: L21 and detect->score scoring model (phase 3b)"
```

---

## Self-Review

**Spec coverage:**
- §3 architecture (detect → score, file layout) → Tasks 2–5.
- §4 Signal/Suspect model + detector table → Task 1 (types), Task 2 (detectors). Anonymous `name=None` → Task 2 taint/region.
- §5 scoring, attribution, confidence, worked examples → Task 3 (`score`, `_compose`, `_classify`) + Task 4 (ground-truth assertions that ARE the worked examples).
- §6 Finding kinds (new + retired) → Task 1 (add), Task 5 (retire).
- §7 process view, two-channel MEDIUM, HIGH deferred → Task 2 `signals_processes` + Task 3 test.
- §8 CLI unchanged in shape → Task 4.
- §9 testing/migration + acceptance criteria → Tasks 2–5 (criterion 1 clean-zero → `test_signals`/`test_ground_truth`; 2/3 composed HIGH → Task 4; 4 two-hidden fallback → Task 3; 5 process MEDIUM → Task 3; 6 3.11 guard → Global Constraints, unchanged).
- §12 L21 → Task 6.

**Deviations from the spec, flagged:**
1. **`signals_processes` skips unreadable-status tasks** rather than emitting a "syscall_kill only → LOW" case as §7's prose muses. Reason: the sweep derives the `tgid` from the status read, so an unreadable-status task has no reliable tgid to key a suspect by — the old (validated) differ skipped it too. In practice a hidden pid answering the sweep has a readable status, so the two-channel MEDIUM path is the real one; the kill-only case is vestigial. Behaviour matches phase 2 exactly.
2. **Removed-since-baseline modules produce no finding** (3a emitted a LOW `baseline_drift` for them). Spec §4 says removals are "informational only"; the scorer only consumes signals, so dropping them is the simplest faithful reading. A rootkit adds capability, so a removed module is not a detection signal. Noted for Angus; trivially reversible by emitting a `baseline_drift` removed-signal if he wants it retained.

**Placeholder scan:** none — every code and test step is complete. The only doc step with prose latitude (Task 6 Step 2) names exactly which sections to change and what to say.

**Type consistency:** `Suspect(kind, name)` and `Signal(channel, suspect, dissent, evidence)` are identical across Tasks 1/2/3. `signals_*`/`all_signals` signatures match between Task 2 and Task 3's `analyze`. `score`/`analyze` signatures match between Task 3 and Task 4's CLI call. Channel strings (`taint`, `vmalloc_region`, `ftrace_orphan`, `unexpected_hook`, `syscall_kill`, `direct_status`, `baseline_drift`) are consistent between `signals.py` (emit) and `scoring.py` (`_HIDING`/`_HIDING_NAMED` sets). `FindingKind` members used in tests (`HIDDEN_MODULE`, `SUSPECTED_HIDDEN_MODULE`, `HIDDEN_PROCESS`, `BASELINE_DRIFT`) all exist after Task 1 and survive Task 5.

---

## Execution Handoff

Plan complete. Save location: `docs/superpowers/plans/2026-08-30-kdetect-phase3b.md`.
