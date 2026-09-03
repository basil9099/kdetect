# kdetect Phase 4b — Reporting, IOCs & Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `report` command (Markdown + JSON), IOC extraction, and a first-class `redact` command over the existing `analyze()` findings, plus `comm` on the sweep so a hidden process has a name — making kdetect's detections shareable (v1.0).

**Architecture:** A pure reporting layer (`reporting/redact.py`, `iocs.py`, `report.py`) consumes `analyze()`'s `Finding`s and the snapshot; the CLI wires `report`/`redact`. One small detection touch threads `comm` from the sweep's `/proc/<tid>/status` read into `SweepEntity` and the `hidden_process` finding's evidence. Additive throughout — no deletions, schema stays 1.1.

**Tech Stack:** Python 3.11+ (lab VM is 3.11), pytest, stdlib only (Markdown is string building; JSON + redaction are stdlib).

**Spec:** `docs/superpowers/specs/2026-09-03-kdetect-phase4b-design.md` (read alongside; principle P11, the portable-vs-local IOC line, and the redaction refocus are argued there and cited by task).

## Global Constraints

- **P11 — the report concludes nothing; it presents `analyze`'s findings.** Rendering, IOC extraction, and redaction are pure transforms over `Finding`s (P5) and snapshot facts (P1). No new detection or confidence.
- **P1/P4 — evidence only.** `comm` is a recorded fact on `SweepEntity`; nothing concludes from it (the differ still folds threads by `tgid`).
- **Additive; schema stays 1.1.** `SweepEntity` gains an optional `comm`; a fixture without it loads as `None`. No existing field changes, no deletions.
- **Determinism.** JSON via `json.dumps(..., sort_keys=True, indent=2)`; IOCs deduplicated and sorted by `(type, value)`; Markdown findings most-severe-first with a stable tiebreak.
- **Stdlib only.** No new runtime dependency.
- **Python 3.11 compatible (L20).** No multi-line expressions inside f-string replacement fields; the `tests/unit/test_python311_compat.py` guard enforces it.
- **The report carries no `cmdline`** (spec §7): findings are secret-free and a hidden process has no `ProcessEntity`. Redaction's job is the snapshot-scrub command, not the report.
- **Exit codes:** `report` → 3 when findings present, 0 when none, 1 on error (incl. `BaselineTampered`), 2 usage; `redact` → 0 ok, 1 error. `analyze`/`capture` unchanged.
- **Capability-gated tests.** All new tiers are pure and run on Windows with the VM off (V1).
- **Angus commits.** During subagent execution, work on a feature branch (`phase-4b`) where subagents commit per task and Angus merges. Never `git push` from the VM while a module is loaded.

---

## File Structure

**Create:**
- `src/kdetect/reporting/redact.py` — `redact_snapshot(dict) -> dict` (cmdline scrub, promoted from `tools/redact_snapshot.py`).
- `src/kdetect/reporting/iocs.py` — `IOC` dataclass + `extract(findings) -> list[IOC]`.
- `src/kdetect/reporting/report.py` — `render_markdown(...)`, `render_json(...)`.
- Tests: `tests/unit/test_redact.py`, `test_iocs.py`, `test_report.py`.

**Modify:**
- `src/kdetect/parsers/procfs.py` — `StatusFields.name`; parse the `Name:` line.
- `src/kdetect/models.py` — `SweepEntity.comm`.
- `src/kdetect/collectors/base.py` — `SignalSource.read_status` (replaces `read_tgid`).
- `src/kdetect/collectors/sources.py` — `LiveSignalSource`/`FixtureSignalSource` `read_status`.
- `src/kdetect/collectors/syscall_sweep.py` — store `comm`.
- `src/kdetect/analysis/signals.py` — `signals_processes` puts `comm` in the `hidden_process` evidence.
- `src/kdetect/cli.py` — `report` + `redact` subcommands; a shared load/baseline helper.
- `tools/redact_snapshot.py` — thin wrapper over `reporting/redact.py`.
- Tests: `test_parse_status.py`, `test_signal_source.py`, `test_collector_sweep.py`, `tests/fixtures/signal-sets/hidden-pid.json`.
- Docs: `docs/limitations.md` (L26), `docs/detection-methods.md`, `docs/architecture.md`, `README.md`.

---

## Task 1: `Name` (comm) in the status parser

**Files:**
- Modify: `src/kdetect/parsers/procfs.py`
- Test: `tests/unit/test_parse_status.py` (extend)

**Interfaces:**
- Consumes: nothing.
- Produces: `StatusFields` gains `name: str | None = None`; `parse_status` sets it from the `Name:` line (None if absent). Uid/Gid/Tgid handling unchanged.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_parse_status.py`:

```python
def test_parse_status_extracts_name():
    text = ("Name:\tevil\nTgid:\t1234\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
    fields = parse_status(text)
    assert fields.name == "evil"
    assert fields.tgid == 1234

def test_parse_status_name_absent_is_none():
    text = ("Tgid:\t1\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
    assert parse_status(text).name is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_parse_status.py -k name -v`
Expected: FAIL — `StatusFields` has no `name` / `AttributeError`.

- [ ] **Step 3: Implement**

In `src/kdetect/parsers/procfs.py`, add the field to `StatusFields`:

```python
@dataclass(frozen=True)
class StatusFields:
    uid: list[int]
    gid: list[int]
    tgid: int
    name: str | None = None
```

In `parse_status`, add a `name` local and a branch, and pass it through:

```python
    uid = None
    gid = None
    tgid = None
    name = None
    ...
            if key == "Uid":
                uid = [int(v) for v in value.split()]
            elif key == "Gid":
                gid = [int(v) for v in value.split()]
            elif key == "Tgid":
                tgid = int(value.strip())
            elif key == "Name":
                name = value.strip()
    ...
    return StatusFields(uid=uid, gid=gid, tgid=tgid, name=name)
```
(`Name:` is not in the required-lines check — it stays optional so existing status fixtures without it still parse.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_parse_status.py -v`
Expected: PASS (existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/parsers/procfs.py tests/unit/test_parse_status.py
git commit -m "feat(parsers): parse Name (comm) from /proc/status"
```

---

## Task 2: `comm` through the sweep (SweepEntity, SignalSource, collector)

**Files:**
- Modify: `src/kdetect/models.py`, `src/kdetect/collectors/base.py`, `src/kdetect/collectors/sources.py`, `src/kdetect/collectors/syscall_sweep.py`, `tests/fixtures/signal-sets/hidden-pid.json`
- Test: `tests/unit/test_signal_source.py` (update), `tests/unit/test_collector_sweep.py` (update), `tests/unit/test_models_roundtrip.py` (extend)

**Interfaces:**
- Consumes: `parse_status(...).name` (Task 1).
- Produces: `SweepEntity(tgid: int, status_readable: bool, comm: str | None = None)`; `SignalSource.read_status(task_id) -> tuple[int, str | None] | None` **replaces** `read_tgid` (returns `(tgid, comm)`, or `None` when status unreadable); `SweepProcessCollector` stores `comm`. Existing `SweepEntity` fixtures without `comm` load as `None`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_models_roundtrip.py`:

```python
def test_sweep_entity_comm_roundtrips():
    from kdetect.models import SweepEntity
    e = SweepEntity(tgid=812, status_readable=True, comm="sshd")
    assert SweepEntity.from_dict(e.to_dict()) == e
    # legacy dict without comm loads as None
    legacy = {"tgid": 812, "status_readable": True}
    assert SweepEntity.from_dict(legacy).comm is None
```

Update `tests/unit/test_collector_sweep.py` — assert the collector records comm (adjust to the file's existing `FixtureSignalSource` usage):

```python
def test_sweep_records_comm():
    from kdetect.collectors.syscall_sweep import SweepProcessCollector
    from kdetect.collectors.sources import FixtureSignalSource
    from pathlib import Path
    fx = Path(__file__).parent.parent / "fixtures" / "signal-sets" / "hidden-pid.json"
    obs = SweepProcessCollector().collect(FixtureSignalSource(fx))
    # the hidden pid in the fixture carries a comm
    hidden = [e for e in obs.entities.values() if e.comm == "evil"]
    assert hidden, "expected a swept entity with comm 'evil'"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_models_roundtrip.py tests/unit/test_collector_sweep.py -v`
Expected: FAIL — `SweepEntity` has no `comm` / `read_status` missing.

- [ ] **Step 3: Add `comm` to `SweepEntity`**

In `src/kdetect/models.py`:

```python
@dataclass(frozen=True)
class SweepEntity:
    tgid: int
    status_readable: bool
    comm: str | None = None

    def to_dict(self) -> dict:
        return {"tgid": self.tgid, "status_readable": self.status_readable,
                "comm": self.comm}

    @classmethod
    def from_dict(cls, d: dict) -> "SweepEntity":
        return cls(tgid=d["tgid"], status_readable=d["status_readable"],
                   comm=d.get("comm"))
```

- [ ] **Step 4: Replace `read_tgid` with `read_status`**

In `src/kdetect/collectors/base.py`, in `SignalSource`:

```python
    @abstractmethod
    def read_status(self, task_id: int) -> tuple[int, str | None] | None:
        """(Tgid, Name) from /proc/<id>/status, or None if it could not be read."""
```
(remove the old `read_tgid` abstractmethod)

In `src/kdetect/collectors/sources.py`, `LiveSignalSource`:

```python
    def read_status(self, task_id: int) -> tuple[int, str | None] | None:
        try:
            with open(f"/proc/{task_id}/status", encoding="utf-8",
                      errors="replace") as fh:
                fields = parse_status(fh.read())
                return (fields.tgid, fields.name)
        except (OSError, ParseError):
            return None
```

`FixtureSignalSource` — read a `comm` map from the fixture and return the pair:

```python
    def __init__(self, path) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._pid_max = data["pid_max"]
        self._alive = sorted(data["alive"])
        self._tgid = {int(k): v for k, v in data["tgid"].items()}
        self._comm = {int(k): v for k, v in data.get("comm", {}).items()}
        self._unreadable = set(data.get("unreadable_status", []))

    def read_status(self, task_id: int) -> tuple[int, str | None] | None:
        if task_id in self._unreadable or task_id not in self._tgid:
            return None
        return (self._tgid[task_id], self._comm.get(task_id))
```

- [ ] **Step 5: Store `comm` in the collector**

In `src/kdetect/collectors/syscall_sweep.py`, replace the `read_tgid` loop:

```python
        entities: dict[int, SweepEntity] = {}
        for task_id in alive:
            res = source.read_status(task_id)
            if res is None:
                entities[task_id] = SweepEntity(
                    tgid=task_id, status_readable=False, comm=None)
            else:
                tgid, comm = res
                entities[task_id] = SweepEntity(
                    tgid=tgid, status_readable=True, comm=comm)
```

Add a `comm` map to `tests/fixtures/signal-sets/hidden-pid.json` giving the hidden pid the comm `"evil"` (match the fixture's existing hidden task id — read the file, add `"comm": {"<hidden_tid>": "evil"}` alongside the `tgid` map). Update any `read_tgid` call in `tests/unit/test_signal_source.py` to `read_status` and its tuple return.

- [ ] **Step 6: Run tests, then commit**

Run: `.venv/Scripts/python.exe -m pytest tests/unit -q`
Expected: all pass (the `read_tgid`→`read_status` rename has exactly one production caller, the sweep collector; the fixture + source tests are updated here).

```bash
git add src/kdetect/models.py src/kdetect/collectors/base.py src/kdetect/collectors/sources.py src/kdetect/collectors/syscall_sweep.py tests/fixtures/signal-sets/hidden-pid.json tests/unit/test_models_roundtrip.py tests/unit/test_collector_sweep.py tests/unit/test_signal_source.py
git commit -m "feat(collectors): comm on SweepEntity via read_status"
```

---

## Task 3: `comm` into the hidden_process finding evidence

**Files:**
- Modify: `src/kdetect/analysis/signals.py`
- Test: `tests/unit/test_signals.py` (extend)

**Interfaces:**
- Consumes: `SweepEntity.comm` (Task 2).
- Produces: `signals_processes` adds `"comm"` to the evidence dict of the `syscall_kill`/`direct_status` signals it emits for a hidden tgid.

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_signals.py`:

```python
def test_signals_processes_carries_comm_in_evidence():
    from kdetect.analysis.signals import signals_processes
    procs = Observation(
        collector="procfs.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=[1], entities={}, stats={}, errors=[], pass_="A")
    sweep = Observation(
        collector="syscall_sweep.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.MEDIUM, status=Status.OK, duration_ms=1,
        entity_ids=[31337],
        entities={31337: SweepEntity(tgid=31337, status_readable=True, comm="evil")},
        stats={}, errors=[])
    host = HostFacts("t", "6.1", "x86_64", "b", 1, 100)
    snap = Snapshot(SCHEMA_VERSION, "id", "t", host, CaptureMeta("0.1.0", 0),
                    [procs, sweep])
    sigs = signals_processes(snap)
    assert sigs and all(s.evidence.get("comm") == "evil" for s in sigs)
```
(import `SweepEntity` in the test file if not already imported.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_signals.py -k comm -v`
Expected: FAIL — evidence has no `comm`.

- [ ] **Step 3: Implement**

In `src/kdetect/analysis/signals.py`, in `signals_processes`, add `comm` to the evidence dict built per hidden tgid:

```python
        evidence = {
            "tgid": tgid, "seen_by_sweep": True, "status_readable": True,
            "comm": ent.comm,
            "in_procfs_passes": sorted(o.pass_ or "?" for o in procfs
                                       if tgid in set(o.entity_ids)),
        }
```
(`ent` is the `SweepEntity` already in scope in that loop.)

- [ ] **Step 4: Run tests, then commit**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_signals.py -v`
Expected: PASS.

```bash
git add src/kdetect/analysis/signals.py tests/unit/test_signals.py
git commit -m "feat(analysis): carry comm into hidden_process evidence"
```

---

## Task 4: Redaction module + `kdetect redact`-ready

**Files:**
- Create: `src/kdetect/reporting/redact.py`
- Modify: `tools/redact_snapshot.py`
- Test: `tests/unit/test_redact.py`

**Interfaces:**
- Consumes: `Snapshot` (for round-trip validation).
- Produces: `redact_snapshot(snap: dict) -> dict` — replaces every process entity's `cmdline` with `["[redacted]"]`, in place, returning the dict.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_redact.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_redact.py -v`
Expected: FAIL — `ModuleNotFoundError: kdetect.reporting.redact`.

- [ ] **Step 3: Write the module**

Create `src/kdetect/reporting/redact.py`:

```python
"""Snapshot redaction for sharing (limitation L13).

/proc/[pid]/cmdline is captured verbatim, so a snapshot can carry credentials a
process was handed as arguments. Cross-view findings never depend on cmdline
(they key on pids/tgids/module/socket data), so replacing every process cmdline
wholesale removes the secrets without changing any conclusion. Reports do not
carry cmdline at all (spec §7); this is for scrubbing a *snapshot* to share.
"""
from __future__ import annotations

_PLACEHOLDER = ["[redacted]"]


def redact_snapshot(snap: dict) -> dict:
    """Replace every process entity's cmdline with a placeholder, in place."""
    for obs in snap.get("observations", []):
        for entity in obs.get("entities", {}).values():
            if isinstance(entity, dict) and "cmdline" in entity:
                entity["cmdline"] = list(_PLACEHOLDER)
    return snap
```

Rewrite `tools/redact_snapshot.py` to delegate (keep its CLI + the `Snapshot` re-serialisation, drop the duplicated logic):

```python
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
```

- [ ] **Step 4: Run tests, then commit**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_redact.py -q`
Expected: PASS (3).

```bash
git add src/kdetect/reporting/redact.py tools/redact_snapshot.py tests/unit/test_redact.py
git commit -m "feat(reporting): redact_snapshot module; tools script delegates to it"
```

---

## Task 5: IOC extraction

**Files:**
- Create: `src/kdetect/reporting/iocs.py`
- Test: `tests/unit/test_iocs.py`

**Interfaces:**
- Consumes: `Finding`, `FindingKind` (`kdetect.analysis.models`).
- Produces: `IOC(type: str, value: str, confidence: str, source_finding: str)` with `to_dict`; `extract(findings: list[Finding]) -> list[IOC]`. Types: `kernel_module`, `hooked_function`, `network_endpoint`, `process_name`. Deduped by `(type, value)`, sorted by `(type, value)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_iocs.py`:

```python
from kdetect.analysis.models import Finding, FindingKind, Confidence
from kdetect.reporting.iocs import IOC, extract

def _f(kind, subject, evidence, conf=Confidence.HIGH):
    return Finding(kind, subject, conf, [], [], evidence, "")

def test_hidden_module_yields_module_and_hook_iocs():
    f = _f(FindingKind.HIDDEN_MODULE, "module diamorphine",
           {"unexpected_hook": [{"function": "__x64_sys_kill"}]})
    iocs = extract([f])
    kinds = {(i.type, i.value) for i in iocs}
    assert ("kernel_module", "diamorphine") in kinds
    assert ("hooked_function", "__x64_sys_kill") in kinds

def test_hidden_process_yields_process_name_and_endpoint():
    f = _f(FindingKind.HIDDEN_PROCESS, "pid 1234",
           {"syscall_kill": [{"comm": "evil"}],
            "socket_visible": [{"state": "ESTABLISHED",
                                "remote": "1.2.3.4:4444", "local": "0.0.0.0:0"}]})
    vals = {(i.type, i.value) for i in extract([f])}
    assert ("process_name", "evil") in vals
    assert ("network_endpoint", "1.2.3.4:4444") in vals

def test_listen_socket_uses_local_and_skips_placeholder():
    f = _f(FindingKind.HIDDEN_PROCESS, "pid 1",
           {"socket_visible": [{"state": "LISTEN",
                                "local": "0.0.0.0:4444", "remote": "0.0.0.0:0"}]})
    vals = {(i.type, i.value) for i in extract([f])}
    assert ("network_endpoint", "0.0.0.0:4444") in vals
    assert all(not v.endswith(":0") for t, v in vals if t == "network_endpoint")

def test_iocs_deduped_and_sorted():
    f1 = _f(FindingKind.HIDDEN_MODULE, "module m", {})
    f2 = _f(FindingKind.HIDDEN_MODULE, "module m", {})
    iocs = extract([f1, f2])
    assert [(i.type, i.value) for i in iocs] == [("kernel_module", "m")]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_iocs.py -v`
Expected: FAIL — `ModuleNotFoundError: kdetect.reporting.iocs`.

- [ ] **Step 3: Write the module**

Create `src/kdetect/reporting/iocs.py`:

```python
"""IOC extraction (spec §6). Pure: [Finding] -> [IOC].

Pulls the PORTABLE indicators out of findings -- a module name, a hooked
syscall, a C2/backdoor endpoint, the malware's own name -- and leaves host-local
artifacts (pids, inodes, region counts) as report context. Concludes nothing new
(P11); every IOC cites the finding it came from.
"""
from __future__ import annotations

from dataclasses import dataclass

from kdetect.analysis.models import Finding, FindingKind


@dataclass(frozen=True)
class IOC:
    type: str
    value: str
    confidence: str
    source_finding: str

    def to_dict(self) -> dict:
        return {"type": self.type, "value": self.value,
                "confidence": self.confidence, "source_finding": self.source_finding}


def _placeholder_endpoint(ep: str | None) -> bool:
    # 0.0.0.0:0 / :::0 / any :0 port is not a usable endpoint.
    return not ep or ep.rsplit(":", 1)[-1] == "0"


def extract(findings: list[Finding]) -> list[IOC]:
    seen: dict[tuple[str, str], IOC] = {}

    def add(type_: str, value: str, conf: str, source: str) -> None:
        key = (type_, value)
        if value and key not in seen:
            seen[key] = IOC(type_, value, conf, source)

    for f in findings:
        conf = f.confidence.value
        if f.kind is FindingKind.HIDDEN_MODULE:
            name = f.subject.removeprefix("module ")
            add("kernel_module", name, conf, f.subject)
            for ev in f.evidence.get("unexpected_hook", []):
                fn = ev.get("function")
                if fn:
                    add("hooked_function", fn, conf, f.subject)
        elif f.kind is FindingKind.HIDDEN_PROCESS:
            for channel in ("syscall_kill", "direct_status"):
                for ev in f.evidence.get(channel, []):
                    comm = ev.get("comm")
                    if comm:
                        add("process_name", comm, conf, f.subject)
            for ev in f.evidence.get("socket_visible", []):
                endpoint = (ev.get("remote") if ev.get("state") == "ESTABLISHED"
                            else ev.get("local"))
                if not _placeholder_endpoint(endpoint):
                    add("network_endpoint", endpoint, conf, f.subject)

    return sorted(seen.values(), key=lambda i: (i.type, i.value))
```

- [ ] **Step 4: Run tests, then commit**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_iocs.py -v`
Expected: PASS (4).

```bash
git add src/kdetect/reporting/iocs.py tests/unit/test_iocs.py
git commit -m "feat(reporting): typed IOC extraction from findings"
```

---

## Task 6: Report renderers (Markdown + JSON)

**Files:**
- Create: `src/kdetect/reporting/report.py`
- Test: `tests/unit/test_report.py`

**Interfaces:**
- Consumes: `Snapshot`, `Finding`, `Confidence` (models); `IOC` (Task 5).
- Produces: `render_markdown(snapshot, findings, iocs, baseline_name=None) -> str`; `render_json(snapshot, findings, iocs, baseline_name=None) -> str`. Findings most-severe-first (HIGH→MEDIUM→LOW, then subject). A zero-findings report is valid and says "No findings."

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_report.py`:

```python
import json
from kdetect.analysis.models import Finding, FindingKind, Confidence
from kdetect.reporting.iocs import extract
from kdetect.reporting import report
from kdetect.models import (
    Snapshot, HostFacts, CaptureMeta, SCHEMA_VERSION,
)

def _snap():
    host = HostFacts("kdetect-lab", "6.1.0-52", "x86_64", "b0", 1, 100)
    return Snapshot(SCHEMA_VERSION, "id", "2026-09-03T00:00:00.000Z", host,
                    CaptureMeta("0.1.0", 0), [])

def _hidden_module():
    return Finding(FindingKind.HIDDEN_MODULE, "module diamorphine",
                   Confidence.HIGH, ["ftrace_orphan"], ["procfs.modules listing"],
                   {"unexpected_hook": [{"function": "__x64_sys_kill"}]},
                   "module diamorphine is concealed")

def test_markdown_has_sections_and_verdict():
    f = _hidden_module()
    md = report.render_markdown(_snap(), [f], extract([f]))
    assert "# kdetect report" in md
    assert "diamorphine" in md
    assert "Indicators of Compromise" in md
    assert "__x64_sys_kill" in md
    assert "HIGH" in md

def test_markdown_hidden_process_shows_comm_and_exe_unavailable():
    f = Finding(FindingKind.HIDDEN_PROCESS, "pid 1234", Confidence.HIGH,
                ["syscall_kill"], [], {"syscall_kill": [{"comm": "evil"}]}, "")
    md = report.render_markdown(_snap(), [f], extract([f]))
    assert "comm" in md and "evil" in md
    assert "unavailable" in md          # exe unavailable (hidden from /proc)

def test_zero_findings_report_is_valid():
    md = report.render_markdown(_snap(), [], [])
    assert "No findings" in md

def test_json_report_shape():
    f = _hidden_module()
    payload = json.loads(report.render_json(_snap(), [f], extract([f])))
    assert payload["host"]["hostname"] == "kdetect-lab"
    assert payload["summary"]["high"] == 1
    assert payload["findings"][0]["kind"] == "hidden_module"
    assert any(i["type"] == "kernel_module" for i in payload["iocs"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_report.py -v`
Expected: FAIL — `ModuleNotFoundError: kdetect.reporting.report`.

- [ ] **Step 3: Write the renderers**

Create `src/kdetect/reporting/report.py`:

```python
"""Report renderers (spec §5). Pure: (snapshot, findings, iocs) -> str.

Presents analyze()'s findings; concludes nothing (P11). Markdown for a human,
JSON for a pipeline. A hidden process shows its comm and owned socket endpoints;
its exe/cmdline are unavailable because it was hidden from the readdir path that
records them (L26).
"""
from __future__ import annotations

import json

from kdetect.analysis.models import Confidence, Finding
from kdetect.models import Snapshot
from kdetect.reporting.iocs import IOC

_ORDER = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


def _ranked(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_ORDER[f.confidence], f.subject))


def _counts(findings: list[Finding]) -> dict:
    return {
        "high": sum(f.confidence is Confidence.HIGH for f in findings),
        "medium": sum(f.confidence is Confidence.MEDIUM for f in findings),
        "low": sum(f.confidence is Confidence.LOW for f in findings),
    }


def _verdict(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    kinds = sorted({f.kind.value for f in findings})
    return f"{len(findings)} finding(s) — {', '.join(kinds)}. Investigate."


def render_json(snapshot: Snapshot, findings: list[Finding], iocs: list[IOC],
                baseline_name: str | None = None) -> str:
    h = snapshot.host
    payload = {
        "host": {"hostname": h.hostname, "kernel_release": h.kernel_release,
                 "arch": h.arch, "boot_id": h.boot_id},
        "captured_at": snapshot.captured_at,
        "euid": snapshot.capture.euid,
        "tool_version": snapshot.capture.tool_version,
        "schema": snapshot.schema_version,
        "baseline": {"name": baseline_name, "verified": True} if baseline_name else None,
        "summary": _counts(findings),
        "verdict": _verdict(findings),
        "findings": [f.to_dict() for f in _ranked(findings)],
        "iocs": [i.to_dict() for i in iocs],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _render_evidence(f: Finding) -> list[str]:
    lines: list[str] = []
    if f.kind.value == "hidden_process":
        comm = None
        for ch in ("syscall_kill", "direct_status"):
            for ev in f.evidence.get(ch, []):
                comm = comm or ev.get("comm")
        lines.append(f"  - comm: {comm if comm else 'unknown'}")
        lines.append("  - exe: unavailable (hidden from /proc)")
        for ev in f.evidence.get("socket_visible", []):
            lines.append(f"  - socket: {ev.get('local')} -> {ev.get('remote')} "
                         f"({ev.get('state')})")
    else:
        for channel in sorted(f.evidence):
            lines.append(f"  - {channel}: {f.evidence[channel]}")
    return lines


def render_markdown(snapshot: Snapshot, findings: list[Finding], iocs: list[IOC],
                    baseline_name: str | None = None) -> str:
    h = snapshot.host
    c = _counts(findings)
    out = [
        f"# kdetect report — {h.hostname}",
        "",
        f"**Host:** {h.hostname} · {h.kernel_release} · {h.arch}",
        f"**Captured:** {snapshot.captured_at} · boot {h.boot_id[:8]} · "
        f"euid {snapshot.capture.euid}",
        f"**Tool:** kdetect {snapshot.capture.tool_version} · schema "
        f"{snapshot.schema_version}",
        f"**Baseline:** {baseline_name if baseline_name else 'none'}",
        "",
        "## Summary",
        f"- HIGH: {c['high']} · MEDIUM: {c['medium']} · LOW: {c['low']}",
        f"- Verdict: {_verdict(findings)}",
        "",
        "## Findings",
    ]
    if not findings:
        out.append("None.")
    for f in _ranked(findings):
        out.append(f"### [{f.confidence.value}] {f.kind.value} — {f.subject}")
        if f.channels_agree:
            out.append(f"- Seen by: {', '.join(f.channels_agree)}")
        if f.channels_dissent:
            out.append(f"- Denied by: {', '.join(f.channels_dissent)}")
        out.extend(_render_evidence(f))
        out.append("")
    out.append("## Indicators of Compromise")
    if not iocs:
        out.append("None.")
    for i in iocs:
        out.append(f"- {i.type}: `{i.value}` ({i.confidence})")
    out.append("")
    return "\n".join(out)
```

- [ ] **Step 4: Run tests, then commit**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_report.py -v`
Expected: PASS (4).

```bash
git add src/kdetect/reporting/report.py tests/unit/test_report.py
git commit -m "feat(reporting): Markdown + JSON report renderers"
```

---

## Task 7: CLI — `report` and `redact` commands

**Files:**
- Modify: `src/kdetect/cli.py`
- Test: `tests/unit/test_analyze.py` (extend, or a new `tests/unit/test_cli_report.py`)

**Interfaces:**
- Consumes: `analyze` (crossview/scoring), `extract` (Task 5), `render_markdown`/`render_json` (Task 6), `redact_snapshot` (Task 4).
- Produces: `cmd_report(args)`, `cmd_redact(args)`; a shared `_load_snapshot(path)` helper. `report` exit 3/0/1/2; `redact` exit 0/1.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_cli_report.py`:

```python
import json
from pathlib import Path
import shutil
from kdetect.cli import main

FIX = Path("tests/fixtures/snapshots")

def test_report_markdown_on_infected(capsys):
    rc = main(["report", str(FIX / "infected-hooktest.json")])
    out = capsys.readouterr().out
    assert rc == 3                          # findings present
    assert "kdetect_hooktest" in out and "# kdetect report" in out

def test_report_json_parses(capsys):
    rc = main(["report", str(FIX / "infected-hooktest.json"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["high"] >= 1
    assert rc == 3

def test_report_clean_is_exit_zero(capsys):
    rc = main(["report", str(FIX / "clean-phase2.json")])
    assert rc == 0
    assert "No findings" in capsys.readouterr().out

def test_report_writes_out_file(tmp_path):
    out = tmp_path / "r.md"
    rc = main(["report", str(FIX / "clean-phase2.json"), "--out", str(out)])
    assert rc == 0 and out.exists() and "kdetect report" in out.read_text()

def test_redact_scrubs_cmdline(tmp_path):
    src = tmp_path / "in.json"; shutil.copy(FIX / "clean-phase2.json", src)
    dst = tmp_path / "out.json"
    rc = main(["redact", str(src), str(dst)])
    assert rc == 0
    data = json.loads(dst.read_text())
    cmds = [e.get("cmdline") for o in data["observations"]
            for e in o.get("entities", {}).values() if "cmdline" in e]
    assert cmds and all(c == ["[redacted]"] for c in cmds)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_cli_report.py -v`
Expected: FAIL — `report`/`redact` are unrecognised commands.

- [ ] **Step 3: Implement the commands**

In `src/kdetect/cli.py`, add a shared loader and the two commands:

```python
def _load_snapshot(path_str: str):
    """Load a snapshot or print an error and return None."""
    path = Path(path_str)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return None
    except json.JSONDecodeError as exc:
        print(f"error: {path} is not valid JSON: {exc}", file=sys.stderr)
        return None
    try:
        return Snapshot.from_dict(raw)
    except IncompatibleSnapshot as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None


def cmd_report(args) -> int:
    from kdetect.analysis.scoring import analyze
    from kdetect.reporting import report as report_mod
    from kdetect.reporting.iocs import extract

    snapshot = _load_snapshot(args.snapshot)
    if snapshot is None:
        return EXIT_ERROR

    baseline = None
    baseline_name = None
    if getattr(args, "baseline", None):
        from kdetect.baseline.store import BaselineTampered, load_baseline, load_public_key
        if not args.verify_key:
            print("error: --baseline requires --verify-key", file=sys.stderr)
            return EXIT_ERROR
        try:
            baseline = load_baseline(Path(args.baseline), load_public_key(Path(args.verify_key)))
        except BaselineTampered as exc:
            print(f"error: baseline verification failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        baseline_name = Path(args.baseline).name

    findings = analyze(snapshot, baseline)
    iocs = extract(findings)
    if args.format == "json":
        text = report_mod.render_json(snapshot, findings, iocs, baseline_name)
    else:
        text = report_mod.render_markdown(snapshot, findings, iocs, baseline_name)

    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(args.out)
    else:
        print(text)
    return 3 if findings else EXIT_OK


def cmd_redact(args) -> int:
    from kdetect.reporting.redact import redact_snapshot
    snapshot = _load_snapshot(args.infile)
    if snapshot is None:
        return EXIT_ERROR
    raw = json.loads(Path(args.infile).read_text(encoding="utf-8"))
    out = Snapshot.from_dict(redact_snapshot(raw))
    Path(args.outfile).write_text(out.to_json(pretty=True) + "\n", encoding="utf-8")
    print(args.outfile)
    return EXIT_OK
```

Register the subparsers in `main` (next to the others) and dispatch:

```python
    report_p = subparsers.add_parser("report", help="Render a shareable report.")
    report_p.add_argument("snapshot")
    report_p.add_argument("--format", choices=["md", "json"], default="md")
    report_p.add_argument("--out", help="Write to a file instead of stdout.")
    report_p.add_argument("--baseline")
    report_p.add_argument("--verify-key")

    redact_p = subparsers.add_parser("redact", help="Scrub a snapshot for sharing.")
    redact_p.add_argument("infile")
    redact_p.add_argument("outfile")
    # ... in the dispatch block:
    if args.command == "report":
        return cmd_report(args)
    if args.command == "redact":
        return cmd_redact(args)
```

- [ ] **Step 4: Run tests, then commit**

Run: `.venv/Scripts/python.exe -m pytest tests/unit -q`
Expected: all pass.

```bash
git add src/kdetect/cli.py tests/unit/test_cli_report.py
git commit -m "feat(cli): report (md/json) and redact commands"
```

---

## Task 8: Docs — L26, reporting method, architecture, README

**Files:**
- Modify: `docs/limitations.md`, `docs/detection-methods.md`, `docs/architecture.md`, `README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: L26 recorded; reporting documented; README shows the `report`/`redact` commands.

- [ ] **Step 1: Add L26 to `docs/limitations.md`** (verbatim from spec §12), after L25.

- [ ] **Step 2: Add a "Reporting & IOCs" section to `docs/detection-methods.md`** (or a short new method entry) — states that reports present findings (P11, conclude nothing); the report is cmdline-free by construction; IOCs are the portable indicators (`kernel_module`, `hooked_function`, `network_endpoint`, `process_name`); redaction (`kdetect redact`) scrubs a snapshot for sharing. Cite the phase-4b spec.

- [ ] **Step 3: Update `docs/architecture.md`** — add the `reporting/` layer (redact, iocs, report) and the `report`/`redact` commands; note `comm` now flows through the sweep. Cite the phase-4b spec.

- [ ] **Step 4: Update `README.md`** — add `kdetect report <snapshot> [--format md|json] [--out …]` and `kdetect redact <in> <out>` to the usage/commands section, with a one-line description each. (Read the README first to match its existing command-list style; if it has no command list yet, add a short "Commands" section covering capture/analyze/baseline/report/redact.)

- [ ] **Step 5: Commit**

```bash
git add docs/limitations.md docs/detection-methods.md docs/architecture.md README.md
git commit -m "docs: phase 4b reporting/IOCs/redaction, L26, README commands"
```

---

## Self-Review

**Spec coverage:**
- §3 comm-through-sweep → Tasks 1 (parser), 2 (entity/source/collector), 3 (evidence).
- §4 module layout → Tasks 4–7 (redact, iocs, report, CLI).
- §5 report content (MD + JSON, verdict, hidden-proc comm/exe-unavailable, zero-findings) → Task 6.
- §6 IOC types + portable-vs-local + dedup/sort → Task 5.
- §7 redaction (module + tool wrapper + `kdetect redact`; report cmdline-free) → Tasks 4, 7.
- §8 CLI (`report` exit 3/0/1/2, `redact`) → Task 7.
- §9 testing/acceptance → Tasks 1–8 (criterion 1 infected report → Task 7 test; 2 clean → Task 7; 3 json shape → Task 6/7; 4 redact → Tasks 4/7; 5 hidden-proc comm/exe → Task 6; 6 3.11 guard → Global Constraints).
- §12 L26 → Task 8.

**Deviations / notes, flagged:**
1. **`read_tgid` is renamed to `read_status`** (returns `(tgid, comm)`), not kept alongside a new method — one status read, not two. Its only production caller is `SweepProcessCollector`; Task 2 updates it and the source tests in the same commit, so nothing dangles.
2. **`report` exits 3 when findings are present** (spec §8) — a report command returning non-zero is intentional (scriptable, matches `analyze`), noted so it isn't mistaken for failure.
3. **Existing snapshot fixtures load `comm=None`** (additive schema 1.1) — report/IOC tests that need a `comm` use synthetic findings (Tasks 5/6), not the committed fixtures, which have no hidden-process findings anyway.

**Placeholder scan:** none — every code/test step is complete. Task 8 Step 4 says to match the README's existing style (a real, bounded instruction, since the README's current shape isn't reproduced here).

**Type consistency:** `SweepEntity(tgid, status_readable, comm=None)` consistent across Tasks 2/3/6-tests. `read_status -> tuple[int, str|None]|None` consistent Tasks 2 (base/live/fixture/collector). `IOC(type, value, confidence, source_finding)` consistent Tasks 5/6. `render_markdown/render_json(snapshot, findings, iocs, baseline_name=None)` consistent Tasks 6/7. `redact_snapshot(dict)->dict` consistent Tasks 4/7. `extract(findings)->list[IOC]` consistent Tasks 5/6/7. Evidence key `comm` written by Task 3, read by Tasks 5/6.

---

## Execution Handoff

Plan complete. Save location: `docs/superpowers/plans/2026-09-03-kdetect-phase4b.md`.
