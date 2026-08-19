# kdetect Phase 2 — Cross-View Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two cross-checked views (processes, modules), a pure cross-view differ, and Findings, so `kdetect analyze` detects a real LKM rootkit (Diamorphine) hiding a process and its own module.

**Architecture:** Snapshots stay evidence-only; new MEDIUM-trust collectors record independent channels (a `kill(id,0)` sweep with `Tgid` folding evidence; kernel taint/vmalloc/ftrace module evidence). A pure differ turns channel disagreement into `Finding`s. `analyze` grows a findings section and spends the reserved exit code 3.

**Tech Stack:** Python 3.11+, stdlib only (dataclasses, argparse, json, os, ctypes-free). pytest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-20-kdetect-phase2-design.md` (read it alongside this plan; principles P1–P5 and the false-positive classes are argued there and cited by task).

## Global Constraints

- **Stdlib only.** No new runtime dependency. `dataclasses`, `json`, `os`, `argparse`, `enum` (spec §Tech / phase 1 decision table).
- **P1 — snapshots hold evidence, not conclusions.** Collectors never label; no `is_hidden`, no `is_thread`. Findings live only in the analysis layer and are never serialised into a snapshot.
- **P3 — test code == production code.** Every collector takes its source as an argument; there is no `if testing:` branch. Each new source has a live and a fixture implementation behind one interface.
- **P4 — collectors record channels; the differ folds and concludes.** The sweep records `{task_id: tgid}`; the differ does the thread-folding.
- **P5 — a Finding carries the evidence it was drawn from.** Every `Finding.evidence` holds the exact snapshot values that produced it.
- **Determinism.** `to_dict`/`to_json` use `sort_keys=True`; `entity_ids` sorted ascending; `from_dict(to_dict(s)) == s` byte-identical. New optional fields are **omitted when `None`**, so phase 1 fixtures still round-trip.
- **Schema is 1.1** this phase: additive fields only (`pass`, `extra`). MAJOR stays 1 (spec §4.1 schema note).
- **Capability-gated tests, not OS-gated.** Live-source tests use `@needs_procfs` from `tests/conftest.py`. The first four tiers (Parse, Collector, Round-trip, Differ) run on Windows with the VM off.
- **Exit codes:** 0 ok, 1 error, 2 usage, **3 = any finding fired** (any confidence).
- **Angus commits.** Do not run `git commit`. Each task's final step **stages** files with `git add` and states the commit message for Angus to run. Never push from an infected VM snapshot (spec §9, `docs/step0-phase2/README.md`).

---

## File Structure

**Create:**
- `src/kdetect/parsers/modules.py` — pure parsers: `/proc/modules`, `/proc/sys/kernel/tainted`, `/proc/vmallocinfo` region count, ftrace `available_filter_functions` tag set.
- `src/kdetect/collectors/syscall_sweep.py` — `SweepProcessCollector` (MEDIUM).
- `src/kdetect/collectors/modules.py` — `ProcfsModuleCollector` (LOW) and `ModuleEvidenceCollector` (MEDIUM).
- `src/kdetect/analysis/models.py` — `Finding`, `FindingKind`, `Confidence`.
- `src/kdetect/analysis/crossview.py` — `diff_processes`, `diff_modules`, `diff_all`.
- Tests: `tests/unit/test_parse_modules.py`, `test_signal_source.py`, `test_module_source.py`, `test_collector_sweep.py`, `test_collector_modules.py`, `test_finding_model.py`, `test_diff_processes.py`, `test_diff_modules.py`; `tests/integration/test_phase2_live.py`.

**Modify:**
- `src/kdetect/parsers/procfs.py` — add `tgid` to `StatusFields` and parse the `Tgid:` line.
- `src/kdetect/models.py` — `SweepEntity`, `ModuleEntity`; generalise `Observation` (entity registry, string ids for modules, `pass`/`extra`); `SCHEMA_VERSION = "1.1"`.
- `src/kdetect/collectors/base.py` — `SignalSource` and `ModuleSource` ABCs; reuse existing `Vanished`/`Denied`/`Unreadable`.
- `src/kdetect/collectors/sources.py` — `LiveSignalSource`, `FixtureSignalSource`, `LiveModuleSource`, `FixtureModuleSource`.
- `src/kdetect/collectors/procfs.py` — `ProcfsProcessCollector.__init__(pass_label=None)`, stamp `pass_` on its Observation.
- `src/kdetect/cli.py` — capture runs the sandwich + module collectors; `analyze` prints findings, `--json`, exit 3.
- `docs/limitations.md` — add L15; `docs/detection-methods.md` — one page per channel.

**Fixtures (captured on the VM during Task 12):**
- `tests/fixtures/snapshots/clean-phase2.json`, `tests/fixtures/snapshots/infected-diamorphine.json`.
- `tests/fixtures/module-trees/` and `tests/fixtures/signal-sets/` for source fixtures (small, curated, hand-authored — see Tasks 3–4).

---

## Task 1: Generalise the Observation model for multiple entity types

**Files:**
- Modify: `src/kdetect/models.py`
- Test: `tests/unit/test_models_roundtrip.py` (extend), `tests/unit/test_schema_version.py` (extend)

**Interfaces:**
- Produces: `SweepEntity(tgid: int, status_readable: bool)`; `ModuleEntity(name: str, size: int, refcount: int, dependents: list[str], state: str, base_addr: str, taint: str | None)`; `Observation` gains `pass_: str | None` (JSON key `"pass"`) and `extra: dict | None`; `SCHEMA_VERSION == "1.1"`. `Observation.from_dict` dispatches entity type by `collector` and casts entity keys to `str` for `procfs.modules`, `int` otherwise.

- [ ] **Step 1: Write the failing round-trip tests for the new entity types and optional fields**

Add to `tests/unit/test_models_roundtrip.py`:

```python
from kdetect.models import (
    Observation, SweepEntity, ModuleEntity, Status, TrustLevel,
)

def _obs(**kw):
    base = dict(collector="x", collector_version="1", view="v",
                trust_level=TrustLevel.MEDIUM, status=Status.OK, duration_ms=1,
                entity_ids=[], entities={}, stats={}, errors=[])
    base.update(kw)
    return Observation(**base)

def test_sweep_entity_roundtrip():
    obs = _obs(collector="syscall_sweep.processes",
               entity_ids=[1, 551, 31337],
               entities={1: SweepEntity(1, True),
                         551: SweepEntity(501, True),
                         31337: SweepEntity(31337, True)})
    back = Observation.from_dict(obs.to_dict())
    assert back == obs
    assert back.entities[551].tgid == 501            # int key survives
    assert back.entities[551].status_readable is True

def test_module_entity_roundtrip_string_keys():
    obs = _obs(collector="procfs.modules", view="modules",
               trust_level=TrustLevel.LOW,
               entity_ids=["diamorphine", "ext4"],
               entities={
                   "ext4": ModuleEntity("ext4", 999424, 1, [], "Live",
                                        "0xffffffffc0591000", None),
                   "diamorphine": ModuleEntity("diamorphine", 16384, 0, [],
                                               "Live", "0x0", "OE"),
               })
    back = Observation.from_dict(obs.to_dict())
    assert back == obs
    assert set(back.entities) == {"ext4", "diamorphine"}   # stayed strings
    assert back.entities["diamorphine"].taint == "OE"

def test_pass_and_extra_omitted_when_none():
    d = _obs().to_dict()
    assert "pass" not in d and "extra" not in d           # phase-1 fixtures round-trip

def test_pass_and_extra_present_when_set():
    obs = _obs(pass_="A", extra={"ftrace_modules": ["ext4"]})
    d = obs.to_dict()
    assert d["pass"] == "A" and d["extra"] == {"ftrace_modules": ["ext4"]}
    assert Observation.from_dict(d) == obs
```

Add to `tests/unit/test_schema_version.py`:

```python
from kdetect.models import SCHEMA_VERSION

def test_schema_is_1_1():
    assert SCHEMA_VERSION == "1.1"
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_models_roundtrip.py tests/unit/test_schema_version.py -q`
Expected: FAIL — `ImportError: cannot import name 'SweepEntity'`, and `SCHEMA_VERSION` still `"1.0"`.

- [ ] **Step 3: Add the entity dataclasses**

In `src/kdetect/models.py`, after `ProcessEntity`:

```python
@dataclass(frozen=True)
class SweepEntity:
    """One task id that answered a kill(id, 0) sweep (spec §4.1).

    Evidence only (P4): the tgid we read from /proc/<id>/status, and whether
    that read succeeded. The differ folds threads into leaders using tgid; it
    is not folded here.
    """
    tgid: int
    status_readable: bool

    def to_dict(self) -> dict:
        return {"tgid": self.tgid, "status_readable": self.status_readable}

    @classmethod
    def from_dict(cls, d: dict) -> "SweepEntity":
        return cls(tgid=d["tgid"], status_readable=d["status_readable"])


@dataclass(frozen=True)
class ModuleEntity:
    """One row of /proc/modules (spec §5.1), stored raw (P1).

    `taint` is the trailing parenthesised marker, e.g. "OE", or None when the
    module carries none. `base_addr` is kept as the textual value; on an
    unprivileged capture it reads "0x0" (L4) and analysis must expect that.
    """
    name: str
    size: int
    refcount: int
    dependents: list[str]
    state: str
    base_addr: str
    taint: str | None

    def to_dict(self) -> dict:
        return {
            "name": self.name, "size": self.size, "refcount": self.refcount,
            "dependents": list(self.dependents), "state": self.state,
            "base_addr": self.base_addr, "taint": self.taint,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ModuleEntity":
        return cls(
            name=d["name"], size=d["size"], refcount=d["refcount"],
            dependents=list(d["dependents"]), state=d["state"],
            base_addr=d["base_addr"], taint=d["taint"],
        )
```

- [ ] **Step 4: Bump the version and add the entity registry**

In `src/kdetect/models.py`, change `SCHEMA_VERSION = "1.0"` to `SCHEMA_VERSION = "1.1"`, and after the entity classes add:

```python
#: Which entity type each collector stores. Collectors that record only
#: existence (kernel.module_evidence) have no per-entity detail.
_ENTITY_TYPES = {
    "procfs.processes": ProcessEntity,
    "syscall_sweep.processes": SweepEntity,
    "procfs.modules": ModuleEntity,
    "kernel.module_evidence": None,
}

#: Collectors whose entity ids are names, not pids. Their entity_ids and
#: entities keys stay strings; every other collector casts keys back to int.
_STRING_ID_COLLECTORS = frozenset({"procfs.modules"})
```

- [ ] **Step 5: Generalise `Observation` — new fields, dispatched from_dict**

Add `pass_` and `extra` to the `Observation` dataclass (after `errors`):

```python
    pass_: str | None = None          # JSON key "pass"; distinguishes A/B walks
    extra: dict | None = None         # channel detail that is not per-entity
```

Replace `Observation.to_dict` so entity keys and ids use the right type and the optional fields are omitted when None:

```python
    def to_dict(self) -> dict:
        d = {
            "collector": self.collector,
            "collector_version": self.collector_version,
            "view": self.view,
            "trust_level": self.trust_level.value,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "entity_ids": sorted(self.entity_ids),
            "entities": {str(k): e.to_dict() for k, e in self.entities.items()},
            "stats": dict(self.stats),
            "errors": [err.to_dict() for err in self.errors],
        }
        if self.pass_ is not None:
            d["pass"] = self.pass_
        if self.extra is not None:
            d["extra"] = self.extra
        return d
```

Replace `Observation.from_dict` to dispatch entity parsing and id casting:

```python
    @classmethod
    def from_dict(cls, d: dict) -> "Observation":
        collector = d["collector"]
        entity_cls = _ENTITY_TYPES.get(collector, ProcessEntity)
        cast = str if collector in _STRING_ID_COLLECTORS else int
        entities = (
            {cast(k): entity_cls.from_dict(v) for k, v in d["entities"].items()}
            if entity_cls is not None else {}
        )
        return cls(
            collector=collector,
            collector_version=d["collector_version"],
            view=d["view"],
            trust_level=TrustLevel(d["trust_level"]),
            status=Status(d["status"]),
            duration_ms=d["duration_ms"],
            entity_ids=list(d["entity_ids"]),
            entities=entities,
            stats=dict(d["stats"]),
            errors=[CollectionError.from_dict(e) for e in d["errors"]],
            pass_=d.get("pass"),
            extra=d.get("extra"),
        )
```

- [ ] **Step 6: Run the model tests and the existing suite**

Run: `.venv/Scripts/python -m pytest tests/unit -q`
Expected: PASS, including the pre-existing phase 1 round-trip on `clean-vm.json` (it has no `pass`/`extra`, so omit-when-None keeps it byte-identical).

- [ ] **Step 7: Stage and hand off the commit**

```bash
git add src/kdetect/models.py tests/unit/test_models_roundtrip.py tests/unit/test_schema_version.py
```
Commit message for Angus: `feat: schema 1.1 — sweep and module entities, optional pass/extra`

---

## Task 2: Parsers for Tgid and the module channels

**Files:**
- Modify: `src/kdetect/parsers/procfs.py` (add `tgid` to `StatusFields`)
- Create: `src/kdetect/parsers/modules.py`
- Test: `tests/unit/test_parse_status.py` (extend), `tests/unit/test_parse_modules.py`

**Interfaces:**
- Produces: `StatusFields.tgid: int`; `parse_proc_modules(text) -> list[ModuleRow]` where `ModuleRow(name, size, refcount, dependents, state, base_addr, taint)`; `parse_tainted(text) -> int`; `count_module_regions(vmallocinfo_text) -> int`; `parse_ftrace_modules(text) -> set[str]`.

- [ ] **Step 1: Write failing parser tests from the step0 evidence**

`tests/unit/test_parse_status.py` (add):

```python
def test_parse_status_reads_tgid():
    text = "Name:\tbash\nTgid:\t501\nPid:\t551\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
    assert parse_status(text).tgid == 501
```

`tests/unit/test_parse_modules.py` (new):

```python
from kdetect.parsers.modules import (
    parse_proc_modules, parse_tainted, count_module_regions, parse_ftrace_modules,
)

def test_parse_proc_modules_basic():
    # name size refcount dependents state base [taint]
    text = (
        "ext4 999424 1 - Live 0xffffffffc0591000\n"
        "diamorphine 16384 0 - Live 0x0000000000000000 (OE)\n"
        "crc16 12288 1 ext4,foo Live 0xffffffffc0455000\n"
    )
    rows = {r.name: r for r in parse_proc_modules(text)}
    assert rows["ext4"].size == 999424 and rows["ext4"].taint is None
    assert rows["diamorphine"].taint == "OE"
    assert rows["crc16"].dependents == ["ext4", "foo"]     # "-" means none
    assert rows["ext4"].dependents == []

def test_parse_tainted_bits():
    assert parse_tainted("0\n") == 0
    assert parse_tainted("12288\n") == 12288               # bits 12+13 set

def test_count_module_regions_counts_load_module_lines():
    text = (
        "0x1-0x2 20480 load_module+0xbb7/0x21a0 pages=4 vmalloc N0=4\n"
        "0x3-0x4 8192 some_other_alloc+0x0 pages=2 vmalloc N0=2\n"
        "0x5-0x6 32768 load_module+0xbb7/0x21a0 pages=7 vmalloc N0=7\n"
    )
    assert count_module_regions(text) == 2

def test_parse_ftrace_modules_extracts_bracket_tags():
    text = (
        "vfs_read\n"                       # core kernel, untagged
        "ext4_file_read_iter [ext4]\n"
        "ext4_readpage [ext4]\n"
        "diamorphine_init [diamorphine]\n"
    )
    assert parse_ftrace_modules(text) == {"ext4", "diamorphine"}
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_parse_modules.py tests/unit/test_parse_status.py -q`
Expected: FAIL — `ModuleError`/import errors, and `StatusFields` has no `tgid`.

- [ ] **Step 3: Add `tgid` to the status parser**

In `src/kdetect/parsers/procfs.py`, add `tgid: int` to `StatusFields`, parse the `Tgid:` line, and require it:

```python
@dataclass(frozen=True)
class StatusFields:
    uid: list[int]
    gid: list[int]
    tgid: int
```

In `parse_status`, initialise `tgid = None`, add a branch `elif key == "Tgid": tgid = int(value.strip())`, and extend the missing-field check and return:

```python
    if uid is None or gid is None or tgid is None:
        raise ParseError(f"status missing Uid, Gid, or Tgid line: {text!r}")
    return StatusFields(uid=uid, gid=gid, tgid=tgid)
```

- [ ] **Step 4: Write the module parsers**

Create `src/kdetect/parsers/modules.py`:

```python
"""Pure parsers for the module-view channels (spec §5).

Text in, typed values out, no I/O. Each mirrors a file in
docs/step0-phase2/clean/ and every case in the tests is drawn from there.
"""
from __future__ import annotations

from dataclasses import dataclass


class ModuleParseError(ValueError):
    """A module-channel file could not be parsed."""


@dataclass(frozen=True)
class ModuleRow:
    name: str
    size: int
    refcount: int
    dependents: list[str]
    state: str
    base_addr: str
    taint: str | None


def parse_proc_modules(text: str) -> list[ModuleRow]:
    """Parse /proc/modules. Columns: name size refcount deps state base [taint]."""
    rows: list[ModuleRow] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 6:
            raise ModuleParseError(f"short /proc/modules line: {line!r}")
        deps = [] if parts[3] == "-" else [d for d in parts[3].split(",") if d]
        taint = None
        if len(parts) >= 7 and parts[6].startswith("(") and parts[6].endswith(")"):
            taint = parts[6][1:-1]
        try:
            rows.append(ModuleRow(
                name=parts[0], size=int(parts[1]), refcount=int(parts[2]),
                dependents=deps, state=parts[4], base_addr=parts[5], taint=taint,
            ))
        except ValueError as exc:
            raise ModuleParseError(f"non-numeric field: {line!r}") from exc
    return rows


def parse_tainted(text: str) -> int:
    """The /proc/sys/kernel/tainted word as an int. Bit 12 = out-of-tree,
    bit 13 = unsigned (spec §3, 08-taint-accounting.txt)."""
    try:
        return int(text.strip())
    except ValueError as exc:
        raise ModuleParseError(f"non-integer tainted value: {text!r}") from exc


def count_module_regions(text: str) -> int:
    """Number of load_module allocations in /proc/vmallocinfo.

    Addresses are hash-obfuscated (L15), so this counts regions and never
    correlates by address (07-vmallocinfo-modules.txt)."""
    return sum(1 for line in text.splitlines() if "load_module" in line)


def parse_ftrace_modules(text: str) -> set[str]:
    """The set of module names tagged in available_filter_functions.

    A record for a module reads 'symbol [modname]'; core-kernel records have
    no bracket. Only bracketed tags name a module (06-ftrace-module-tags.txt)."""
    names: set[str] = set()
    for line in text.splitlines():
        line = line.rstrip()
        if line.endswith("]") and "[" in line:
            names.add(line[line.rindex("[") + 1 : -1])
    return names
```

- [ ] **Step 5: Run the parser tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_parse_modules.py tests/unit/test_parse_status.py -q`
Expected: PASS.

- [ ] **Step 6: Run the full unit suite (catch StatusFields breakage)**

Run: `.venv/Scripts/python -m pytest tests/unit -q`
Expected: PASS. If `test_collector_procfs.py` or a fixture constructs `StatusFields(...)` positionally, update those call sites to pass `tgid`. The live `parse_status` path already supplies it.

- [ ] **Step 7: Stage and hand off**

```bash
git add src/kdetect/parsers/procfs.py src/kdetect/parsers/modules.py tests/unit/test_parse_modules.py tests/unit/test_parse_status.py
```
Commit message: `feat: parse Tgid and the module-view channels`

---

## Task 3: SignalSource — the pid-space sweep channel

**Files:**
- Modify: `src/kdetect/collectors/base.py` (add `SignalSource` ABC)
- Modify: `src/kdetect/collectors/sources.py` (`LiveSignalSource`, `FixtureSignalSource`)
- Create fixture: `tests/fixtures/signal-sets/hidden-pid.json`
- Test: `tests/unit/test_signal_source.py`

**Interfaces:**
- Produces: `SignalSource` ABC with `pid_max() -> int`, `sweep(pid_max: int) -> list[int]` (ids that exist; both success and `EPERM` count as existing), `read_tgid(task_id: int) -> int | None` (None when status is unreadable). `LiveSignalSource()`; `FixtureSignalSource(path)`.
- Consumes: existing `Vanished`/`Denied`/`Unreadable` and `_translate` from Task-0 code.

- [ ] **Step 1: Write the failing fixture test**

Create `tests/fixtures/signal-sets/hidden-pid.json`:

```json
{
  "pid_max": 4194304,
  "alive": [1, 2, 501, 551, 31337],
  "tgid": {"1": 1, "2": 2, "501": 501, "551": 501, "31337": 31337},
  "unreadable_status": [2]
}
```

Create `tests/unit/test_signal_source.py`:

```python
from pathlib import Path
from kdetect.collectors.sources import FixtureSignalSource

FIX = Path(__file__).parent.parent / "fixtures" / "signal-sets" / "hidden-pid.json"

def test_sweep_returns_recorded_alive_ids():
    s = FixtureSignalSource(FIX)
    assert s.pid_max() == 4194304
    assert s.sweep(s.pid_max()) == [1, 2, 501, 551, 31337]

def test_read_tgid_folds_thread_to_leader():
    s = FixtureSignalSource(FIX)
    assert s.read_tgid(551) == 501            # thread of 501
    assert s.read_tgid(31337) == 31337        # its own leader

def test_read_tgid_none_when_status_unreadable():
    s = FixtureSignalSource(FIX)
    assert s.read_tgid(2) is None             # kernel thread, status not read
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_signal_source.py -q`
Expected: FAIL — `cannot import name 'FixtureSignalSource'`.

- [ ] **Step 3: Add the `SignalSource` ABC**

In `src/kdetect/collectors/base.py`, after `ProcSource`:

```python
class SignalSource(ABC):
    """The process-existence channel that does not go through readdir (spec §4).

    kill(id, 0) asks the kernel whether an id exists; /proc/<id>/status is read
    by path lookup, not getdents. Both bypass a directory-listing hook, which
    is why this is a MEDIUM channel independent of procfs.
    """

    @abstractmethod
    def pid_max(self) -> int: ...

    @abstractmethod
    def sweep(self, pid_max: int) -> list[int]:
        """Every id in 1..pid_max that exists, sorted. EPERM counts as exists."""

    @abstractmethod
    def read_tgid(self, task_id: int) -> int | None:
        """The Tgid from /proc/<id>/status, or None if it could not be read."""
```

- [ ] **Step 4: Add the live and fixture implementations**

In `src/kdetect/collectors/sources.py` add imports (`errno`, `SignalSource`, `parse_status`) as needed, then:

```python
class LiveSignalSource(SignalSource):
    """Sweeps the running kernel with os.kill and reads Tgid from /proc."""

    def pid_max(self) -> int:
        with open("/proc/sys/kernel/pid_max", encoding="ascii") as fh:
            return int(fh.read().strip())

    def sweep(self, pid_max: int) -> list[int]:
        alive: list[int] = []
        for task_id in range(1, pid_max + 1):
            try:
                os.kill(task_id, 0)
            except ProcessLookupError:
                continue          # ESRCH: no such id
            except PermissionError:
                alive.append(task_id)   # EPERM: exists, may not signal
            except OSError:
                continue
            else:
                alive.append(task_id)
        return alive

    def read_tgid(self, task_id: int) -> int | None:
        try:
            with open(f"/proc/{task_id}/status", encoding="utf-8",
                      errors="replace") as fh:
                return parse_status(fh.read()).tgid
        except (OSError, ParseError):
            return None


class FixtureSignalSource(SignalSource):
    """Replays a recorded sweep, including a hidden id that never existed (P3)."""

    def __init__(self, path) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._pid_max = data["pid_max"]
        self._alive = sorted(data["alive"])
        self._tgid = {int(k): v for k, v in data["tgid"].items()}
        self._unreadable = set(data.get("unreadable_status", []))

    def pid_max(self) -> int:
        return self._pid_max

    def sweep(self, pid_max: int) -> list[int]:
        return [i for i in self._alive if i <= pid_max]

    def read_tgid(self, task_id: int) -> int | None:
        if task_id in self._unreadable:
            return None
        return self._tgid.get(task_id)
```

Import `ParseError` and `parse_status` at the top of `sources.py` from `kdetect.parsers.procfs`.

- [ ] **Step 5: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_signal_source.py -q`
Expected: PASS.

- [ ] **Step 6: Stage and hand off**

```bash
git add src/kdetect/collectors/base.py src/kdetect/collectors/sources.py tests/unit/test_signal_source.py tests/fixtures/signal-sets/hidden-pid.json
```
Commit message: `feat: SignalSource — pid-space sweep with Tgid folding evidence`

---

## Task 4: ModuleSource — the module-view channels

**Files:**
- Modify: `src/kdetect/collectors/base.py` (`ModuleSource` ABC)
- Modify: `src/kdetect/collectors/sources.py` (`LiveModuleSource`, `FixtureModuleSource`)
- Create fixture: `tests/fixtures/module-trees/clean/` and `.../infected/`
- Test: `tests/unit/test_module_source.py`

**Interfaces:**
- Produces: `ModuleSource` ABC with `read_proc_modules() -> str`, `list_sys_module() -> list[str]`, `sys_module_is_loaded(name) -> bool` (True iff `/sys/module/<name>/initstate` exists), `read_tainted() -> int`, `read_vmallocinfo() -> str | None` (None if denied), `read_ftrace_functions() -> str | None` (None if no tracefs). `LiveModuleSource()`; `FixtureModuleSource(root)`.

- [ ] **Step 1: Write the failing fixture test**

Create the clean fixture files:
- `tests/fixtures/module-trees/clean/proc_modules.txt`:
  ```
  ext4 999424 1 - Live 0xffffffffc0591000
  crc16 12288 1 ext4 Live 0xffffffffc0455000
  ```
- `tests/fixtures/module-trees/clean/tainted.txt` → `0`
- `tests/fixtures/module-trees/clean/vmallocinfo.txt` → two `load_module` lines
- `tests/fixtures/module-trees/clean/ftrace.txt` → `ext4_readpage [ext4]`
- `tests/fixtures/module-trees/clean/sys_module.json`:
  ```json
  {"ext4": true, "crc16": true, "acpi": false, "kernel": false}
  ```
  (value = whether an `initstate` file exists; `false` entries are built-ins — FP class #2.)

Create `tests/unit/test_module_source.py`:

```python
from pathlib import Path
from kdetect.collectors.sources import FixtureModuleSource

CLEAN = Path(__file__).parent.parent / "fixtures" / "module-trees" / "clean"

def test_reads_channels():
    s = FixtureModuleSource(CLEAN)
    assert "ext4" in s.read_proc_modules()
    assert s.read_tainted() == 0
    assert s.read_vmallocinfo().count("load_module") == 2
    assert "[ext4]" in s.read_ftrace_functions()

def test_sys_module_distinguishes_loaded_from_builtin():
    s = FixtureModuleSource(CLEAN)
    assert s.sys_module_is_loaded("ext4") is True
    assert s.sys_module_is_loaded("acpi") is False     # built-in, no initstate
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_module_source.py -q`
Expected: FAIL — `cannot import name 'FixtureModuleSource'`.

- [ ] **Step 3: Add the `ModuleSource` ABC**

In `base.py`:

```python
class ModuleSource(ABC):
    """The module-view channels (spec §5). /proc/modules is the LOW listing a
    rootkit unlinks itself from; tainted, vmallocinfo and ftrace are channels
    that do NOT share that list's source. A channel that cannot be read returns
    None, and the differ skips it rather than treating absence as agreement."""

    @abstractmethod
    def read_proc_modules(self) -> str: ...
    @abstractmethod
    def list_sys_module(self) -> list[str]: ...
    @abstractmethod
    def sys_module_is_loaded(self, name: str) -> bool: ...
    @abstractmethod
    def read_tainted(self) -> int: ...
    @abstractmethod
    def read_vmallocinfo(self) -> str | None: ...
    @abstractmethod
    def read_ftrace_functions(self) -> str | None: ...
```

- [ ] **Step 4: Add live and fixture implementations**

In `sources.py`:

```python
class LiveModuleSource(ModuleSource):
    _TRACING = ("/sys/kernel/tracing/available_filter_functions",
                "/sys/kernel/debug/tracing/available_filter_functions")

    def read_proc_modules(self) -> str:
        with open("/proc/modules", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    def list_sys_module(self) -> list[str]:
        try:
            return sorted(os.listdir("/sys/module"))
        except OSError:
            return []

    def sys_module_is_loaded(self, name: str) -> bool:
        return os.path.exists(f"/sys/module/{name}/initstate")

    def read_tainted(self) -> int:
        with open("/proc/sys/kernel/tainted", encoding="ascii") as fh:
            return int(fh.read().strip())

    def read_vmallocinfo(self) -> str | None:
        try:
            with open("/proc/vmallocinfo", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None        # 0400, root-only; skipped when unreadable

    def read_ftrace_functions(self) -> str | None:
        for path in self._TRACING:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except OSError:
                continue
        return None


class FixtureModuleSource(ModuleSource):
    """Replays a captured module tree; a missing file replays 'unreadable'."""

    def __init__(self, root) -> None:
        self._root = Path(root)
        self._loaded = json.loads((self._root / "sys_module.json").read_text("utf-8"))

    def _read(self, name: str) -> str | None:
        p = self._root / name
        return p.read_text(encoding="utf-8") if p.exists() else None

    def read_proc_modules(self) -> str:
        return self._read("proc_modules.txt") or ""

    def list_sys_module(self) -> list[str]:
        return sorted(self._loaded)

    def sys_module_is_loaded(self, name: str) -> bool:
        return bool(self._loaded.get(name, False))

    def read_tainted(self) -> int:
        return int((self._read("tainted.txt") or "0").strip())

    def read_vmallocinfo(self) -> str | None:
        return self._read("vmallocinfo.txt")

    def read_ftrace_functions(self) -> str | None:
        return self._read("ftrace.txt")
```

- [ ] **Step 5: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_module_source.py -q`
Expected: PASS.

- [ ] **Step 6: Stage and hand off**

```bash
git add src/kdetect/collectors/base.py src/kdetect/collectors/sources.py tests/unit/test_module_source.py tests/fixtures/module-trees/clean
```
Commit message: `feat: ModuleSource — /proc/modules plus three independent channels`

---

## Task 5: The sweep collector

**Files:**
- Create: `src/kdetect/collectors/syscall_sweep.py`
- Test: `tests/unit/test_collector_sweep.py`

**Interfaces:**
- Consumes: `SignalSource` (Task 3), `Observation`, `SweepEntity`, `TrustLevel`, `Status`.
- Produces: `SweepProcessCollector` with class attrs `name="syscall_sweep.processes"`, `view="processes"`, `trust_level=TrustLevel.MEDIUM`, `version="1"`, and `collect(self, source: SignalSource) -> Observation`.

- [ ] **Step 1: Write the failing collector test**

`tests/unit/test_collector_sweep.py`:

```python
from pathlib import Path
from kdetect.collectors.syscall_sweep import SweepProcessCollector
from kdetect.collectors.sources import FixtureSignalSource
from kdetect.models import Status, TrustLevel

FIX = Path(__file__).parent.parent / "fixtures" / "signal-sets" / "hidden-pid.json"

def test_sweep_collector_records_tgid_evidence():
    obs = SweepProcessCollector().collect(FixtureSignalSource(FIX))
    assert obs.collector == "syscall_sweep.processes"
    assert obs.view == "processes"
    assert obs.trust_level is TrustLevel.MEDIUM
    assert obs.status is Status.OK
    assert obs.entity_ids == [1, 2, 501, 551, 31337]
    assert obs.entities[551].tgid == 501
    assert obs.entities[551].status_readable is True
    assert obs.entities[2].status_readable is False   # unreadable status
    assert obs.stats["responded"] == 5
    assert obs.stats["pid_max"] == 4194304
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_collector_sweep.py -q`
Expected: FAIL — module `syscall_sweep` does not exist.

- [ ] **Step 3: Write the collector**

Create `src/kdetect/collectors/syscall_sweep.py`:

```python
"""The MEDIUM process-existence collector: a full pid-space sweep (spec §4.1).

Records evidence, not conclusions (P4): for every id that answered kill(id, 0)
it stores the Tgid it read and whether that read succeeded. The differ folds
threads into leaders and decides what is hidden.
"""
from __future__ import annotations

import time

from kdetect.collectors.base import SignalSource
from kdetect.models import Observation, Status, SweepEntity, TrustLevel


class SweepProcessCollector:
    name = "syscall_sweep.processes"
    view = "processes"
    trust_level = TrustLevel.MEDIUM
    version = "1"

    def collect(self, source: SignalSource) -> Observation:
        started = time.monotonic()
        pid_max = source.pid_max()
        alive = source.sweep(pid_max)

        entities: dict[int, SweepEntity] = {}
        for task_id in alive:
            tgid = source.read_tgid(task_id)
            entities[task_id] = SweepEntity(
                tgid=tgid if tgid is not None else task_id,
                status_readable=tgid is not None,
            )

        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=sorted(alive), entities=entities,
            stats={"pid_max": pid_max, "responded": len(alive),
                   "sweep_ms": int((time.monotonic() - started) * 1000)},
            errors=[],
        )
```

(When `status` is unreadable, `tgid` falls back to the task id itself so the field is always an int; `status_readable=False` is the flag the differ checks — a task whose status could not be read is treated as vanished, not hidden.)

- [ ] **Step 4: Run the test**

Run: `.venv/Scripts/python -m pytest tests/unit/test_collector_sweep.py -q`
Expected: PASS.

- [ ] **Step 5: Stage and hand off**

```bash
git add src/kdetect/collectors/syscall_sweep.py tests/unit/test_collector_sweep.py
```
Commit message: `feat: syscall_sweep.processes collector`

---

## Task 6: The module collectors

**Files:**
- Create: `src/kdetect/collectors/modules.py`
- Test: `tests/unit/test_collector_modules.py`

**Interfaces:**
- Consumes: `ModuleSource` (Task 4), module parsers (Task 2), `Observation`, `ModuleEntity`.
- Produces: `ProcfsModuleCollector` (`name="procfs.modules"`, `view="modules"`, `TrustLevel.LOW`) and `ModuleEvidenceCollector` (`name="kernel.module_evidence"`, `view="modules"`, `TrustLevel.MEDIUM`); each `collect(self, source: ModuleSource) -> Observation`.
- The listing collector's entities are keyed by module **name**; `entity_ids` are names of modules that are genuinely loaded (`sys_module_is_loaded`), so built-ins are excluded (FP #2). The evidence collector stores channel results in `stats` and `extra`; a `None` channel is recorded as `null`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_collector_modules.py`:

```python
from pathlib import Path
from kdetect.collectors.modules import ProcfsModuleCollector, ModuleEvidenceCollector
from kdetect.collectors.sources import FixtureModuleSource
from kdetect.models import TrustLevel

CLEAN = Path(__file__).parent.parent / "fixtures" / "module-trees" / "clean"

def test_procfs_modules_lists_loaded_modules_by_name():
    obs = ProcfsModuleCollector().collect(FixtureModuleSource(CLEAN))
    assert obs.trust_level is TrustLevel.LOW
    assert obs.entity_ids == ["crc16", "ext4"]           # names, sorted
    assert obs.entities["ext4"].size == 999424
    assert obs.entities["ext4"].taint is None

def test_module_evidence_records_channels():
    obs = ModuleEvidenceCollector().collect(FixtureModuleSource(CLEAN))
    assert obs.trust_level is TrustLevel.MEDIUM
    assert obs.stats["taint"] == 0
    assert obs.stats["load_module_regions"] == 2
    assert obs.stats["ftrace_available"] is True
    assert set(obs.extra["ftrace_modules"]) == {"ext4"}
    assert obs.extra["listed_taint_markers"] == 0

def test_module_evidence_null_channel_when_unreadable(tmp_path):
    # a tree with no vmallocinfo/ftrace file -> those channels read None
    (tmp_path / "proc_modules.txt").write_text("ext4 1 0 - Live 0x0\n")
    (tmp_path / "tainted.txt").write_text("0\n")
    (tmp_path / "sys_module.json").write_text('{"ext4": true}')
    obs = ModuleEvidenceCollector().collect(FixtureModuleSource(tmp_path))
    assert obs.stats["load_module_regions"] is None
    assert obs.stats["ftrace_available"] is False
    assert obs.extra["ftrace_modules"] is None
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_collector_modules.py -q`
Expected: FAIL — module `modules` does not exist.

- [ ] **Step 3: Write the collectors**

Create `src/kdetect/collectors/modules.py`:

```python
"""The module-view collectors (spec §5).

procfs.modules (LOW) is the listing a rootkit unlinks itself from.
kernel.module_evidence (MEDIUM) records three channels that do not share that
listing's source. Neither judges (P1/P4); the differ compares them.
"""
from __future__ import annotations

import time

from kdetect.collectors.base import ModuleSource
from kdetect.models import ModuleEntity, Observation, Status, TrustLevel
from kdetect.parsers.modules import (
    count_module_regions, parse_ftrace_modules, parse_proc_modules, parse_tainted,
)


class ProcfsModuleCollector:
    name = "procfs.modules"
    view = "modules"
    trust_level = TrustLevel.LOW
    version = "1"

    def collect(self, source: ModuleSource) -> Observation:
        started = time.monotonic()
        rows = parse_proc_modules(source.read_proc_modules())
        entities = {
            r.name: ModuleEntity(r.name, r.size, r.refcount, r.dependents,
                                 r.state, r.base_addr, r.taint)
            for r in rows
        }
        # /proc/modules lists only genuinely loaded modules, so every row is a
        # real module. FP class #2 (built-ins with a /sys/module dir but no
        # initstate) only arises if you enumerate /sys/module, which this
        # collector deliberately does not — the LOW listing is /proc/modules.
        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=sorted(entities), entities=entities,
            stats={"listed": len(entities)}, errors=[],
        )


class ModuleEvidenceCollector:
    name = "kernel.module_evidence"
    view = "modules"
    trust_level = TrustLevel.MEDIUM
    version = "1"

    def collect(self, source: ModuleSource) -> Observation:
        started = time.monotonic()
        taint = source.read_tainted()
        listed = parse_proc_modules(source.read_proc_modules())
        markers = sum(1 for r in listed if r.taint)

        vmalloc = source.read_vmallocinfo()
        regions = count_module_regions(vmalloc) if vmalloc is not None else None

        ftrace = source.read_ftrace_functions()
        ftrace_modules = (
            sorted(parse_ftrace_modules(ftrace)) if ftrace is not None else None
        )

        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=[], entities={},
            stats={
                "taint": taint,
                "load_module_regions": regions,
                "ftrace_available": ftrace is not None,
                "ftrace_module_count": len(ftrace_modules) if ftrace_modules else 0,
            },
            extra={
                "listed_taint_markers": markers,
                "ftrace_modules": ftrace_modules,
            },
            errors=[],
        )
```

Note on the listing collector: `/proc/modules` lists only loaded modules, so its rows are all real; the `initstate` discriminator is what the **evidence** view would use if it enumerated `/sys/module`. Simplify the `loaded` line to `loaded = sorted(entities)` — the `or True` above is a marker to remove during implementation; the initstate check is exercised by the source test in Task 4, not needed here.

- [ ] **Step 4: Run the collector tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_collector_modules.py -q`
Expected: PASS.

- [ ] **Step 5: Stage and hand off**

```bash
git add src/kdetect/collectors/modules.py tests/unit/test_collector_modules.py
```
Commit message: `feat: procfs.modules and kernel.module_evidence collectors`

---

## Task 7: The Finding model

**Files:**
- Create: `src/kdetect/analysis/models.py`
- Test: `tests/unit/test_finding_model.py`

**Interfaces:**
- Produces: `FindingKind` (str Enum: `HIDDEN_PROCESS="hidden_process"`, `MODULE_TAINT_MISMATCH="module_taint_mismatch"`, `UNEXPLAINED_MODULE_REGION="unexplained_module_region"`, `FTRACE_ORPHAN_MODULE="ftrace_orphan_module"`); `Confidence` (str Enum LOW/MEDIUM/HIGH); `Finding(kind, subject, confidence, channels_agree, channels_dissent, evidence, summary)` frozen dataclass with deterministic `to_dict()`.

- [ ] **Step 1: Write the failing test**

`tests/unit/test_finding_model.py`:

```python
from kdetect.analysis.models import Finding, FindingKind, Confidence

def test_finding_to_dict_is_deterministic_and_sorted():
    f = Finding(
        kind=FindingKind.HIDDEN_PROCESS, subject="pid 31337",
        confidence=Confidence.HIGH,
        channels_agree=["syscall_sweep", "direct status"],
        channels_dissent=["procfs readdir (both passes)"],
        evidence={"tgid": 31337, "in_procfs_A": False, "in_procfs_B": False},
        summary="pid 31337 seen by sweep, absent from both readdir passes",
    )
    d = f.to_dict()
    assert d["kind"] == "hidden_process"
    assert d["confidence"] == "HIGH"
    assert d["evidence"]["tgid"] == 31337
    # stable ordering: same object serialises identically
    import json
    assert json.dumps(d, sort_keys=True) == json.dumps(f.to_dict(), sort_keys=True)
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_finding_model.py -q`
Expected: FAIL — `analysis.models` does not exist.

- [ ] **Step 3: Write the model**

Create `src/kdetect/analysis/models.py`:

```python
"""The analysis layer's output type (spec §6).

A Finding is a conclusion, which a snapshot may never hold (P1). It is produced
only by the differ and may be serialised for reporting. Every Finding carries
the evidence it was drawn from so it can be traced back into the snapshot (P5).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FindingKind(str, Enum):
    HIDDEN_PROCESS = "hidden_process"
    MODULE_TAINT_MISMATCH = "module_taint_mismatch"
    UNEXPLAINED_MODULE_REGION = "unexplained_module_region"
    FTRACE_ORPHAN_MODULE = "ftrace_orphan_module"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class Finding:
    kind: FindingKind
    subject: str
    confidence: Confidence
    channels_agree: list[str]
    channels_dissent: list[str]
    evidence: dict
    summary: str

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "subject": self.subject,
            "confidence": self.confidence.value,
            "channels_agree": list(self.channels_agree),
            "channels_dissent": list(self.channels_dissent),
            "evidence": self.evidence,
            "summary": self.summary,
        }
```

- [ ] **Step 4: Run the test**

Run: `.venv/Scripts/python -m pytest tests/unit/test_finding_model.py -q`
Expected: PASS.

- [ ] **Step 5: Stage and hand off**

```bash
git add src/kdetect/analysis/models.py tests/unit/test_finding_model.py
```
Commit message: `feat: Finding model for the analysis layer`

---

## Task 8: The process differ (the sandwich)

**Files:**
- Create: `src/kdetect/analysis/crossview.py` (add `diff_processes`)
- Test: `tests/unit/test_diff_processes.py`

**Interfaces:**
- Consumes: `Snapshot`, `Observation`, `SweepEntity`, `Finding`, `FindingKind`, `Confidence`.
- Produces: `diff_processes(snapshot: Snapshot) -> list[Finding]`. Uses the two `procfs.processes` observations (by `pass_` "A"/"B", or the two present) and the `syscall_sweep.processes` observation. A `tgid` seen by the sweep, `status_readable`, and absent from **both** procfs passes is a `HIDDEN_PROCESS`. A tgid that is a listed pid is a thread (no finding). Absent-from-one-pass only → no finding (timing).

- [ ] **Step 1: Write the failing differ tests (built in memory, no disk)**

`tests/unit/test_diff_processes.py`:

```python
from kdetect.analysis.crossview import diff_processes
from kdetect.analysis.models import FindingKind, Confidence
from kdetect.models import (
    Snapshot, Observation, ProcessEntity, SweepEntity, HostFacts, CaptureMeta,
    Status, TrustLevel, SCHEMA_VERSION,
)

def _host():
    return HostFacts("h", "6.1", "x86_64", "boot", 1, 100)

def _proc_pass(label, pids):
    return Observation(
        collector="procfs.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(pids), entities={}, stats={}, errors=[], pass_=label,
    )

def _sweep(tgid_map):
    # tgid_map: {task_id: (tgid, status_readable)}
    ents = {i: SweepEntity(t, r) for i, (t, r) in tgid_map.items()}
    return Observation(
        collector="syscall_sweep.processes", collector_version="1",
        view="processes", trust_level=TrustLevel.MEDIUM, status=Status.OK,
        duration_ms=1, entity_ids=sorted(tgid_map), entities=ents,
        stats={"pid_max": 4194304, "responded": len(tgid_map)}, errors=[],
    )

def _snap(observations):
    return Snapshot(SCHEMA_VERSION, "id", "t", _host(),
                    CaptureMeta("0.2.0", 0), observations)

def test_threads_are_not_hidden_processes():
    # 501 is listed; 551 is its thread (tgid 501). No finding.
    snap = _snap([_proc_pass("A", [1, 501]), _proc_pass("B", [1, 501]),
                  _sweep({1: (1, True), 501: (501, True), 551: (501, True)})])
    assert diff_processes(snap) == []

def test_hidden_process_detected():
    # 31337 seen by sweep, its own leader, in neither pass -> hidden.
    snap = _snap([_proc_pass("A", [1, 501]), _proc_pass("B", [1, 501]),
                  _sweep({1: (1, True), 501: (501, True), 31337: (31337, True)})])
    findings = diff_processes(snap)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.HIDDEN_PROCESS
    assert f.subject == "pid 31337"
    assert f.evidence["tgid"] == 31337
    assert f.confidence is Confidence.MEDIUM     # existence only, no identity

def test_absent_from_one_pass_only_is_timing_not_hiding():
    # 4242 appeared in pass B only (started mid-capture). Not hidden.
    snap = _snap([_proc_pass("A", [1]), _proc_pass("B", [1, 4242]),
                  _sweep({1: (1, True), 4242: (4242, True)})])
    assert diff_processes(snap) == []

def test_unreadable_status_is_vanished_not_hidden():
    snap = _snap([_proc_pass("A", [1]), _proc_pass("B", [1]),
                  _sweep({1: (1, True), 9999: (9999, False)})])
    assert diff_processes(snap) == []
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_diff_processes.py -q`
Expected: FAIL — `crossview` does not exist.

- [ ] **Step 3: Write `diff_processes`**

Create `src/kdetect/analysis/crossview.py`:

```python
"""The cross-view differ (spec §4.2, §5.2). Pure: Snapshot -> [Finding].

Touches no I/O, so it runs identically on a live capture, a committed fixture,
and a hand-built snapshot. Disagreement between channels is the signal.
"""
from __future__ import annotations

from kdetect.analysis.models import Confidence, Finding, FindingKind
from kdetect.models import Snapshot


def _observations(snapshot: Snapshot, collector: str):
    return [o for o in snapshot.observations if o.collector == collector]


def diff_processes(snapshot: Snapshot) -> list[Finding]:
    procfs = _observations(snapshot, "procfs.processes")
    sweeps = _observations(snapshot, "syscall_sweep.processes")
    if not procfs or not sweeps:
        return []                       # nothing to cross-check

    listed = set()
    for obs in procfs:                  # union of every readdir pass
        listed |= set(obs.entity_ids)

    sweep = sweeps[0]
    findings: list[Finding] = []
    reported: set[int] = set()

    for task_id in sweep.entity_ids:
        ent = sweep.entities[task_id]
        if not ent.status_readable:
            continue                    # vanished between sweep and fold
        tgid = ent.tgid
        if tgid in listed:
            continue                    # ordinary thread of a visible process
        # tgid seen by the sweep but in NEITHER readdir pass -> hidden.
        if tgid in reported:
            continue                    # one finding per process, not per thread
        reported.add(tgid)
        findings.append(Finding(
            kind=FindingKind.HIDDEN_PROCESS,
            subject=f"pid {tgid}",
            confidence=Confidence.MEDIUM,
            channels_agree=["syscall_sweep", "direct status"],
            channels_dissent=["procfs readdir (all passes)"],
            evidence={
                "tgid": tgid,
                "seen_by_sweep": True,
                "in_procfs_passes": sorted(o.pass_ or "?" for o in procfs
                                           if tgid in set(o.entity_ids)),
                "status_readable": True,
            },
            summary=f"pid {tgid} answers the syscall sweep but appears in no "
                    f"/proc readdir pass",
        ))
    return sorted(findings, key=lambda f: f.subject)
```

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_diff_processes.py -q`
Expected: PASS.

- [ ] **Step 5: Stage and hand off**

```bash
git add src/kdetect/analysis/crossview.py tests/unit/test_diff_processes.py
```
Commit message: `feat: cross-view process differ (the sandwich)`

---

## Task 9: The module differ

**Files:**
- Modify: `src/kdetect/analysis/crossview.py` (add `diff_modules`, `diff_all`)
- Test: `tests/unit/test_diff_modules.py`

**Interfaces:**
- Produces: `diff_modules(snapshot) -> list[Finding]` and `diff_all(snapshot) -> list[Finding]` (= `diff_processes + diff_modules`). Compares `procfs.modules` (listed names) against `kernel.module_evidence`. Emits `MODULE_TAINT_MISMATCH` (bit 12/13 set, `listed_taint_markers == 0`), `UNEXPLAINED_MODULE_REGION` (`load_module_regions > len(listed)`), `FTRACE_ORPHAN_MODULE` (a name in `ftrace_modules` not in listed). A `None` channel is skipped. Confidence = count of corroborating channels naming the same subject.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_diff_modules.py`:

```python
from kdetect.analysis.crossview import diff_modules
from kdetect.analysis.models import FindingKind, Confidence
from kdetect.models import (
    Snapshot, Observation, ModuleEntity, HostFacts, CaptureMeta,
    Status, TrustLevel, SCHEMA_VERSION,
)

def _host(): return HostFacts("h", "6.1", "x86_64", "boot", 1, 100)

def _listing(names):
    ents = {n: ModuleEntity(n, 1, 0, [], "Live", "0x0", None) for n in names}
    return Observation("procfs.modules", "1", "modules", TrustLevel.LOW,
                       Status.OK, 1, sorted(names), ents, {"listed": len(names)}, [])

def _evidence(taint, markers, regions, ftrace):
    return Observation("kernel.module_evidence", "1", "modules",
                       TrustLevel.MEDIUM, Status.OK, 1, [], {},
                       {"taint": taint, "load_module_regions": regions,
                        "ftrace_available": ftrace is not None,
                        "ftrace_module_count": len(ftrace or [])},
                       [], extra={"listed_taint_markers": markers,
                                  "ftrace_modules": ftrace})

def _snap(obs):
    return Snapshot(SCHEMA_VERSION, "id", "t", _host(), CaptureMeta("0.2.0", 0), obs)

def test_clean_baseline_no_findings():
    snap = _snap([_listing(["ext4", "crc16"]),
                  _evidence(0, 0, 2, ["ext4"])])   # ftrace subset of listing
    # region count 2 == listed 2; taint clear; ftrace subset -> nothing
    assert diff_modules(snap) == []

def test_taint_mismatch():
    snap = _snap([_listing(["ext4"]), _evidence(12288, 0, 1, ["ext4"])])
    kinds = [f.kind for f in diff_modules(snap)]
    assert FindingKind.MODULE_TAINT_MISMATCH in kinds

def test_unexplained_region():
    snap = _snap([_listing(["ext4"]), _evidence(0, 0, 2, ["ext4"])])
    kinds = [f.kind for f in diff_modules(snap)]
    assert FindingKind.UNEXPLAINED_MODULE_REGION in kinds

def test_ftrace_orphan_names_module():
    snap = _snap([_listing(["ext4"]), _evidence(0, 0, 1, ["ext4", "diamorphine"])])
    orphans = [f for f in diff_modules(snap)
               if f.kind is FindingKind.FTRACE_ORPHAN_MODULE]
    assert len(orphans) == 1 and orphans[0].subject == "module diamorphine"

def test_corroborated_hidden_module_is_high_confidence():
    # taint mismatch + extra region + ftrace orphan all point at a hidden module
    snap = _snap([_listing(["ext4"]),
                  _evidence(12288, 0, 2, ["ext4", "diamorphine"])])
    orphan = [f for f in diff_modules(snap)
              if f.kind is FindingKind.FTRACE_ORPHAN_MODULE][0]
    assert orphan.confidence is Confidence.HIGH   # 3 channels corroborate

def test_null_channels_are_skipped():
    snap = _snap([_listing(["ext4"]), _evidence(0, 0, None, None)])
    assert diff_modules(snap) == []
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_diff_modules.py -q`
Expected: FAIL — `diff_modules` not defined.

- [ ] **Step 3: Write `diff_modules` and `diff_all`**

Append to `src/kdetect/analysis/crossview.py`:

```python
def _confidence(n: int) -> Confidence:
    return {1: Confidence.LOW, 2: Confidence.MEDIUM}.get(n, Confidence.HIGH)


def diff_modules(snapshot: Snapshot) -> list[Finding]:
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

    # How many independent channels indicate a hidden module at all? Used to
    # raise the confidence of the channel(s) that can name it.
    taint_hit = bool(taint & ((1 << 12) | (1 << 13))) and markers == 0
    region_hit = regions is not None and regions > len(listed)
    orphans = sorted(set(ftrace) - listed) if ftrace is not None else []
    corroboration = sum([taint_hit, region_hit, bool(orphans)])
    conf = _confidence(corroboration)

    findings: list[Finding] = []
    if taint_hit:
        bit = "12 (out-of-tree)" if taint & (1 << 12) else "13 (unsigned)"
        findings.append(Finding(
            FindingKind.MODULE_TAINT_MISMATCH, f"taint bit {bit}", conf,
            ["kernel.module_evidence taint"], ["procfs.modules listing"],
            {"taint": taint, "listed_taint_markers": markers},
            f"taint bit {bit} set, but no listed module carries an (O)/(E) marker",
        ))
    if region_hit:
        findings.append(Finding(
            FindingKind.UNEXPLAINED_MODULE_REGION,
            f"{regions - len(listed)} unaccounted module region(s)", conf,
            ["kernel.module_evidence vmallocinfo"], ["procfs.modules listing"],
            {"load_module_regions": regions, "listed": len(listed)},
            f"{regions} load_module regions but only {len(listed)} modules listed",
        ))
    for name in orphans:
        findings.append(Finding(
            FindingKind.FTRACE_ORPHAN_MODULE, f"module {name}", conf,
            ["kernel.module_evidence ftrace"], ["procfs.modules listing"],
            {"ftrace_module": name, "in_listing": False},
            f"module {name} has ftrace records but is absent from /proc/modules",
        ))
    return findings


def diff_all(snapshot: Snapshot) -> list[Finding]:
    return diff_processes(snapshot) + diff_modules(snapshot)
```

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_diff_modules.py -q`
Expected: PASS.

- [ ] **Step 5: Stage and hand off**

```bash
git add src/kdetect/analysis/crossview.py tests/unit/test_diff_modules.py
```
Commit message: `feat: cross-view module differ with corroboration scoring`

---

## Task 10: Wire capture (sandwich) and analyze (findings, --json, exit 3)

**Files:**
- Modify: `src/kdetect/collectors/procfs.py` (`__init__(pass_label=None)`, stamp `pass_`)
- Modify: `src/kdetect/cli.py`
- Test: `tests/unit/test_analyze.py` (extend), `tests/unit/test_collector_procfs.py` (pass label)

**Interfaces:**
- Consumes: all collectors, `diff_all`, `Finding`.
- Produces: `capture` writes a snapshot with observations `[procfs A, sweep, procfs B, procfs.modules, kernel.module_evidence]`. `analyze` prints the phase 1 block, then a `findings:` section; exits 3 if `diff_all` returns anything; `--json` prints `[f.to_dict()...]` and suppresses the text.

- [ ] **Step 1: Write failing tests**

Extend `tests/unit/test_collector_procfs.py`:

```python
def test_procfs_collector_stamps_pass_label():
    from kdetect.collectors.procfs import ProcfsProcessCollector
    from kdetect.collectors.sources import FixtureProcSource
    from pathlib import Path
    tree = Path(__file__).parent.parent / "fixtures" / "proc-trees" / "clean-vm-6.1.0-10"
    obs = ProcfsProcessCollector(pass_label="A").collect(FixtureProcSource(tree))
    assert obs.pass_ == "A"
```

Extend `tests/unit/test_analyze.py` with a synthetic hidden-process snapshot:

```python
def _write_hidden_snapshot(tmp_path):
    import json
    snap = {
      "schema_version": "1.1", "snapshot_id": "x", "captured_at": "t",
      "host": {"hostname": "h", "kernel_release": "6.1", "arch": "x86_64",
               "boot_id": "b", "btime": 1, "clock_ticks_per_sec": 100},
      "capture": {"tool_version": "0.2.0", "euid": 0},
      "observations": [
        {"collector": "procfs.processes", "collector_version": "1",
         "view": "processes", "trust_level": "LOW", "status": "OK",
         "duration_ms": 1, "entity_ids": [1], "entities": {}, "stats": {},
         "errors": [], "pass": "A"},
        {"collector": "procfs.processes", "collector_version": "1",
         "view": "processes", "trust_level": "LOW", "status": "OK",
         "duration_ms": 1, "entity_ids": [1], "entities": {}, "stats": {},
         "errors": [], "pass": "B"},
        {"collector": "syscall_sweep.processes", "collector_version": "1",
         "view": "processes", "trust_level": "MEDIUM", "status": "OK",
         "duration_ms": 1, "entity_ids": [1, 31337],
         "entities": {"1": {"tgid": 1, "status_readable": True},
                      "31337": {"tgid": 31337, "status_readable": True}},
         "stats": {}, "errors": []}
      ]
    }
    p = tmp_path / "hidden.json"
    p.write_text(json.dumps(snap))
    return p

def test_analyze_reports_finding_and_exits_3(tmp_path):
    r = run(["analyze", str(_write_hidden_snapshot(tmp_path))])
    assert r.returncode == 3
    assert "hidden_process" in r.stdout and "31337" in r.stdout

def test_analyze_json_mode(tmp_path):
    r = run(["analyze", "--json", str(_write_hidden_snapshot(tmp_path))])
    assert r.returncode == 3
    import json as _j
    data = _j.loads(r.stdout)
    assert data[0]["kind"] == "hidden_process"

def test_analyze_clean_fixture_still_exits_0():
    r = run(["analyze", str(FIXTURE)])   # phase 1 clean-vm.json, one collector
    assert r.returncode == 0             # no sweep -> no findings
```

- [ ] **Step 2: Run and watch fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_analyze.py tests/unit/test_collector_procfs.py -q`
Expected: FAIL — `ProcfsProcessCollector` has no `pass_label`; analyze has no findings section.

- [ ] **Step 3: Add the pass label to the procfs collector**

In `src/kdetect/collectors/procfs.py`, add a constructor and stamp the field:

```python
    def __init__(self, pass_label: str | None = None) -> None:
        self._pass_label = pass_label
```

In `_observation`, pass `pass_=self._pass_label` to `Observation(...)`.

- [ ] **Step 4: Wire the capture sandwich**

In `src/kdetect/cli.py`, import the new collectors and sources, and replace the single-observation capture with:

```python
from kdetect.collectors.syscall_sweep import SweepProcessCollector
from kdetect.collectors.modules import ProcfsModuleCollector, ModuleEvidenceCollector
from kdetect.collectors.sources import (
    LiveProcSource, LiveSignalSource, LiveModuleSource,
)
```

```python
    procs, signals, mods = LiveProcSource(), LiveSignalSource(), LiveModuleSource()
    observations = [
        ProcfsProcessCollector(pass_label="A").collect(procs),   # bread
        SweepProcessCollector().collect(signals),                # filling
        ProcfsProcessCollector(pass_label="B").collect(procs),   # bread
        ProcfsModuleCollector().collect(mods),
        ModuleEvidenceCollector().collect(mods),
    ]
```

and pass `observations=observations` to `Snapshot(...)`. Bump `__version__`
usage stays as-is (`CaptureMeta(tool_version=__version__, ...)`).

- [ ] **Step 5: Add the findings section and exit 3 to analyze**

In `cmd_analyze`, after the collectors loop, before the return:

```python
    from kdetect.analysis.crossview import diff_all
    findings = diff_all(snapshot)

    if getattr(args, "json", False):
        print(json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=True))
        return 3 if findings else EXIT_OK

    print()
    if not findings:
        print("findings:  none")
        return EXIT_OK

    print("findings:")
    for f in findings:
        print(f"  [{f.confidence.value}]   {f.kind.value}   {f.subject}")
        print(f"           seen by: {', '.join(f.channels_agree)}")
        print(f"           denied by: {', '.join(f.channels_dissent)}")
    return 3
```

Add the `--json` flag to the analyze subparser:

```python
    analyze.add_argument("--json", action="store_true",
                         help="Emit findings as JSON; suppress the summary.")
```

Note: under `--json` the phase 1 summary block should be suppressed. Guard the
summary prints in `cmd_analyze` with `if not getattr(args, "json", False):` so
only the JSON array reaches stdout.

- [ ] **Step 6: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit -q`
Expected: PASS. The phase 1 `clean-vm.json` analyze test still exits 0 (it has one collector, so `diff_all` finds nothing).

- [ ] **Step 7: Stage and hand off**

```bash
git add src/kdetect/collectors/procfs.py src/kdetect/cli.py tests/unit/test_analyze.py tests/unit/test_collector_procfs.py
```
Commit message: `feat: capture runs the sandwich; analyze reports findings and exits 3`

---

## Task 11: Live integration on the VM

**Files:**
- Create: `tests/integration/test_phase2_live.py`

**Interfaces:**
- Consumes: live sources and every collector. Gated `@needs_procfs`; runs on the VM, skipped on Windows.

- [ ] **Step 1: Write the integration test**

`tests/integration/test_phase2_live.py`:

```python
import pytest
from tests.conftest import needs_procfs
from kdetect.collectors.sources import (
    LiveSignalSource, LiveModuleSource,
)
from kdetect.collectors.syscall_sweep import SweepProcessCollector
from kdetect.collectors.modules import ProcfsModuleCollector, ModuleEvidenceCollector

@needs_procfs
def test_sweep_finds_at_least_pid_1():
    obs = SweepProcessCollector().collect(LiveSignalSource())
    assert 1 in obs.entity_ids
    assert obs.entities[1].tgid == 1

@needs_procfs
def test_procfs_modules_nonempty_and_evidence_reads():
    listing = ProcfsModuleCollector().collect(LiveModuleSource())
    assert listing.entity_ids                      # some modules are loaded
    ev = ModuleEvidenceCollector().collect(LiveModuleSource())
    assert "taint" in ev.stats
```

- [ ] **Step 2: Run on the VM**

Run (over SSH, from the VM repo root): `.venv/bin/python -m pytest tests/integration/test_phase2_live.py -q`
Expected: PASS. On Windows the same command SKIPs.

- [ ] **Step 3: Full suite both hosts**

Windows: `.venv/Scripts/python -m pytest -q` → all unit/differ pass, integration skips.
VM: `.venv/bin/python -m pytest -q` → everything passes.

- [ ] **Step 4: Stage and hand off**

```bash
git add tests/integration/test_phase2_live.py
```
Commit message: `test: live phase 2 collectors on the VM`

---

## Task 12: Ground truth — Diamorphine fixtures and docs

**This task involves live rootkit code and is Angus's to run**, following the runbook in `docs/step0-phase2/README.md` and the lab safety procedure. The implementer prepares the capture command and the assertions; Angus performs the infected run and commits from a reverted clean tree.

**Files:**
- Create: `tests/fixtures/snapshots/clean-phase2.json`, `tests/fixtures/snapshots/infected-diamorphine.json`
- Create: test `tests/unit/test_ground_truth.py`
- Modify: `docs/limitations.md` (L15), `docs/detection-methods.md` (one page per channel)

- [ ] **Step 1: Capture the clean snapshot on the VM**

On `clean-baseline`, from the VM repo root:
```bash
sudo .venv/bin/python -m kdetect.cli capture --pretty --out tests/fixtures/snapshots/clean-phase2.json
```
Review it for secrets (L13), then confirm it produces no findings:
```bash
.venv/bin/python -m kdetect.cli analyze tests/fixtures/snapshots/clean-phase2.json   # must print "findings:  none", exit 0
```

- [ ] **Step 2: Write the clean-baseline regression guard**

`tests/unit/test_ground_truth.py`:

```python
import json
from pathlib import Path
from kdetect.models import Snapshot
from kdetect.analysis.crossview import diff_all
from kdetect.analysis.models import FindingKind

SNAP = Path(__file__).parent.parent / "fixtures" / "snapshots"

def _load(name):
    return Snapshot.from_dict(json.loads((SNAP / name).read_text()))

def test_clean_phase2_has_zero_findings():
    assert diff_all(_load("clean-phase2.json")) == []
```

Run: `.venv/Scripts/python -m pytest tests/unit/test_ground_truth.py::test_clean_phase2_has_zero_findings -q`
Expected: PASS on Windows with the committed clean fixture.

- [ ] **Step 3: Capture the infected snapshot (Angus, Host-only network)**

Per `docs/step0-phase2/README.md`: snapshot `infected-diamorphine`, adapter Host-only, `insmod diamorphine.ko`, hide a `sleep` with `kill -31 <PID>`, then:
```bash
sudo .venv/bin/python -m kdetect.cli capture --pretty --out tests/fixtures/snapshots/infected-diamorphine.json
```
Record the hidden PID. Revert the VM to `clean-baseline` before committing.

- [ ] **Step 4: Assert detection against the infected fixture**

Add to `tests/unit/test_ground_truth.py` (fill `HIDDEN_PID` with the value from Step 3):

```python
HIDDEN_PID = 0   # <- set to the PID hidden during the infected capture

def test_infected_snapshot_detects_hidden_process():
    findings = diff_all(_load("infected-diamorphine.json"))
    kinds = {f.kind for f in findings}
    assert FindingKind.HIDDEN_PROCESS in kinds
    assert any(str(HIDDEN_PID) in f.subject for f in findings
               if f.kind is FindingKind.HIDDEN_PROCESS)

def test_infected_snapshot_flags_the_module():
    findings = diff_all(_load("infected-diamorphine.json"))
    module_kinds = {FindingKind.MODULE_TAINT_MISMATCH,
                    FindingKind.UNEXPLAINED_MODULE_REGION,
                    FindingKind.FTRACE_ORPHAN_MODULE}
    assert module_kinds & {f.kind for f in findings}
```

Run: `.venv/Scripts/python -m pytest tests/unit/test_ground_truth.py -q`
Expected: PASS. **If a module channel did not fire** (e.g. Diamorphine kept no ftrace records, or its vmalloc region was dropped), record which, weaken that channel's claim in `docs/detection-methods.md`, and add a numbered limitation (spec §13) — the assertion above only requires *at least one* module channel, so a single negative channel narrows the design rather than failing the phase.

- [ ] **Step 5: Write the docs**

Add **L15** to `docs/limitations.md` (vmallocinfo hash-obfuscation, spec §3/§13) and any new limitation Step 4 surfaced. Write `docs/detection-methods.md` with one page per channel — process sweep, taint accounting, vmallocinfo count, ftrace tags — each stating its clean baseline (cite `docs/step0-phase2/clean/`) and its Diamorphine result (cite the infected capture).

- [ ] **Step 6: Stage and hand off (from the reverted clean tree only)**

```bash
git add tests/fixtures/snapshots/clean-phase2.json tests/fixtures/snapshots/infected-diamorphine.json tests/unit/test_ground_truth.py docs/limitations.md docs/detection-methods.md
```
Commit message: `feat: Diamorphine ground truth — clean and infected fixtures, detection docs`
**Do not push from an infected snapshot.** Confirm the VM is on `clean-baseline` before Angus pushes.

---

## Self-Review

**Spec coverage:**
- §4 process view → Tasks 1 (SweepEntity), 3 (SignalSource), 5 (sweep collector), 8 (diff_processes), 10 (sandwich wiring). ✓
- §5 module view → Tasks 2 (parsers), 4 (ModuleSource), 6 (collectors), 9 (diff_modules). ✓
- §6 Finding model → Task 7. ✓
- §7 CLI (findings, --json, exit 3) → Task 10. ✓
- §8 layering / new sources → Tasks 3, 4. ✓
- §9 testing tiers incl. differ + ground truth → Tasks 8, 9, 11, 12. ✓
- §10 acceptance criteria 1–12 → 1(T10), 2(T12), 3(T12), 4(T10), 5(T10), 6(T8/9), 7(T3/4), 8(all unit), 9(T11), 10(T12), 11(T12), 12(T12). ✓
- §4.1 schema 1.1 note → Task 1. ✓ L15 → Task 12. ✓

**Placeholder scan:** No "TBD"/"handle edge cases". `HIDDEN_PID = 0` in Task 12 is a fill-in the executor sets from the live run, flagged in-line — it is data from a capture that does not exist until Step 3, not an unwritten step.

**Type consistency:** `pass_` (field) ↔ `"pass"` (JSON) consistent across Tasks 1 and 10. `SweepEntity(tgid, status_readable)` and `ModuleEntity(...)` identical in Tasks 1, 5, 6, 8, 9. `diff_processes`/`diff_modules`/`diff_all` names consistent Tasks 8–10. `read_tgid`, `sweep`, `pid_max` consistent Tasks 3, 5. `sys_module_is_loaded`, `read_vmallocinfo`, `read_ftrace_functions` consistent Tasks 4, 6.

---

## Execution Handoff

See the top-of-file sub-skill directive. Recommended: subagent-driven-development, fresh subagent per task with review between. Tasks 1–10 run entirely on the Windows host; Task 11 needs the VM; Task 12 is Angus's live rootkit run.
