# kdetect Phase 1 Implementation Plan

> **Execution mode: coach.** Angus writes all implementation code. Claude
> reviews at the checkpoint that ends each task. Steps use checkbox
> (`- [ ]`) syntax for tracking.

**Goal:** A `capture` → JSON → `analyze` round-trip using one procfs collector,
with no detection logic, proving the data model before anything is built on it.

**Architecture:** Three layers with a hard I/O seam — a `ProcSource` that owns all
filesystem access, pure parse functions that never touch the OS, and a `Collector`
that assembles an `Observation` from them. Collectors receive their source as an
argument, so a fixture-driven test runs the identical code path as a live capture.

**Tech Stack:** Python 3.11 (Debian 12 default), stdlib only — `dataclasses`,
`argparse`, `json`, `enum`, `pathlib`. `pytest` for tests. No runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-08-18-kdetect-phase1-design.md`

---

## Conventions for this plan

**Tests are given in full.** Copy them. They encode the specification, and the
Step 0 evidence they are drawn from is cited so you can check them against what
you actually observed.

**Implementation steps give a signature and an algorithm, not a finished body.**
That is deliberate — you are writing this code to learn kernel-facing data
handling. Where a step says "raise `ParseError` if fewer than 20 fields remain",
that is a requirement to implement, not a gap in the plan.

**Ask for review at the end of each task**, before moving to the next. Paste the
diff or push the branch.

---

## Global Constraints

Copied verbatim from the spec. Every task's requirements implicitly include these.

- **Python 3.11+**, standard library only. No runtime dependencies. `pytest` is a
  dev dependency.
- **`schema_version` is `"1.0"`.** MAJOR mismatch refuses to load; MINOR is
  additive-only and loads with a stderr warning.
- **Serialisation is deterministic:** `json.dump(..., sort_keys=True,
  separators=(",", ":"))`; `--pretty` uses `indent=2` with `sort_keys=True`.
- **`entity_ids` is unique and sorted ascending.** `partial` is sorted
  alphabetically. `errors` follow `entity_ids` order.
- **Timestamps are UTC ISO-8601, millisecond precision, `Z` suffix.**
- **Exit codes:** `0` success, `1` error, `2` usage. **`3` is reserved** for
  "analysis produced findings" and must not be used in phase 1.
- **P1 — evidence, not conclusions.** Collectors record raw observations. No
  derived or judged fields in the data model.
- **P3 — one code path.** No `if testing:` branches. Sources are injected.
- Capture filenames contain **no `:` characters** (illegal on Windows).

---

## File structure

| File | Responsibility |
|---|---|
| `pyproject.toml` | Packaging, `kdetect` entry point, pytest config |
| `src/kdetect/__init__.py` | `__version__` only |
| `src/kdetect/parsers/procfs.py` | Pure parse functions + `ParseError` |
| `src/kdetect/models.py` | Enums, entities, `Observation`, `Snapshot`, serialisation |
| `src/kdetect/collectors/base.py` | `ProcSource` ABC, `Collector` ABC, source errors |
| `src/kdetect/collectors/sources.py` | `LiveProcSource`, `FixtureProcSource` |
| `src/kdetect/collectors/procfs.py` | `ProcfsProcessCollector` |
| `src/kdetect/cli.py` | `argparse`, `capture`, `analyze` |
| `tools/capture-fixture.sh` | Lab utility that builds a fixture tree |

**Note on `parsers/`:** the original project tree had no such package. It is added
here to make spec §4.1's three layers visible in the directory structure — parse
functions are pure and shared, and burying them inside a collector would invite
the I/O seam to erode.

---

## Task 1: Skeleton and CLI stub

**Files:**
- Create: `pyproject.toml`, `src/kdetect/__init__.py`, `src/kdetect/cli.py`
- Create: `tests/conftest.py`

**Interfaces:**
- Produces: `kdetect.__version__: str`; `kdetect.cli.main(argv: list[str] | None = None) -> int`

- [ ] **Step 1: Create the virtualenv and install pytest**

```bash
cd ~/projects/kdetect && python3 -m venv .venv && . .venv/bin/activate && pip install pytest
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "kdetect"
version = "0.1.0"
description = "Linux kernel rootkit detection via cross-view comparison"
requires-python = ">=3.11"
dependencies = []

[project.scripts]
kdetect = "kdetect.cli:cli_entry"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["needs_procfs: requires a live /proc filesystem"]
```

- [ ] **Step 3: Write `src/kdetect/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 4: Write `tests/conftest.py`**

```python
from pathlib import Path
import pytest

HAS_PROCFS = Path("/proc/self/stat").exists()

needs_procfs = pytest.mark.skipif(
    not HAS_PROCFS, reason="requires a live /proc filesystem"
)
```

Gate on the capability, not `sys.platform` — what the tests need is a procfs, not
an operating system name.

- [ ] **Step 5: Write the CLI stub**

Create `src/kdetect/cli.py`.

Required behaviour:
- `main(argv: list[str] | None = None) -> int` builds an `argparse.ArgumentParser`
  with `prog="kdetect"` and two subparsers, `capture` and `analyze`.
- `capture` accepts `--out PATH` (default `None`) and `--pretty` (store_true).
- `analyze` accepts one positional argument `snapshot`.
- Both subcommands currently `return 0` without doing anything.
- If no subcommand is given, print help and return `2`.
- `cli_entry()` is a thin wrapper: `raise SystemExit(main())`.
- The module must end with `if __name__ == "__main__": raise SystemExit(main())`.
  Tasks 9 and 10 invoke the CLI as `python -m kdetect.cli` in subprocess tests,
  which needs this guard as well as the console-script entry point.

- [ ] **Step 6: Install editable and verify**

```bash
pip install -e . && kdetect capture --help && kdetect analyze --help && kdetect; echo "exit=$?"
```

Expected: both help texts render; the bare `kdetect` prints help and reports
`exit=2`.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/kdetect/__init__.py src/kdetect/cli.py tests/conftest.py && git commit -m "feat: project skeleton and CLI stub"
```

**Satisfies acceptance criterion 1.** → **Review checkpoint.**

---

## Task 2: `parse_stat`

The single most error-prone parser in the project. Test first.

**Files:**
- Create: `src/kdetect/parsers/__init__.py`, `src/kdetect/parsers/procfs.py`
- Test: `tests/unit/test_parse_stat.py`

**Interfaces:**
- Produces:
  - `ParseError(ValueError)`
  - `StatFields` frozen dataclass with fields `pid: int`, `comm: str`,
    `state: str`, `ppid: int`, `flags: int`, `num_threads: int`,
    `starttime_ticks: int`
  - `parse_stat(text: str) -> StatFields`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_parse_stat.py`. The first case is the real line captured
in `docs/step0/03-comm-paren-trap.txt`.

```python
import pytest

from kdetect.parsers.procfs import ParseError, parse_stat

PAREN_COMM = (
    "6041 (ev (il) proc) S 6009 6009 6009 0 -1 4194304 110 0 0 0 0 0 0 0 "
    "20 0 1 0 368731 5603328 226 18446744073709551615 94560358600704"
)

NORMAL = (
    "6009 (bash) S 6008 6009 6009 0 -1 4194304 736 1504 0 1 0 0 1 0 "
    "20 0 1 0 368626 7106560 869 18446744073709551615 94700239310848"
)

KTHREADD = (
    "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 "
    "20 0 1 0 6 0 0 18446744073709551615 0 0"
)


def test_comm_with_spaces_and_parens_does_not_misalign_fields():
    s = parse_stat(PAREN_COMM)
    assert s.pid == 6041
    assert s.comm == "ev (il) proc"
    assert s.state == "S"
    assert s.ppid == 6009


def test_normal_line():
    s = parse_stat(NORMAL)
    assert s.pid == 6009
    assert s.comm == "bash"
    assert s.state == "S"
    assert s.ppid == 6008
    assert s.flags == 4194304
    assert s.num_threads == 1
    assert s.starttime_ticks == 368626


def test_kernel_thread_flags():
    s = parse_stat(KTHREADD)
    assert s.comm == "kthreadd"
    assert s.ppid == 0
    assert s.flags == 2129984
    assert s.flags & 0x00200000  # PF_KTHREAD


def test_comm_at_fifteen_char_limit():
    line = "42 (abcdefghijklmno) S 1 1 1 0 -1 4194304 " + "0 " * 12 + "20 0 1 0 99 0 0"
    assert parse_stat(line).comm == "abcdefghijklmno"


def test_trailing_newline_is_tolerated():
    assert parse_stat(NORMAL + "\n").pid == 6009


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not a stat line at all",
        "123 (noclose S 1 1",
        "123 (bash) S 1",
    ],
)
def test_malformed_raises_parse_error(bad):
    with pytest.raises(ParseError):
        parse_stat(bad)
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python -m pytest tests/unit/test_parse_stat.py -v
```

Expected: collection error — `ModuleNotFoundError: No module named 'kdetect.parsers'`.

- [ ] **Step 3: Implement `parse_stat`**

Create `src/kdetect/parsers/__init__.py` (empty) and
`src/kdetect/parsers/procfs.py`.

Define:
- `class ParseError(ValueError)`
- `@dataclass(frozen=True) class StatFields` with the seven fields listed under
  Interfaces above
- `def parse_stat(text: str) -> StatFields`

Algorithm — implement exactly this:

1. Strip trailing whitespace from `text`.
2. `open_idx = text.find("(")`; `close_idx = text.rfind(")")`. If either is `-1`,
   or `close_idx < open_idx`, raise `ParseError`.
3. `pid = int(text[:open_idx].strip())`
4. `comm = text[open_idx + 1 : close_idx]`
5. `rest = text[close_idx + 1 :].split()`
6. `rest[0]` is stat field **3**, so **stat field N is `rest[N - 3]`**:
   - `state` = `rest[0]`
   - `ppid` = `int(rest[1])`
   - `flags` = `int(rest[6])`
   - `num_threads` = `int(rest[17])`
   - `starttime_ticks` = `int(rest[19])`
7. If `len(rest) < 20`, raise `ParseError`.
8. Wrap any `ValueError` from `int()` in a `ParseError`.

**Use `rfind(")")`. Never `text.split()` on the whole line** — that is the bug the
first test exists to catch, and it produces silent misalignment rather than an
exception.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
python -m pytest tests/unit/test_parse_stat.py -v
```

Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/parsers tests/unit/test_parse_stat.py && git commit -m "feat: parse /proc/[pid]/stat with paren-safe comm extraction"
```

→ **Review checkpoint.**

---

## Task 3: `parse_cmdline` and `parse_status`

**Files:**
- Modify: `src/kdetect/parsers/procfs.py`
- Test: `tests/unit/test_parse_cmdline.py`, `tests/unit/test_parse_status.py`

**Interfaces:**
- Consumes: `ParseError` from Task 2
- Produces:
  - `parse_cmdline(text: str) -> list[str]`
  - `StatusFields` frozen dataclass with `uid: list[int]`, `gid: list[int]`
  - `parse_status(text: str) -> StatusFields`

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_parse_cmdline.py`:

```python
from kdetect.parsers.procfs import parse_cmdline


def test_nul_separated_args():
    assert parse_cmdline("/usr/bin/sleep\x00300\x00") == ["/usr/bin/sleep", "300"]


def test_kernel_thread_has_empty_cmdline():
    # docs/step0/05-kernel-thread-pid2.txt: cmdline is 0 bytes. Not an error.
    assert parse_cmdline("") == []


def test_forged_argv0_is_preserved_verbatim():
    # docs/step0/02-comm-vs-cmdline.txt: argv[0] is attacker-controlled.
    raw = "evil (hidden) proc\x0030\x00"
    assert parse_cmdline(raw) == ["evil (hidden) proc", "30"]


def test_no_trailing_nul():
    assert parse_cmdline("a\x00b") == ["a", "b"]


def test_only_nuls():
    assert parse_cmdline("\x00\x00") == []
```

`tests/unit/test_parse_status.py`:

```python
import pytest

from kdetect.parsers.procfs import ParseError, parse_status

STATUS = """Name:\tbash
State:\tS (sleeping)
Tgid:\t6009
Pid:\t6009
PPid:\t6008
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
Threads:\t1
"""


def test_uid_and_gid_are_four_tuples():
    s = parse_status(STATUS)
    assert s.uid == [1000, 1000, 1000, 1000]
    assert s.gid == [1000, 1000, 1000, 1000]


def test_root_process():
    s = parse_status("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
    assert s.uid == [0, 0, 0, 0]


def test_missing_uid_line_raises():
    with pytest.raises(ParseError):
        parse_status("Name:\tbash\n")
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python -m pytest tests/unit/test_parse_cmdline.py tests/unit/test_parse_status.py -v
```

Expected: `ImportError: cannot import name 'parse_cmdline'`.

- [ ] **Step 3: Implement both functions**

In `src/kdetect/parsers/procfs.py`.

`parse_cmdline(text: str) -> list[str]`:
1. Split `text` on `"\x00"`.
2. Drop empty strings that result from the trailing NUL, and return `[]` for
   input that is empty or all NULs.
3. Do **not** strip, rewrite, or validate the arguments — `argv[0]` is
   attacker-controlled and must be recorded verbatim (P1).

`parse_status(text: str) -> StatusFields`:
1. Iterate lines, splitting each on the first `":"`.
2. For keys `Uid` and `Gid`, split the value on whitespace and convert to
   `list[int]`.
3. If either key is absent, raise `ParseError`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
python -m pytest tests/unit -v
```

Expected: 17 passed.

- [ ] **Step 5: Record the encoding limitation**

Append to `docs/limitations.md`:

```markdown
- `/proc/[pid]/cmdline` is raw bytes and may not be valid UTF-8. Phase 1 decodes
  with `errors="replace"`, so a process with non-UTF-8 arguments is recorded
  lossily. A rootkit could use this to make a command line unreproducible.
```

- [ ] **Step 6: Commit**

```bash
git add src/kdetect/parsers tests/unit docs/limitations.md && git commit -m "feat: parse cmdline and status"
```

→ **Review checkpoint.**

---

## Task 4: Models and the round-trip

The core of the milestone.

**Files:**
- Create: `src/kdetect/models.py`
- Test: `tests/unit/test_models_roundtrip.py`

**Interfaces:**
- Produces:
  - `TrustLevel(str, Enum)`: `LOW`, `MEDIUM`, `HIGH`
  - `Status(str, Enum)`: `OK`, `PARTIAL`, `FAILED`
  - `ErrorKind(str, Enum)`: `VANISHED`, `DENIED`, `MALFORMED`, `IO_ERROR`
  - `ProcessEntity` dataclass: `pid: int`, `ppid: int`, `comm: str`,
    `state: str`, `flags: int`, `num_threads: int`, `starttime_ticks: int`,
    `cmdline: list[str]`, `exe: str | None`, `uid: list[int] | None`,
    `gid: list[int] | None`, `partial: list[str]`
  - `CollectionError` dataclass: `entity_id: int | None`, `kind: ErrorKind`,
    `detail: str`
  - `Observation` dataclass: `collector: str`, `collector_version: str`,
    `view: str`, `trust_level: TrustLevel`, `status: Status`,
    `duration_ms: int`, `entity_ids: list[int]`,
    `entities: dict[int, ProcessEntity]`, `stats: dict[str, int]`,
    `errors: list[CollectionError]`
  - `HostFacts` dataclass: `hostname: str`, `kernel_release: str`, `arch: str`,
    `boot_id: str`, `btime: int`, `clock_ticks_per_sec: int`
  - `CaptureMeta` dataclass: `tool_version: str`, `euid: int`
  - `Snapshot` dataclass: `schema_version: str`, `snapshot_id: str`,
    `captured_at: str`, `host: HostFacts`, `capture: CaptureMeta`,
    `observations: list[Observation]`
  - Every dataclass has `to_dict(self) -> dict` and
    `from_dict(cls, d: dict)` as a `@classmethod`
  - `Snapshot.to_json(self, pretty: bool = False) -> str`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_models_roundtrip.py`.

```python
import json

from kdetect.models import (
    CaptureMeta,
    CollectionError,
    ErrorKind,
    HostFacts,
    Observation,
    ProcessEntity,
    Snapshot,
    Status,
    TrustLevel,
)


def _entity(pid, comm, flags, exe, partial):
    return ProcessEntity(
        pid=pid, ppid=0, comm=comm, state="S", flags=flags,
        num_threads=1, starttime_ticks=6, cmdline=[], exe=exe,
        uid=[0, 0, 0, 0], gid=[0, 0, 0, 0], partial=partial,
    )


def make_snapshot():
    systemd = _entity(1, "systemd", 4194560, "/usr/lib/systemd/systemd", [])
    kthreadd = _entity(2, "kthreadd", 2129984, None, [])
    denied = _entity(812, "sshd", 4194304, None, ["exe"])
    obs = Observation(
        collector="procfs.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=84,
        entity_ids=[1, 2, 812],
        entities={1: systemd, 2: kthreadd, 812: denied},
        stats={"scanned": 4, "collected": 3, "vanished": 1},
        errors=[CollectionError(entity_id=4171, kind=ErrorKind.VANISHED,
                                detail="ENOENT reading stat")],
    )
    return Snapshot(
        schema_version="1.0",
        snapshot_id="b3f1c8e2-7a4d-4f19-9c2e-1d8a3f5b6c07",
        captured_at="2026-08-18T02:01:08.412Z",
        host=HostFacts(hostname="kdetect-lab", kernel_release="6.1.0-10-amd64",
                       arch="x86_64", boot_id="4fa7045a", btime=1787032782,
                       clock_ticks_per_sec=100),
        capture=CaptureMeta(tool_version="0.1.0", euid=0),
        observations=[obs],
    )


def test_roundtrip_equals_original():
    s = make_snapshot()
    assert Snapshot.from_dict(s.to_dict()) == s


def test_reserialisation_is_byte_identical():
    s = make_snapshot()
    once = s.to_json()
    twice = Snapshot.from_dict(json.loads(once)).to_json()
    assert once == twice


def test_entity_keys_survive_as_integers():
    # JSON object keys are always strings. This is the classic round-trip bug.
    s = make_snapshot()
    raw = json.loads(s.to_json())
    assert set(raw["observations"][0]["entities"]) == {"1", "2", "812"}
    back = Snapshot.from_dict(raw)
    assert set(back.observations[0].entities) == {1, 2, 812}


def test_entities_keys_are_subset_of_entity_ids():
    s = make_snapshot()
    obs = s.observations[0]
    assert set(obs.entities).issubset(set(obs.entity_ids))


def test_exe_three_states_are_distinguishable():
    s = Snapshot.from_dict(make_snapshot().to_dict())
    ents = s.observations[0].entities
    assert ents[1].exe == "/usr/lib/systemd/systemd" and ents[1].partial == []
    assert ents[2].exe is None and ents[2].partial == []      # ENOENT
    assert ents[812].exe is None and ents[812].partial == ["exe"]  # EACCES


def test_entity_ids_are_sorted_ascending():
    raw = json.loads(make_snapshot().to_json())
    ids = raw["observations"][0]["entity_ids"]
    assert ids == sorted(ids)


def test_enums_serialise_as_their_string_values():
    raw = json.loads(make_snapshot().to_json())
    obs = raw["observations"][0]
    assert obs["trust_level"] == "LOW"
    assert obs["status"] == "OK"
    assert obs["errors"][0]["kind"] == "vanished"


def test_pretty_and_compact_carry_the_same_data():
    s = make_snapshot()
    assert json.loads(s.to_json(pretty=True)) == json.loads(s.to_json())
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python -m pytest tests/unit/test_models_roundtrip.py -v
```

Expected: `ModuleNotFoundError: No module named 'kdetect.models'`.

- [ ] **Step 3: Implement `models.py`**

Requirements beyond the signatures listed under Interfaces:

- Enum **values**: `TrustLevel` and `Status` members use upper-case values
  (`"LOW"`, `"OK"`). `ErrorKind` members use lower-case values (`"vanished"`,
  `"denied"`, `"malformed"`, `"io_error"`) — matching the spec's error table.
  The last test above pins this down.
- `Observation.to_dict` writes `entities` with **string** keys
  (`str(pid)`); `from_dict` converts them back with `int(k)`.
- `Observation.to_dict` emits `entity_ids` sorted ascending and `partial`
  sorted alphabetically, regardless of the order held in memory.
- `Snapshot.to_json(pretty=False)` uses
  `json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))`;
  `pretty=True` uses `indent=2, sort_keys=True`.
- Dataclasses use default `eq=True` so `==` compares by value.
- No validation logic beyond type conversion. Models are a transcription of the
  schema, not a rule engine.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
python -m pytest tests/unit/test_models_roundtrip.py -v
```

Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/models.py tests/unit/test_models_roundtrip.py && git commit -m "feat: snapshot models with deterministic round-trip"
```

**Satisfies acceptance criterion 4.** → **Review checkpoint.**

---

## Task 5: Schema versioning

**Files:**
- Modify: `src/kdetect/models.py`
- Test: `tests/unit/test_schema_version.py`

**Interfaces:**
- Consumes: `Snapshot` from Task 4
- Produces: `IncompatibleSnapshot(Exception)`; version enforcement inside
  `Snapshot.from_dict`

- [ ] **Step 1: Write the failing tests**

```python
import pytest

from kdetect.models import IncompatibleSnapshot, Snapshot
from tests.unit.test_models_roundtrip import make_snapshot


def test_same_version_loads():
    d = make_snapshot().to_dict()
    assert Snapshot.from_dict(d).schema_version == "1.0"


def test_newer_minor_loads_with_warning(capsys):
    d = make_snapshot().to_dict()
    d["schema_version"] = "1.7"
    d["some_future_field"] = 42
    Snapshot.from_dict(d)
    assert "unknown" in capsys.readouterr().err.lower()


def test_newer_major_refuses():
    d = make_snapshot().to_dict()
    d["schema_version"] = "2.0"
    with pytest.raises(IncompatibleSnapshot):
        Snapshot.from_dict(d)


def test_older_major_refuses():
    d = make_snapshot().to_dict()
    d["schema_version"] = "0.9"
    with pytest.raises(IncompatibleSnapshot):
        Snapshot.from_dict(d)


def test_missing_version_refuses():
    d = make_snapshot().to_dict()
    del d["schema_version"]
    with pytest.raises(IncompatibleSnapshot):
        Snapshot.from_dict(d)


def test_malformed_version_refuses():
    d = make_snapshot().to_dict()
    d["schema_version"] = "banana"
    with pytest.raises(IncompatibleSnapshot):
        Snapshot.from_dict(d)
```

Add `tests/__init__.py` and `tests/unit/__init__.py` (both empty) so the
cross-module import of `make_snapshot` resolves.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python -m pytest tests/unit/test_schema_version.py -v
```

Expected: `ImportError: cannot import name 'IncompatibleSnapshot'`.

- [ ] **Step 3: Implement the version gate**

- Module constant `SCHEMA_VERSION = "1.0"`.
- `class IncompatibleSnapshot(Exception)`.
- At the **very top** of `Snapshot.from_dict`, before parsing anything else:
  read `schema_version`; raise `IncompatibleSnapshot` if absent, unparseable, or
  if its MAJOR differs from `SCHEMA_VERSION`'s MAJOR.
- If MINOR is greater than the current MINOR, write a warning to `sys.stderr`
  naming the unknown top-level keys, then continue.
- A partially-parsed `Snapshot` must never be returned: either the whole object
  or an exception.

- [ ] **Step 4: Run the full suite**

```bash
python -m pytest tests/unit -v
```

Expected: 31 passed.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/models.py tests/unit/test_schema_version.py tests/__init__.py tests/unit/__init__.py && git commit -m "feat: enforce schema version on load"
```

→ **Review checkpoint.**

---

## Task 6: `ProcSource` and `LiveProcSource`

**Files:**
- Create: `src/kdetect/collectors/base.py`, `src/kdetect/collectors/sources.py`
- Test: `tests/integration/test_live_source.py`

**Interfaces:**
- Consumes: `TrustLevel`, `Observation` from Task 4
- Produces:
  - `ProcSourceError(Exception)`, and subclasses `Vanished`, `Denied`,
    `Unreadable`
  - `ProcSource` ABC: `list_pids(self) -> list[int]`,
    `read_text(self, pid: int, name: str) -> str`,
    `read_link(self, pid: int, name: str) -> str`
  - `Collector` ABC: class attributes `name`, `view`, `trust_level`, `version`;
    abstract `collect(self, source: ProcSource) -> Observation`
  - `LiveProcSource(ProcSource)`, constructed with no arguments

- [ ] **Step 1: Write the failing tests**

```python
import os

import pytest

from kdetect.collectors.base import Vanished
from kdetect.collectors.sources import LiveProcSource
from tests.conftest import needs_procfs

pytestmark = needs_procfs


def test_lists_only_numeric_pids():
    pids = LiveProcSource().list_pids()
    assert all(isinstance(p, int) and p > 0 for p in pids)
    assert pids == sorted(pids)
    assert 1 in pids


def test_reads_own_stat():
    text = LiveProcSource().read_text(os.getpid(), "stat")
    assert text.startswith(f"{os.getpid()} (")


def test_kernel_thread_exe_raises_vanished_or_unreadable():
    # PID 2 has no executable: ENOENT. See docs/step0/06-exe-errno-comparison.txt
    with pytest.raises(Exception):
        LiveProcSource().read_link(2, "exe")


def test_nonexistent_pid_raises_vanished():
    with pytest.raises(Vanished):
        LiveProcSource().read_text(999999, "stat")


def test_oserror_never_escapes():
    src = LiveProcSource()
    try:
        src.read_text(999999, "stat")
    except OSError:
        pytest.fail("raw OSError escaped the source layer")
    except Exception:
        pass
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python -m pytest tests/integration/test_live_source.py -v
```

Expected: `ModuleNotFoundError: No module named 'kdetect.collectors.base'`.

Add `tests/integration/__init__.py` (empty) if collection complains.

- [ ] **Step 3: Implement the ABCs and `LiveProcSource`**

`base.py` — the exception hierarchy and the two ABCs listed under Interfaces.
`Collector.collect` is decorated `@abstractmethod`.

`sources.py` — `LiveProcSource`:
- `list_pids()`: `os.listdir("/proc")`, keep entries where `entry.isdigit()`,
  convert to `int`, return sorted.
- `read_text(pid, name)`: open `/proc/{pid}/{name}` and read, decoding UTF-8 with
  `errors="replace"`.
- `read_link(pid, name)`: `os.readlink(f"/proc/{pid}/{name}")`. Return the target
  **verbatim**, including any `" (deleted)"` suffix.
- Both readers translate `OSError` by `errno`:
  - `ENOENT`, `ESRCH` → `Vanished`
  - `EACCES`, `EPERM` → `Denied`
  - anything else → `Unreadable`
- **No `OSError` may escape this class.** That is the entire point of the layer.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
python -m pytest tests/integration/test_live_source.py -v
```

Expected: 5 passed on the VM.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/collectors tests/integration && git commit -m "feat: ProcSource abstraction and live implementation"
```

→ **Review checkpoint.**

---

## Task 7: Fixture source and a curated fixture tree

**Files:**
- Modify: `src/kdetect/collectors/sources.py`
- Create: `tools/capture-fixture.sh`
- Create: `tests/fixtures/proc-trees/clean-vm-6.1.0-10/`
- Test: `tests/unit/test_fixture_source.py`

**Interfaces:**
- Consumes: `ProcSource`, `Vanished`, `Denied`, `Unreadable` from Task 6
- Produces: `FixtureProcSource(ProcSource)`, constructed as
  `FixtureProcSource(root: Path)`

**Fixture format:**
```
clean-vm-6.1.0-10/
  proc/
    1/stat
    1/cmdline
    1/status
    1/exe.readlink        <- symlink target as plain text
    2/stat
    2/cmdline             <- empty file
    2/status
    ...
  _errors.json            <- {"812/exe": "EACCES", "4171/stat": "ENOENT"}
```

Symlinks are stored as `<name>.readlink` text files because Windows cannot create
real symlinks without elevated privileges, and this tree is read on Windows.

- [ ] **Step 1: Write the failing tests**

```python
import json
from pathlib import Path

import pytest

from kdetect.collectors.base import Denied, Vanished
from kdetect.collectors.sources import FixtureProcSource

ROOT = Path(__file__).parent.parent / "fixtures" / "proc-trees" / "clean-vm-6.1.0-10"


@pytest.fixture
def src():
    return FixtureProcSource(ROOT)


def test_lists_pids_sorted(src):
    pids = src.list_pids()
    assert pids == sorted(pids)
    assert 1 in pids and 2 in pids


def test_reads_stat(src):
    assert src.read_text(1, "stat").startswith("1 (")


def test_kernel_thread_cmdline_is_empty(src):
    assert src.read_text(2, "cmdline") == ""


def test_recorded_eacces_is_replayed(src):
    with pytest.raises(Denied):
        src.read_link(812, "exe")


def test_recorded_enoent_is_replayed(src):
    with pytest.raises(Vanished):
        src.read_text(4171, "stat")


def test_readlink_returns_target_verbatim(src):
    assert src.read_link(1, "exe") == "/usr/lib/systemd/systemd"


def test_errors_sidecar_is_valid_json():
    assert isinstance(json.loads((ROOT / "_errors.json").read_text()), dict)
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python -m pytest tests/unit/test_fixture_source.py -v
```

Expected: `ImportError: cannot import name 'FixtureProcSource'`.

- [ ] **Step 3: Write `tools/capture-fixture.sh`**

A lab utility, not part of kdetect. Requirements:
- Takes a destination directory and a list of PIDs.
- For each PID, copies `stat`, `cmdline`, `status` into `<dest>/proc/<pid>/`.
- Writes `readlink /proc/<pid>/exe` output into `<pid>/exe.readlink` when it
  succeeds; records `{"<pid>/exe": "<ERRNO>"}` in `_errors.json` when it fails.
- Prints the resulting tree so you can eyeball it before committing.

- [ ] **Step 4: Build the curated fixture tree**

Capture **exactly these seven**, chosen for coverage rather than realism:

| PID | Why it's in the fixture |
|---|---|
| 1 (`systemd`) | ordinary process, readable `exe` |
| 2 (`kthreadd`) | kernel thread: empty `cmdline`, `exe` → `ENOENT` |
| a `kworker` | second kernel thread, different `flags` value |
| your `bash` | ordinary user-owned process |
| a `sleep` with parens in `comm` | the `parse_stat` trap, end to end |
| an sshd or root-owned process | recorded as `EACCES` in `_errors.json` |
| a synthetic PID `4171` | present in no directory; `_errors.json` maps it to `ENOENT` to simulate vanishing |

**Read every file before committing it.** This tree is the only capture that
leaves the machine, and it contains hostnames, usernames and command lines.

- [ ] **Step 5: Implement `FixtureProcSource`**

- `__init__(self, root: Path)` — stores `root`, loads `root / "_errors.json"`
  into a dict (missing file is acceptable; treat as `{}`).
- Before every read, consult the errors map for the key `f"{pid}/{name}"`. If
  present, raise the mapped domain error: `ENOENT`/`ESRCH` → `Vanished`,
  `EACCES`/`EPERM` → `Denied`, anything else → `Unreadable`.
- `list_pids()` — numeric directory names under `root / "proc"`, sorted. Do not
  include synthetic PIDs that exist only in `_errors.json`.
- `read_text(pid, name)` — read `root / "proc" / str(pid) / name`. A missing file
  raises `Vanished`.
- `read_link(pid, name)` — read `root / "proc" / str(pid) / f"{name}.readlink"`
  and return its contents stripped of the trailing newline only.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
python -m pytest tests/unit/test_fixture_source.py -v
```

Expected: 7 passed.

- [ ] **Step 7: Commit**

```bash
git add src/kdetect/collectors/sources.py tools/capture-fixture.sh tests/fixtures tests/unit/test_fixture_source.py && git commit -m "feat: fixture source with replayable errnos"
```

**Satisfies acceptance criterion 5.** → **Review checkpoint.**

---

## Task 8: `ProcfsProcessCollector`

**Files:**
- Create: `src/kdetect/collectors/procfs.py`
- Test: `tests/unit/test_collector_procfs.py`

**Interfaces:**
- Consumes: `Collector`, `ProcSource`, source errors (Task 6);
  `FixtureProcSource` (Task 7); parse functions (Tasks 2–3); models (Task 4)
- Produces: `ProcfsProcessCollector(Collector)` with `name = "procfs.processes"`,
  `view = "processes"`, `trust_level = TrustLevel.LOW`, `version = "1"`

- [ ] **Step 1: Write the failing tests**

```python
from pathlib import Path

from kdetect.collectors.procfs import ProcfsProcessCollector
from kdetect.collectors.sources import FixtureProcSource
from kdetect.models import ErrorKind, Status, TrustLevel

ROOT = Path(__file__).parent.parent / "fixtures" / "proc-trees" / "clean-vm-6.1.0-10"


def collect():
    return ProcfsProcessCollector().collect(FixtureProcSource(ROOT))


def test_identity_fields():
    obs = collect()
    assert obs.collector == "procfs.processes"
    assert obs.view == "processes"
    assert obs.trust_level is TrustLevel.LOW


def test_entity_ids_sorted_and_superset_of_entities():
    obs = collect()
    assert obs.entity_ids == sorted(obs.entity_ids)
    assert set(obs.entities).issubset(set(obs.entity_ids))


def test_kernel_thread_exe_is_none_and_not_partial():
    # ENOENT: genuinely has no executable.
    e = collect().entities[2]
    assert e.exe is None
    assert "exe" not in e.partial
    assert e.flags & 0x00200000


def test_denied_exe_is_none_and_marked_partial():
    # EACCES: exists, could not be read.
    e = collect().entities[812]
    assert e.exe is None
    assert "exe" in e.partial


def test_vanished_does_not_degrade_status():
    obs = collect()
    assert obs.status is Status.OK
    assert obs.stats["vanished"] >= 1
    assert any(err.kind is ErrorKind.VANISHED for err in obs.errors)


def test_stats_are_consistent():
    obs = collect()
    assert obs.stats["collected"] == len(obs.entities)
    assert obs.stats["scanned"] >= obs.stats["collected"]


def test_paren_comm_process_parsed_correctly():
    obs = collect()
    assert any("(" in e.comm for e in obs.entities.values())


def test_duration_is_recorded():
    assert collect().duration_ms >= 0
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python -m pytest tests/unit/test_collector_procfs.py -v
```

Expected: `ModuleNotFoundError: No module named 'kdetect.collectors.procfs'`.

- [ ] **Step 3: Implement the collector**

`collect(self, source)`:

1. Record a monotonic start time.
2. `pids = source.list_pids()`. If this raises, return an Observation with
   `status = FAILED`, empty `entity_ids`, and one `CollectionError`.
3. `scanned = len(pids)`; `vanished = 0`; `status = Status.OK`.
4. For each pid, in order:
   - Read `stat`. On `Vanished`: increment `vanished`, append a
     `CollectionError(kind=VANISHED)`, `continue` — **do not** change `status`.
     On `Denied`/`Unreadable`: append the matching error, set
     `status = PARTIAL`, `continue`.
   - `parse_stat`. On `ParseError`: append `CollectionError(kind=MALFORMED)`,
     set `status = PARTIAL`, `continue`.
   - Read `cmdline` and `status`, and `read_link` `exe`. Each of these is
     **individually optional**: on `Vanished` leave the value `None`/`[]` and do
     not add to `partial`; on `Denied`/`Unreadable` leave the value `None` **and
     append the field name to `partial`**, and set `status = PARTIAL`.
   - Build the `ProcessEntity`, add pid to `entity_ids`, add the entity to
     `entities`.
5. Sort each entity's `partial`; sort `entity_ids`.
6. Return the `Observation` with
   `stats = {"scanned": …, "collected": len(entities), "vanished": …}` and
   `duration_ms` as an `int` of elapsed milliseconds.

The `exe` handling in step 4 is the three-state rule from spec §3.3 and is what
two of the tests above check. Getting it wrong is invisible until phase 2.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
python -m pytest tests/unit -v
```

Expected: 46 passed.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/collectors/procfs.py tests/unit/test_collector_procfs.py && git commit -m "feat: procfs process collector"
```

**Satisfies acceptance criterion 6.** → **Review checkpoint.**

---

## Task 9: `kdetect capture`

**Files:**
- Modify: `src/kdetect/cli.py`
- Create: `src/kdetect/hostfacts.py`
- Test: `tests/integration/test_capture.py`

**Interfaces:**
- Consumes: everything from Tasks 4, 6, 8
- Produces: `kdetect.hostfacts.gather() -> HostFacts`; a working `capture`
  subcommand

- [ ] **Step 1: Write the failing tests**

```python
import json
import os
import subprocess
import sys

from kdetect.models import Snapshot
from tests.conftest import needs_procfs

pytestmark = needs_procfs


def run(args, cwd):
    return subprocess.run([sys.executable, "-m", "kdetect.cli"] + args,
                          capture_output=True, text=True, cwd=cwd)


def test_capture_writes_a_file_and_prints_its_path(tmp_path):
    r = run(["capture"], tmp_path)
    assert r.returncode == 0
    path = tmp_path / r.stdout.strip()
    assert path.exists()


def test_capture_filename_has_no_colons(tmp_path):
    r = run(["capture"], tmp_path)
    assert ":" not in r.stdout.strip().split("/")[-1]


def test_capture_to_stdout(tmp_path):
    r = run(["capture", "--out", "-"], tmp_path)
    assert Snapshot.from_dict(json.loads(r.stdout)).schema_version == "1.0"


def test_capture_contains_its_own_pid(tmp_path):
    # Acceptance criterion 9: the observer is in the observation.
    r = run(["capture", "--out", "-"], tmp_path)
    snap = Snapshot.from_dict(json.loads(r.stdout))
    comms = [e.comm for e in snap.observations[0].entities.values()]
    assert any("python" in c for c in comms)


def test_host_facts_are_populated(tmp_path):
    r = run(["capture", "--out", "-"], tmp_path)
    h = Snapshot.from_dict(json.loads(r.stdout)).host
    assert h.btime > 0
    assert h.clock_ticks_per_sec == 100
    assert len(h.boot_id) >= 8
    assert h.kernel_release


def test_non_root_warns_on_stderr(tmp_path):
    if os.geteuid() == 0:
        return
    r = run(["capture", "--out", "-"], tmp_path)
    assert "root" in r.stderr.lower() or "euid" in r.stderr.lower()
    assert r.returncode == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python -m pytest tests/integration/test_capture.py -v
```

Expected: failures — `capture` currently returns 0 and prints nothing.

- [ ] **Step 3: Implement `hostfacts.gather()`**

Create `src/kdetect/hostfacts.py`. Returns a `HostFacts` built from:
- `hostname` — `socket.gethostname()`
- `kernel_release` — `os.uname().release`
- `arch` — `os.uname().machine`
- `boot_id` — `/proc/sys/kernel/random/boot_id`, stripped
- `btime` — the `btime` line of `/proc/stat`, as `int`
- `clock_ticks_per_sec` — `os.sysconf("SC_CLK_TCK")`

All six are mandatory; a missing value is an error, not a `None`. Without `btime`
and `clock_ticks_per_sec`, `starttime_ticks` is uninterpretable (spec §3.1).

- [ ] **Step 4: Implement `capture`**

- Build `HostFacts` via `gather()`, and `CaptureMeta(tool_version=__version__,
  euid=os.geteuid())`.
- If `euid != 0`, write to **stderr**: a warning that address-bearing data will be
  zeroed and that root is required for address-based detection. Do **not** refuse
  (spec §5, §11.2).
- Run `ProcfsProcessCollector().collect(LiveProcSource())`.
- Build the `Snapshot` with `schema_version=SCHEMA_VERSION`,
  `snapshot_id=str(uuid.uuid4())`, and `captured_at` as UTC ISO-8601 with
  millisecond precision and a `Z` suffix.
- If `--out -`: write `to_json(pretty)` to stdout, nothing else.
- Otherwise: create `captures/` if needed, generate the filename
  `{YYYYMMDD}T{HHMMSS}Z_{hostname}_{boot_id[:8]}.json`, write the file, and print
  **only the path** to stdout.
- Return `0`.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
python -m pytest tests/integration/test_capture.py -v && kdetect capture
```

Expected: 6 passed, and a printed path such as
`captures/20260818T143000Z_debian_4fa7045a.json`.

- [ ] **Step 6: Commit**

```bash
git add src/kdetect/cli.py src/kdetect/hostfacts.py tests/integration/test_capture.py && git commit -m "feat: kdetect capture writes a snapshot"
```

**Satisfies acceptance criteria 2 and 9.** → **Review checkpoint.**

---

## Task 10: `kdetect analyze`

**Files:**
- Modify: `src/kdetect/cli.py`
- Create: `tests/fixtures/snapshots/clean-vm.json`
- Test: `tests/unit/test_analyze.py`

**Interfaces:**
- Consumes: `Snapshot`, `IncompatibleSnapshot` from Tasks 4–5
- Produces: a working `analyze` subcommand

- [ ] **Step 1: Save a real capture as the round-trip fixture**

```bash
kdetect capture --out tests/fixtures/snapshots/clean-vm.json --pretty && head -20 tests/fixtures/snapshots/clean-vm.json
```

Read it before committing — it contains your hostname and command lines.

- [ ] **Step 2: Write the failing tests**

```python
import json
import subprocess
import sys
from pathlib import Path

FIXTURE = Path(__file__).parent.parent / "fixtures" / "snapshots" / "clean-vm.json"


def run(args):
    return subprocess.run([sys.executable, "-m", "kdetect.cli"] + args,
                          capture_output=True, text=True)


def test_analyze_prints_summary():
    r = run(["analyze", str(FIXTURE)])
    assert r.returncode == 0
    for field in ("snapshot:", "schema:", "host:", "captured:", "euid:",
                  "procfs.processes", "trust=LOW"):
        assert field in r.stdout


def test_analyze_reports_entity_count():
    r = run(["analyze", str(FIXTURE)])
    n = len(json.loads(FIXTURE.read_text())["observations"][0]["entity_ids"])
    assert str(n) in r.stdout


def test_analyze_rejects_major_version_mismatch(tmp_path):
    d = json.loads(FIXTURE.read_text())
    d["schema_version"] = "2.0"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(d))
    r = run(["analyze", str(bad)])
    assert r.returncode == 1
    assert "version" in (r.stderr + r.stdout).lower()


def test_analyze_missing_file_exits_1():
    r = run(["analyze", "/nonexistent/nope.json"])
    assert r.returncode == 1


def test_analyze_malformed_json_exits_1(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert run(["analyze", str(bad)]).returncode == 1


def test_fixture_round_trips_byte_identically():
    from kdetect.models import Snapshot
    raw = json.loads(FIXTURE.read_text())
    s = Snapshot.from_dict(raw)
    assert Snapshot.from_dict(json.loads(s.to_json())).to_json() == s.to_json()
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
python -m pytest tests/unit/test_analyze.py -v
```

- [ ] **Step 4: Implement `analyze`**

- Read the file; on `FileNotFoundError` or `json.JSONDecodeError`, write the
  message to stderr and return `1`.
- `Snapshot.from_dict`; on `IncompatibleSnapshot`, write to stderr and return `1`.
- Print exactly the block from spec §5:

```
snapshot:  <path>
schema:    <schema_version>
host:      <hostname>  <kernel_release>  <arch>
captured:  <captured_at>   boot <boot_id[:8]>
euid:      <euid>

collectors:
  <collector>   trust=<trust_level>   status=<status>   <n> entities   <duration_ms>ms
                scanned=<n>  collected=<n>  vanished=<n>
```

- Return `0`. **Do not return `3`** — that code is reserved for phase 2.

- [ ] **Step 5: Run the tests and the whole suite**

```bash
python -m pytest -v
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/kdetect/cli.py tests/fixtures/snapshots tests/unit/test_analyze.py && git commit -m "feat: kdetect analyze summarises a snapshot"
```

**Satisfies acceptance criterion 3.** → **Review checkpoint.**

---

## Task 11: Cross-platform verification

The payoff for the I/O seam. Nothing new is built here; this proves the design
claim.

**Files:**
- Modify: `tests/conftest.py` if any skip is missing

- [ ] **Step 1: Push from the VM**

```bash
git push
```

- [ ] **Step 2: On Windows, with the VM powered off, pull and run the unit suite**

```bash
cd C:\Users\angus\projects\kdetect && git pull && py -m venv .venv && .venv\Scripts\python -m pip install -e . pytest && .venv\Scripts\python -m pytest tests/unit -v
```

Expected: every unit test passes on Windows. The integration tests are skipped,
reported as `s`, because `/proc/self/stat` does not exist.

- [ ] **Step 3: Confirm the skip count is right**

```bash
.venv\Scripts\python -m pytest -v
```

Expected: unit tests pass, integration tests **skipped, not failed**. A failure
here means something leaked a Linux assumption into the pure layers — most likely
a hardcoded `/proc` path or a POSIX-only call such as `os.geteuid()` outside the
integration tier.

- [ ] **Step 4: Record the result**

Append to `docs/limitations.md`:

```markdown
- The unit and round-trip suites run on Windows against captured fixtures; only
  the integration tier requires a live `/proc`. This keeps parser development
  possible without the VM, and is why `ProcSource` is an interface rather than a
  configurable path.
```

- [ ] **Step 5: Commit from the VM**

```bash
git add docs/limitations.md && git commit -m "docs: record cross-platform test result" && git push
```

**Satisfies acceptance criteria 7 and 8.** → **Review checkpoint.**

---

## Task 12: `architecture.md`

Closes the loop on Step 1 of the original brief — the schema was settled in
conversation and in the spec, but `architecture.md` is still empty.

**Files:**
- Modify: `docs/architecture.md`

- [ ] **Step 1: Write the document**

It must contain:
1. The three-layer diagram from spec §4.1 and one paragraph on why the seam
   exists.
2. The **complete `Snapshot` example with two views**, copied from spec §3.4.
3. A **single `Observation` in isolation**, copied from spec §3.2.
4. The four Step 1 questions from the original brief, each with the answer that
   was chosen and one sentence of reasoning:
   - Does an Observation hold one entity or a whole view?
   - Where does per-entity detail live?
   - How does a collector report partial failure?
   - What is the version field, and what happens when the format changes?
5. A link to the spec and to `docs/step0/README.md`.

- [ ] **Step 2: Verify it against a real capture**

```bash
python -c "import json,sys; json.load(open('tests/fixtures/snapshots/clean-vm.json')); print('fixture parses')" && grep -c '"schema_version"' docs/architecture.md
```

Check by eye that the field names in the document match the real capture. A
divergence here means the document is already stale.

- [ ] **Step 3: Commit**

```bash
git add docs/architecture.md && git commit -m "docs: architecture with worked snapshot examples" && git push
```

**Satisfies acceptance criterion 10.** → **Final review checkpoint.**

---

## Acceptance criteria coverage

| # | Criterion | Task |
|---|---|---|
| 1 | `--help` on both subcommands | 1 |
| 2 | `capture` writes JSON, prints path | 9 |
| 3 | `analyze` prints the summary | 10 |
| 4 | Round-trip, byte-identical | 4 |
| 5 | Curated fixture tree | 7 |
| 6 | Parse tests cover the five cases | 2, 3, 8 |
| 7 | Unit suite passes on Windows | 11 |
| 8 | Integration suite passes on the VM | 11 |
| 9 | Capture contains its own PID | 9 |
| 10 | `architecture.md` worked examples | 12 |

## Definition of done

All twelve tasks committed, `pytest` green on the VM, unit tests green on Windows
with the VM off, and the ten acceptance criteria checked off. Phase 2 —
cross-view diffing against a second collector, with Diamorphine as ground truth —
begins with its own spec.
