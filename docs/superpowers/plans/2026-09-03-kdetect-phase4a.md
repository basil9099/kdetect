# kdetect Phase 4a — Network Sockets & Cross-View Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a socket collector (`/proc/net/*` tables + `/proc/<pid>/fd` inode attribution), two socket cross-view signals, and the HIGH `hidden_process` correlation, so `analyze` detects hidden connections and confirms hidden processes from the network view.

**Architecture:** Additive extension of the phase-3b detect→score pipeline. A new `procfs.sockets` collector records socket evidence (per-inode `in_table` + `owner_pids`); a new `signals_sockets` detector emits `hidden_socket` (socket suspect) and `socket_visible` (process suspect); the unchanged scorer composes `socket_visible` with the sweep's two process channels into a HIGH `hidden_process`. `cli.py` passes the collector the `readdir ∪ sweep` pid union so hidden pids' sockets are attributed.

**Tech Stack:** Python 3.11+ (lab VM is 3.11), pytest, stdlib only (`socket`, `struct` for address decode; no new dependency, no netlink).

**Spec:** `docs/superpowers/specs/2026-09-03-kdetect-phase4a-design.md` (read it alongside this plan; principles P8–P10, the two-signals/drop-orphan decision, and the FP calibration are argued there and cited by task).

## Global Constraints

- **P8 — detectors observe, the scorer concludes.** `signals_sockets` returns `list[Signal]`; the collector records `in_table`/`owner_pids` as evidence and decides nothing.
- **P9 — confidence is a per-suspect count of distinct channels.** No weights. `_confidence`: 1→LOW, 2→MEDIUM, ≥3→HIGH (unchanged).
- **P10 — the socket collector walks the pid set it is given** (`readdir ∪ sweep`), supplied by `cli.py`. It never sweeps pids itself.
- **P1/P5 — evidence only; findings cite it.** `SocketEntity` and `Signal.evidence` hold the exact values.
- **Determinism.** Entity ids sorted; signal/finding output deterministic; `from_dict(to_dict(x)) == x`. New fields omit-when-None where optional.
- **Schema stays 1.1** — additive (a new collector name + entity type + a `Suspect` kind value + one FindingKind). No existing field changes.
- **Stdlib only.** No new runtime dependency. `sock_diag`/netlink is out of scope (spec §9).
- **Python 3.11 compatible (L20).** No multi-line expressions inside f-string replacement fields. `tests/unit/test_python311_compat.py` enforces it — keep it green.
- **Capability-gated tests.** All parser/collector/detector/scorer tests run on Windows with the VM off (V1). Only live capture needs Linux.
- **Exit codes unchanged:** 0 ok, 1 error, 2 usage, 3 = any finding.
- **Clean machine fires nothing (paramount).** The socket view must not add a finding on a clean capture — every socket-owning pid is in readdir and every fd inode is in some table on a clean host.
- **Angus commits.** During subagent execution, work on a feature branch (`phase-4a`) where subagents commit per task and Angus merges. Never `git push` from the VM while a module is loaded.

---

## File Structure

**Create:**
- `src/kdetect/parsers/sockets.py` — pure parsers: `parse_net_tcp` (tcp/tcp6/udp/udp6 rich rows), `parse_net_inodes` (inode set for unix/netlink/packet/raw), address/state decode helpers.
- `src/kdetect/collectors/sockets.py` — `SocketCollector(pids)` (LOW).
- Tests: `tests/unit/test_parse_sockets.py`, `test_socket_source.py`, `test_collector_sockets.py`; fixtures under `tests/fixtures/socket-trees/`.

**Modify:**
- `src/kdetect/models.py` — `SocketEntity`; register `procfs.sockets`; add `FindingKind.HIDDEN_CONNECTION`.
- `src/kdetect/collectors/base.py` — `SocketSource` ABC.
- `src/kdetect/collectors/sources.py` — `LiveSocketSource`, `FixtureSocketSource`.
- `src/kdetect/analysis/signals.py` — `signals_sockets`; extend `all_signals`.
- `src/kdetect/analysis/scoring.py` — `_HIDING` += socket channels; `_classify` socket branch.
- `src/kdetect/cli.py` — capture runs `SocketCollector` with the pid union.
- Tests: `test_finding_model.py`, `test_signals.py`, `test_scoring.py`, `test_ground_truth.py`, `tests/integration/test_capture.py`.
- Docs: `docs/limitations.md` (L23, L24), `docs/detection-methods.md`, `docs/architecture.md`.

---

## Task 1: SocketEntity, the socket suspect kind, and HIDDEN_CONNECTION

**Files:**
- Modify: `src/kdetect/analysis/models.py` (FindingKind), `src/kdetect/models.py` (SocketEntity + registry)
- Test: `tests/unit/test_finding_model.py` (extend)

**Interfaces:**
- Consumes: nothing.
- Produces: `SocketEntity(inode: int, kind: str, state: str | None, local: str | None, remote: str | None, uid: int | None, in_table: bool, owner_pids: list[int])` with `to_dict`/`from_dict`; `procfs.sockets` registered in `_ENTITY_TYPES` (→ `SocketEntity`) and `_STRING_ID_COLLECTORS`; `FindingKind.HIDDEN_CONNECTION == "hidden_connection"`. (`Suspect` is already `(kind, name)`; the new `"socket"` kind needs no code change.)

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_finding_model.py`:

```python
from kdetect.models import SocketEntity, Observation, Status, TrustLevel
from kdetect.analysis.models import FindingKind as _FK

def test_hidden_connection_kind_exists():
    assert _FK.HIDDEN_CONNECTION.value == "hidden_connection"

def test_socket_entity_roundtrips():
    e = SocketEntity(inode=12345, kind="tcp", state="LISTEN",
                     local="0.0.0.0:22", remote="0.0.0.0:0", uid=0,
                     in_table=True, owner_pids=[812])
    assert SocketEntity.from_dict(e.to_dict()) == e

def test_socket_entity_fd_only_has_nulls():
    e = SocketEntity(inode=999, kind="unknown", state=None, local=None,
                     remote=None, uid=None, in_table=False, owner_pids=[4171])
    back = SocketEntity.from_dict(e.to_dict())
    assert back.in_table is False and back.state is None

def test_sockets_observation_uses_string_inode_ids():
    obs = Observation(
        collector="procfs.sockets", collector_version="1", view="sockets",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=["12345"],
        entities={"12345": SocketEntity(12345, "tcp", "LISTEN",
                  "0.0.0.0:22", "0.0.0.0:0", 0, True, [812])},
        stats={}, errors=[],
    )
    back = Observation.from_dict(obs.to_dict())
    assert back == obs
    assert list(back.entities.keys()) == ["12345"]   # stayed str
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_finding_model.py -v`
Expected: FAIL with `ImportError: cannot import name 'SocketEntity'`.

- [ ] **Step 3: Add the entity, registry entries, and kind**

In `src/kdetect/analysis/models.py`, add to `FindingKind` (after `BASELINE_DRIFT`):

```python
    HIDDEN_CONNECTION = "hidden_connection"
```

In `src/kdetect/models.py`, add the entity (after `HookEntity`):

```python
@dataclass(frozen=True)
class SocketEntity:
    """One socket, keyed by inode (spec §4.2). Evidence only (P1/P4):
    in_table (did some /proc/net/* family list it) and owner_pids (which walked
    pids hold it as an fd) are facts; "hidden connection" is the differ's call.
    state/local/remote/uid are None for an fd-only inode with no table row.
    """

    inode: int
    kind: str                 # "tcp" | "tcp6" | "udp" | ... | "unix" | ... | "unknown"
    state: str | None
    local: str | None
    remote: str | None
    uid: int | None
    in_table: bool
    owner_pids: list[int]

    def to_dict(self) -> dict:
        return {
            "inode": self.inode, "kind": self.kind, "state": self.state,
            "local": self.local, "remote": self.remote, "uid": self.uid,
            "in_table": self.in_table, "owner_pids": sorted(self.owner_pids),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SocketEntity":
        return cls(
            inode=d["inode"], kind=d["kind"], state=d["state"],
            local=d["local"], remote=d["remote"], uid=d["uid"],
            in_table=d["in_table"], owner_pids=list(d["owner_pids"]),
        )
```

Register it:

```python
_ENTITY_TYPES = {
    "procfs.processes": ProcessEntity,
    "syscall_sweep.processes": SweepEntity,
    "procfs.modules": ModuleEntity,
    "kernel.module_evidence": None,
    "kernel.hooks": HookEntity,
    "procfs.sockets": SocketEntity,          # NEW
}

_STRING_ID_COLLECTORS = frozenset(
    {"procfs.modules", "kernel.hooks", "procfs.sockets"})   # + procfs.sockets
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_finding_model.py tests/unit/test_models_roundtrip.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/models.py src/kdetect/analysis/models.py tests/unit/test_finding_model.py
git commit -m "feat(models): SocketEntity, procfs.sockets registry, HIDDEN_CONNECTION kind"
```

---

## Task 2: Socket parsers

**Files:**
- Create: `src/kdetect/parsers/sockets.py`
- Test: `tests/unit/test_parse_sockets.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `NetRow(inode: int, kind: str, state: str | None, local: str | None, remote: str | None, uid: int | None)`; `parse_net_tcp(text: str, kind: str) -> list[NetRow]` (for tcp/tcp6/udp/udp6, decoding hex addr:port and state); `parse_net_inodes(text: str, inode_index: int) -> set[int]` (pull the inode column for unix/netlink/packet/raw); `SocketParseError(ValueError)`. Address decode handles v4 (8 hex) and v6 (32 hex).

- [ ] **Step 1: Write the failing tests**

The sample rows below are the documented `/proc/net` format; **reconcile against `docs/step0-phase4/` (Task 7's capture) if a real row differs — the capture wins.**

Create `tests/unit/test_parse_sockets.py`:

```python
import pytest
from kdetect.parsers.sockets import (
    NetRow, SocketParseError, parse_net_tcp, parse_net_inodes,
)

TCP = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode\n"
    "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
    "     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
    "   1: 0100007F:1F90 0100007F:C3A2 01 00000000:00000000 00:00000000 00000000"
    "  1000        0 67890 1 0000000000000000 20 4 30 10 -1\n"
)

def test_parse_tcp_decodes_addr_state_inode_uid():
    rows = parse_net_tcp(TCP, "tcp")
    assert rows[0] == NetRow(inode=12345, kind="tcp", state="LISTEN",
                             local="127.0.0.1:53", remote="0.0.0.0:0", uid=0)
    assert rows[1].state == "ESTABLISHED"
    assert rows[1].local == "127.0.0.1:8080" and rows[1].uid == 1000

def test_parse_tcp_skips_header_and_blank():
    assert parse_net_tcp("sl local_address rem_address st\n\n", "tcp") == []

def test_parse_tcp6_decodes_v6():
    # loopback ::1 , port 0x1F90 = 8080
    tcp6 = (
        "  sl  local_address                         remote_address"
        "                      st ... uid ... inode\n"
        "   0: 00000000000000000000000001000000:1F90"
        " 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000"
        " 00000000     0        0 55555 1 0 100 0 0 10 0\n"
    )
    rows = parse_net_tcp(tcp6, "tcp6")
    assert rows[0].inode == 55555
    assert rows[0].local.endswith(":8080")
    assert ":" in rows[0].local           # a v6 address rendered

def test_parse_net_inodes_pulls_column():
    # /proc/net/unix: Num RefCount Protocol Flags Type St Inode Path
    unix = (
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 24680 /run/foo.sock\n"
    )
    assert parse_net_inodes(unix, 6) == {24680}

def test_parse_tcp_raises_on_short_row():
    with pytest.raises(SocketParseError):
        parse_net_tcp("  0: 0100007F:0035\n", "tcp")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_parse_sockets.py -v`
Expected: FAIL with `ModuleNotFoundError: kdetect.parsers.sockets`.

- [ ] **Step 3: Write the parsers**

Create `src/kdetect/parsers/sockets.py`:

```python
"""Pure parsers for the socket-view channels (spec §4).

Text in, typed values out, no I/O. The /proc/net/{tcp,udp}[6] tables share a
column layout; unix/netlink/packet/raw differ, but for those we need only the
inode column (to decide an fd socket is "in some table", not hidden). Each case
mirrors docs/step0-phase4/.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


class SocketParseError(ValueError):
    """A /proc/net socket table could not be parsed."""


@dataclass(frozen=True)
class NetRow:
    inode: int
    kind: str                 # "tcp" | "tcp6" | "udp" | "udp6"
    state: str | None
    local: str | None
    remote: str | None
    uid: int | None


#: TCP state codes (hex) -> name. UDP reuses the column; unknown codes pass
#: through as the raw hex so nothing is silently mislabelled.
_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}


def _decode_addr(hexaddr: str) -> str:
    """'0100007F:0035' -> '127.0.0.1:53'. v4 = 8 hex (little-endian word),
    v6 = 32 hex (four little-endian 32-bit words)."""
    ip_hex, _, port_hex = hexaddr.partition(":")
    port = int(port_hex, 16)
    if len(ip_hex) == 8:
        packed = struct.pack("<I", int(ip_hex, 16))
        ip = socket.inet_ntop(socket.AF_INET, packed)
    elif len(ip_hex) == 32:
        raw = bytes.fromhex(ip_hex)
        packed = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        ip = socket.inet_ntop(socket.AF_INET6, packed)
    else:
        raise SocketParseError(f"bad address field: {hexaddr!r}")
    return f"{ip}:{port}"


def parse_net_tcp(text: str, kind: str) -> list[NetRow]:
    """Parse a /proc/net/{tcp,tcp6,udp,udp6} table into NetRows."""
    rows: list[NetRow] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] == "sl" or not parts[0].endswith(":"):
            continue                       # header or blank
        if len(parts) < 10:
            raise SocketParseError(f"short {kind} row: {line!r}")
        try:
            rows.append(NetRow(
                inode=int(parts[9]), kind=kind,
                state=_STATES.get(parts[3].upper(), parts[3]),
                local=_decode_addr(parts[1]), remote=_decode_addr(parts[2]),
                uid=int(parts[7]),
            ))
        except (ValueError, IndexError) as exc:
            raise SocketParseError(f"bad {kind} row: {line!r}") from exc
    return rows


def parse_net_inodes(text: str, inode_index: int) -> set[int]:
    """The set of inode numbers in a table where inode is a fixed column.
    Non-numeric/short lines (headers) are skipped."""
    out: set[int] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) <= inode_index:
            continue
        try:
            out.add(int(parts[inode_index]))
        except ValueError:
            continue                       # header row
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_parse_sockets.py -v`
Expected: PASS (5 tests). If the real Task-7 capture shows a different column layout, adjust indices to the capture.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/parsers/sockets.py tests/unit/test_parse_sockets.py
git commit -m "feat(parsers): /proc/net socket table parsers (addr/state/inode decode)"
```

---

## Task 3: SocketSource

**Files:**
- Modify: `src/kdetect/collectors/base.py`, `src/kdetect/collectors/sources.py`
- Test: `tests/unit/test_socket_source.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `SocketSource(ABC)` with `read_net_table(name: str) -> str | None` and `list_fds(pid: int) -> dict[int, list[str]]`; `LiveSocketSource` (reads `/proc/net/<name>` and `/proc/<pid>/fd`); `FixtureSocketSource(root)` (reads `net/<name>.txt` and an `fds.json` mapping `{pid: [inode,...]}`).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_socket_source.py`:

```python
import json
from kdetect.collectors.sources import FixtureSocketSource

def test_fixture_reads_table_and_fds(tmp_path):
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "tcp.txt").write_text("  0: 0100007F:0035 ...\n")
    (tmp_path / "fds.json").write_text(json.dumps({"812": [12345], "4171": [999]}))
    src = FixtureSocketSource(tmp_path)
    assert "0100007F" in src.read_net_table("tcp")
    assert src.read_net_table("udp") is None          # absent -> None
    assert src.list_fds(812) == {12345: ["/proc/812/fd/0"]}
    assert src.list_fds(999999) == {}                  # unknown pid -> {}

def test_fixture_missing_tree_is_none(tmp_path):
    src = FixtureSocketSource(tmp_path)
    assert src.read_net_table("tcp") is None
    assert src.list_fds(1) == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_socket_source.py -v`
Expected: FAIL with `ImportError: cannot import name 'FixtureSocketSource'`.

- [ ] **Step 3: Add the ABC and implementations**

Add to `src/kdetect/collectors/base.py` (after `KernelHookSource`):

```python
class SocketSource(ABC):
    """The socket-view channels (spec §4): the /proc/net/* tables and per-process
    fd ownership. A table that cannot be read returns None; an unreadable pid's
    fds return {} (a hidden pid contributes nothing, not an error)."""

    @abstractmethod
    def read_net_table(self, name: str) -> str | None: ...
    @abstractmethod
    def list_fds(self, pid: int) -> dict[int, list[str]]: ...
```

Add to `src/kdetect/collectors/sources.py` (import `SocketSource`; `os`, `json`, `Path` are already imported):

```python
class LiveSocketSource(SocketSource):
    def read_net_table(self, name: str) -> str | None:
        try:
            with open(f"/proc/net/{name}", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def list_fds(self, pid: int) -> dict[int, list[str]]:
        out: dict[int, list[str]] = {}
        base = f"/proc/{pid}/fd"
        try:
            names = os.listdir(base)
        except OSError:
            return {}
        for n in names:
            try:
                target = os.readlink(f"{base}/{n}")
            except OSError:
                continue
            if target.startswith("socket:["):
                inode = int(target[len("socket:["):-1])
                out.setdefault(inode, []).append(f"{base}/{n}")
        return out


class FixtureSocketSource(SocketSource):
    """Replays a captured socket tree: net/<name>.txt tables and an fds.json
    mapping {pid: [inode, ...]}."""

    def __init__(self, root) -> None:
        self._root = Path(root)
        fds_path = self._root / "fds.json"
        self._fds = (
            {int(k): v for k, v in json.loads(fds_path.read_text()).items()}
            if fds_path.exists() else {}
        )

    def read_net_table(self, name: str) -> str | None:
        p = self._root / "net" / f"{name}.txt"
        return p.read_text(encoding="utf-8") if p.exists() else None

    def list_fds(self, pid: int) -> dict[int, list[str]]:
        return {int(inode): [f"/proc/{pid}/fd/0"] for inode in self._fds.get(pid, [])}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_socket_source.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/collectors/base.py src/kdetect/collectors/sources.py tests/unit/test_socket_source.py
git commit -m "feat(collectors): SocketSource with live and fixture implementations"
```

---

## Task 4: The socket collector

**Files:**
- Create: `src/kdetect/collectors/sockets.py`
- Test: `tests/unit/test_collector_sockets.py`
- Fixtures: `tests/fixtures/socket-trees/basic/`

**Interfaces:**
- Consumes: `SocketSource` (Task 3); `parse_net_tcp`, `parse_net_inodes`, `NetRow` (Task 2); `SocketEntity`, `Observation` (Task 1).
- Produces: `SocketCollector` with `name="procfs.sockets"`, `view="sockets"`, `trust_level=LOW`, `version="1"`, `__init__(self, pids: set[int])`, `collect(source) -> Observation`. One `SocketEntity` per inode (string-keyed); `in_table` set from any family; `owner_pids` from walking `list_fds` over `self.pids`. An fd inode in no table gets `kind="unknown"`, `in_table=False`.

- [ ] **Step 1: Create the fixture**

`tests/fixtures/socket-trees/basic/net/tcp.txt` — a listening socket (inode 12345) and an established one (inode 67890):
```
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0 100 0 0 10 0
   1: 0100007F:1F90 0100007F:C3A2 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0 20 4 30 10 -1
```
`tests/fixtures/socket-trees/basic/fds.json` — pid 812 owns the listener; pid 4171 owns an inode (55555) that is in NO table (a hidden connection); pid 67890-owner 900 owns the established socket:
```json
{"812": [12345], "900": [67890], "4171": [55555]}
```

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/test_collector_sockets.py`:

```python
from pathlib import Path
from kdetect.collectors.sockets import SocketCollector
from kdetect.collectors.sources import FixtureSocketSource
from kdetect.models import Observation, TrustLevel

BASIC = Path(__file__).parent.parent / "fixtures" / "socket-trees" / "basic"

def _collect(pids):
    return SocketCollector(set(pids)).collect(FixtureSocketSource(BASIC))

def test_table_socket_attributed_to_owner():
    obs = _collect([812, 900, 4171])
    assert obs.trust_level is TrustLevel.LOW and obs.view == "sockets"
    e = obs.entities["12345"]
    assert e.in_table is True and e.state == "LISTEN" and e.owner_pids == [812]

def test_fd_only_socket_is_not_in_table():
    obs = _collect([812, 900, 4171])
    e = obs.entities["55555"]
    assert e.in_table is False and e.kind == "unknown" and e.owner_pids == [4171]

def test_unwalked_pids_leave_socket_unowned():
    obs = _collect([])                       # walk no fds
    assert obs.entities["12345"].owner_pids == []   # still in_table from the table
    assert "55555" not in obs.entities              # fd-only inode never seen

def test_observation_round_trips():
    obs = _collect([812, 900, 4171])
    assert Observation.from_dict(obs.to_dict()) == obs
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_collector_sockets.py -v`
Expected: FAIL with `ModuleNotFoundError: kdetect.collectors.sockets`.

- [ ] **Step 4: Write the collector**

Create `src/kdetect/collectors/sockets.py`:

```python
"""The socket-view collector (spec §4.2).

procfs.sockets (LOW) records one SocketEntity per inode seen in a /proc/net/*
table or a walked /proc/<pid>/fd. It never concludes: in_table and owner_pids
are evidence; the differ decides "hidden connection" and "confirms a hidden
process". It walks fds only for the pids it is given (P10).
"""
from __future__ import annotations

import time

from kdetect.collectors.base import SocketSource
from kdetect.models import Observation, SocketEntity, Status, TrustLevel
from kdetect.parsers.sockets import parse_net_inodes, parse_net_tcp

#: Rich tables (shared tcp/udp layout) and the inode column for the rest.
_RICH = ("tcp", "tcp6", "udp", "udp6")
_INODE_ONLY = {"unix": 6, "netlink": 9, "packet": 8, "raw": 9, "raw6": 9}


class SocketCollector:
    name = "procfs.sockets"
    view = "sockets"
    trust_level = TrustLevel.LOW
    version = "1"

    def __init__(self, pids: set[int]) -> None:
        self._pids = set(pids)

    def collect(self, source: SocketSource) -> Observation:
        started = time.monotonic()
        entities: dict[str, SocketEntity] = {}
        tables_read = 0

        # Rich tcp/udp tables: full detail.
        for kind in _RICH:
            text = source.read_net_table(kind)
            if text is None:
                continue
            tables_read += 1
            for r in parse_net_tcp(text, kind):
                entities[str(r.inode)] = SocketEntity(
                    r.inode, r.kind, r.state, r.local, r.remote, r.uid,
                    in_table=True, owner_pids=[])

        # Inode-only families: just mark in_table so their inodes aren't "hidden".
        for name, idx in _INODE_ONLY.items():
            text = source.read_net_table(name)
            if text is None:
                continue
            tables_read += 1
            for inode in parse_net_inodes(text, idx):
                key = str(inode)
                if key not in entities:
                    entities[key] = SocketEntity(
                        inode, name, None, None, None, None,
                        in_table=True, owner_pids=[])

        # Attribute ownership by walking the given pids' fds.
        owners: dict[str, set[int]] = {}
        for pid in self._pids:
            for inode in source.list_fds(pid):
                owners.setdefault(str(inode), set()).add(pid)

        for key, pids in owners.items():
            if key in entities:
                e = entities[key]
                entities[key] = SocketEntity(
                    e.inode, e.kind, e.state, e.local, e.remote, e.uid,
                    e.in_table, sorted(pids))
            else:                            # fd inode in no table -> unknown, hidden
                entities[key] = SocketEntity(
                    int(key), "unknown", None, None, None, None,
                    in_table=False, owner_pids=sorted(pids))

        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=sorted(entities), entities=entities,
            stats={"tables_read": tables_read, "sockets": len(entities),
                   "pids_walked": len(self._pids)},
            errors=[],
        )
```

- [ ] **Step 5: Run tests, then commit**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_collector_sockets.py -v`
Expected: PASS (4 tests). Then the full unit suite once.

```bash
git add src/kdetect/collectors/sockets.py tests/unit/test_collector_sockets.py tests/fixtures/socket-trees/
git commit -m "feat(collectors): procfs.sockets collector with fd/inode attribution"
```

---

## Task 5: The socket detector

**Files:**
- Modify: `src/kdetect/analysis/signals.py`
- Test: `tests/unit/test_signals.py` (extend)

**Interfaces:**
- Consumes: `Signal`, `Suspect` (models); the `procfs.sockets` and `procfs.processes` observations.
- Produces: `signals_sockets(snapshot) -> list[Signal]` emitting `hidden_socket` (Suspect `("socket", str(inode))`, dissent `"/proc/net tables"`) for an owned inode with `in_table == False`, and `socket_visible` (Suspect `("process", str(pid))`, dissent `"procfs readdir (all passes)"`) for an owner pid not in the readdir listing that owns an `in_table` socket. `all_signals` now also calls `signals_sockets`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_signals.py` (imports `Suspect`, `Observation`, `SocketEntity`, `ProcessEntity`, etc. — add what's missing):

```python
from kdetect.analysis.signals import signals_sockets
from kdetect.models import SocketEntity

def _sock_snap(sockets, listed_pids):
    socks = Observation(
        collector="procfs.sockets", collector_version="1", view="sockets",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(sockets), entities=sockets, stats={}, errors=[])
    procs = Observation(
        collector="procfs.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(listed_pids),
        entities={}, stats={}, errors=[], pass_="A")
    host = HostFacts("t", "6.1", "x86_64", "b", 1, 100)
    return Snapshot(SCHEMA_VERSION, "id", "t", host, CaptureMeta("0.1.0", 0),
                    [procs, socks])

def test_hidden_socket_fires_on_untabled_owned_inode():
    socks = {"999": SocketEntity(999, "unknown", None, None, None, None,
                                 in_table=False, owner_pids=[4171])}
    sigs = signals_sockets(_sock_snap(socks, listed_pids=[1, 4171]))
    assert len(sigs) == 1
    assert sigs[0].channel == "hidden_socket"
    assert sigs[0].suspect == Suspect("socket", "999")

def test_socket_visible_fires_for_unlisted_owner_of_table_socket():
    socks = {"12345": SocketEntity(12345, "tcp", "LISTEN", "0.0.0.0:22",
                                   "0.0.0.0:0", 0, in_table=True, owner_pids=[31337])}
    sigs = signals_sockets(_sock_snap(socks, listed_pids=[1]))   # 31337 not listed
    assert len(sigs) == 1
    assert sigs[0].channel == "socket_visible"
    assert sigs[0].suspect == Suspect("process", "31337")

def test_normal_owned_table_socket_is_silent():
    socks = {"12345": SocketEntity(12345, "tcp", "ESTABLISHED", "a", "b", 0,
                                   in_table=True, owner_pids=[812])}
    assert signals_sockets(_sock_snap(socks, listed_pids=[1, 812])) == []

def test_unowned_table_socket_emits_nothing():
    socks = {"12345": SocketEntity(12345, "tcp", "TIME_WAIT", "a", "b", 0,
                                   in_table=True, owner_pids=[])}
    assert signals_sockets(_sock_snap(socks, listed_pids=[1])) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_signals.py -k socket -v`
Expected: FAIL with `ImportError: cannot import name 'signals_sockets'`.

- [ ] **Step 3: Write the detector**

Add to `src/kdetect/analysis/signals.py`:

```python
_NET_DISSENT = "/proc/net tables"


def signals_sockets(snapshot: Snapshot) -> list[Signal]:
    sock_obs = _observations(snapshot, "procfs.sockets")
    if not sock_obs:
        return []
    sockets = sock_obs[0]

    listed: set[int] = set()
    for obs in _observations(snapshot, "procfs.processes"):
        listed |= set(obs.entity_ids)

    out: list[Signal] = []
    for key in sockets.entity_ids:
        e = sockets.entities[key]
        if e.owner_pids and not e.in_table:
            out.append(Signal("hidden_socket", Suspect("socket", str(e.inode)),
                              _NET_DISSENT,
                              {"inode": e.inode, "kind": e.kind,
                               "owner_pids": list(e.owner_pids),
                               "local": e.local, "remote": e.remote}))
        if e.in_table:
            for pid in e.owner_pids:
                if pid not in listed:
                    out.append(Signal("socket_visible", Suspect("process", str(pid)),
                                      _PROCESS_DISSENT,
                                      {"inode": e.inode, "local": e.local,
                                       "remote": e.remote, "state": e.state}))
    return sorted(out, key=lambda s: (s.channel, s.suspect.name or ""))
```

Extend `all_signals` to include sockets:

```python
def all_signals(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Signal]:
    sigs = (signals_processes(snapshot) + signals_modules(snapshot)
            + signals_hooks(snapshot) + signals_sockets(snapshot))
    if baseline is not None:
        sigs += signals_baseline(snapshot, baseline)
    return sigs
```

- [ ] **Step 4: Run tests, then commit**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_signals.py -v`
Expected: PASS (existing + 4 new).

```bash
git add src/kdetect/analysis/signals.py tests/unit/test_signals.py
git commit -m "feat(analysis): signals_sockets (hidden_socket + socket_visible)"
```

---

## Task 6: Scorer — HIDDEN_CONNECTION and the HIGH hidden_process composition

**Files:**
- Modify: `src/kdetect/analysis/scoring.py`
- Test: `tests/unit/test_scoring.py` (extend)

**Interfaces:**
- Consumes: `signals_sockets` output shape (Task 5); the `Suspect("socket", …)` kind and `FindingKind.HIDDEN_CONNECTION` (Task 1).
- Produces: `_classify` returns `HIDDEN_CONNECTION` for `Suspect.kind == "socket"`; `_HIDING` includes `hidden_socket` and `socket_visible`. No change to grouping/attribution — `socket_visible` composes with `syscall_kill`+`direct_status` on the same process suspect → HIGH.

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_scoring.py`:

```python
def test_socket_visible_lifts_hidden_process_to_high():
    p = Suspect("process", "1234")
    sigs = [
        Signal("syscall_kill", p, "procfs readdir (all passes)", {"tgid": 1234}),
        Signal("direct_status", p, "procfs readdir (all passes)", {"tgid": 1234}),
        Signal("socket_visible", p, "procfs readdir (all passes)", {"inode": 999}),
    ]
    findings = score(sigs)
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.HIDDEN_PROCESS
    assert findings[0].confidence is Confidence.HIGH        # 3 channels

def test_hidden_socket_is_a_low_hidden_connection():
    s = Suspect("socket", "999")
    findings = score([Signal("hidden_socket", s, "/proc/net tables",
                             {"inode": 999, "owner_pids": [4171]})])
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.HIDDEN_CONNECTION
    assert findings[0].subject == "socket inode 999"
    assert findings[0].confidence is Confidence.LOW
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_scoring.py -k "socket or hidden_connection" -v`
Expected: FAIL — `HIDDEN_CONNECTION` classify branch missing, so a socket suspect misclassifies.

- [ ] **Step 3: Extend the scorer**

In `src/kdetect/analysis/scoring.py`, add the socket channels to `_HIDING`:

```python
_HIDING = {"taint", "vmalloc_region", "ftrace_orphan", "unexpected_hook",
           "syscall_kill", "direct_status", "hidden_socket", "socket_visible"}
```

Add the socket branch to `_classify` (immediately after the `process` branch, before the `suspect.name is None` branch):

```python
    if suspect.kind == "socket":
        return (FindingKind.HIDDEN_CONNECTION, f"socket inode {suspect.name}",
                f"socket inode {suspect.name} is held by a process but appears in "
                f"no /proc/net table")
```

- [ ] **Step 4: Run tests, then commit**

Run: `.venv/Scripts/python.exe -m pytest tests/unit/test_scoring.py -v`
Expected: PASS (existing + 2 new).

```bash
git add src/kdetect/analysis/scoring.py tests/unit/test_scoring.py
git commit -m "feat(analysis): HIDDEN_CONNECTION + socket_visible -> HIGH hidden_process"
```

---

## Task 7: Wire the socket collector into capture; step-0 evidence

**Files:**
- Modify: `src/kdetect/cli.py`
- Test: `tests/integration/test_capture.py` (extend), `tests/unit/test_ground_truth.py` (extend)
- VM (Angus): `docs/step0-phase4/`

**Interfaces:**
- Consumes: `SocketCollector` (Task 4), `LiveSocketSource` (Task 3), the `analyze` pipeline (all prior tasks).
- Produces: `capture` emits a `procfs.sockets` observation built over `readdir ∪ sweep` pids; the clean fixtures still analyze to zero findings.

- [ ] **Step 1: Wire capture**

In `src/kdetect/cli.py`, import the new pieces and, in `cmd_capture`, after the existing observations are collected, compute the pid union and append the socket observation:

```python
from kdetect.collectors.sockets import SocketCollector
from kdetect.collectors.sources import (  # add to the existing import
    LiveSocketSource,
)
# ... after observations = [ ... KernelHookCollector().collect(hooks) ]:
    pids = set(observations[0].entity_ids) | set(observations[1].entity_ids)
    observations.append(SocketCollector(pids).collect(LiveSocketSource()))
```

(`observations[0]` is procfs pass A, `observations[1]` is the sweep — both carry the entity_ids the socket collector needs to walk fds, including any hidden pid.)

- [ ] **Step 2: Extend the capture integration test**

Add to `tests/integration/test_capture.py` (module is `@needs_procfs`, skips on Windows):

```python
def test_capture_emits_sockets_observation():
    import kdetect.cli as cli
    rc = cli.main(["capture", "--out", "-"])   # or the harness's capture entrypoint
    assert rc == 0
```
(Match the existing test style in the file — assert a `procfs.sockets` observation is present in a captured snapshot, using the same capture helper the other integration tests use.)

- [ ] **Step 3: Guard clean-machine zero findings**

Confirm the socket view does not fire on the committed clean fixtures. Since those fixtures predate the socket collector they carry no `procfs.sockets` observation, so `signals_sockets` returns `[]` — but assert it explicitly. Add to `tests/unit/test_ground_truth.py`:

```python
def test_clean_fixtures_have_no_socket_findings():
    from kdetect.analysis.models import FindingKind
    for name in ("clean-phase2.json", "clean-phase3a.json"):
        kinds = {f.kind for f in analyze(_load(name))}
        assert FindingKind.HIDDEN_CONNECTION not in kinds
        assert not any(f.subject.startswith("socket ") for f in analyze(_load(name)))
```

- [ ] **Step 4: Run tests**

Run: `.venv/Scripts/python.exe -m pytest tests/unit -q`
Expected: all green on Windows (integration skips). The capture wiring is exercised live on the VM in Step 5.

- [ ] **Step 5: Step-0 evidence + live capture (VM, Angus)**

On the VM, capture the `/proc/net/*` formats and calibrate:
```bash
D=~/projects/kdetect/docs/step0-phase4; mkdir -p "$D"
for f in tcp tcp6 udp udp6 unix netlink packet raw raw6; do sudo cat /proc/net/$f > "$D/$f.txt" 2>/dev/null; done
sudo .venv/bin/kdetect capture --out /tmp/clean-sock.json
.venv/bin/kdetect analyze /tmp/clean-sock.json     # EXPECT: findings none
```
Record in `docs/step0-phase4/README.md`: the column layouts actually seen (reconcile Task 2's `_INODE_ONLY` indices if any differ), and the clean-machine counts of untabled-fd and unowned-table sockets. **If `analyze` shows any socket finding on the clean capture, that is a calibration gap** — capture it and we tighten `signals_sockets` (e.g. exclude a socket whose owner pid vanished mid-capture) before proceeding.

- [ ] **Step 6: Commit**

```bash
git add src/kdetect/cli.py tests/integration/test_capture.py tests/unit/test_ground_truth.py
git commit -m "feat(cli): capture emits procfs.sockets over the readdir+sweep pid union"
```
(Angus commits the `docs/step0-phase4/` evidence separately from the VM, from a clean tree.)

---

## Task 8: Docs — L23, L24, detection-methods, architecture

**Files:**
- Modify: `docs/limitations.md`, `docs/detection-methods.md`, `docs/architecture.md`

**Interfaces:**
- Consumes: nothing.
- Produces: L23/L24 recorded; the socket method and its correlation documented.

- [ ] **Step 1: Add L23 and L24 to `docs/limitations.md`** (verbatim from spec §11), after L22.

- [ ] **Step 2: Add a socket method entry to `docs/detection-methods.md`** — observes the `/proc/net/*` tables vs `/proc/<pid>/fd` ownership; the two signals (`hidden_socket` → `HIDDEN_CONNECTION`; `socket_visible` → the third channel lifting `hidden_process` to HIGH); the dropped orphan-socket direction and why; cites the phase-4a spec. Mark `[implemented — phase 4a]`.

- [ ] **Step 3: Update `docs/architecture.md`** — add the socket collector to the collector layout and note the capture-time pid-union wiring (P10). Cite the phase-4a spec.

- [ ] **Step 4: Commit**

```bash
git add docs/limitations.md docs/detection-methods.md docs/architecture.md
git commit -m "docs: phase 4a socket method, L23 (module<->socket), L24 (synthetic ground truth)"
```

---

## Self-Review

**Spec coverage:**
- §3 architecture (collector → detector → scorer; pid union) → Tasks 4, 5, 7.
- §4 source/collector/entity → Tasks 1 (entity), 2 (parsers), 3 (source), 4 (collector). All nine families read → Task 4 `_RICH`/`_INODE_ONLY`.
- §5 signals + FP calibration (drop orphan) → Task 5 (`hidden_socket`, `socket_visible`; no orphan emitted); LOW confidence → Task 6 test.
- §6 correlation + HIGH hidden_process → Task 6 (`socket_visible` composes to HIGH; `HIDDEN_CONNECTION` socket suspect).
- §7 schema/CLI → Task 1 (entity/kind/registry), Task 6 (`_HIDING`/`_classify`), Task 7 (capture wiring; analyze unchanged).
- §8 testing/step-0/criteria → Tasks 2–7 (criterion 1 clean-zero → Task 7 Step 3; criteria 2/3 → Task 6; criterion 4 orphan-silent → Task 5; step-0 → Task 7 Step 5).
- §11 L23/L24 → Task 8.

**Deviations / notes, flagged:**
1. **`_HIDING` gains `hidden_socket`/`socket_visible` though `_classify` never consults them for socket/process suspects** (both are classified by dedicated `suspect.kind` branches that don't check `_HIDING`). Added per spec §7 and for consistency ("channels that indicate concealment"); it is defensive, not load-bearing. A reviewer may flag it as unused — it is spec-mandated and harmless.
2. **`socket_visible` can only fire for a swept pid** (the collector walks only `readdir ∪ sweep`, and the signal requires "not in readdir"), so it always lands on a pid `signals_processes` also flags → composes to HIGH, never a lone LOW process finding. This is the criterion-1 safety argument; no code enforces it beyond the pid-union wiring (Task 7) and is worth preserving.
3. **`_INODE_ONLY` column indices are the documented defaults**, reconciled against the real `docs/step0-phase4/` capture in Task 7 Step 5 ("capture wins"), the same discipline phase 3a used for `enabled_functions`.

**Placeholder scan:** none — every code/test step is complete. Task 7 Step 2's integration assertion says to match the file's existing capture helper (the file's harness is not reproduced here); that is a real, bounded instruction, not a placeholder.

**Type consistency:** `SocketEntity` fields identical across Tasks 1/4/5. `NetRow` fields consistent Tasks 2/4. `SocketSource.read_net_table`/`list_fds` signatures match Tasks 3/4. Channel strings (`hidden_socket`, `socket_visible`) consistent Tasks 5/6. `Suspect("socket", str(inode))` and `FindingKind.HIDDEN_CONNECTION` consistent Tasks 1/5/6. `all_signals`/`analyze` unchanged signatures. The pid union uses `observations[0]` (procfs A) and `observations[1]` (sweep) — consistent with `cmd_capture`'s existing build order.

---

## Execution Handoff

Plan complete. Save location: `docs/superpowers/plans/2026-09-03-kdetect-phase4a.md`.
