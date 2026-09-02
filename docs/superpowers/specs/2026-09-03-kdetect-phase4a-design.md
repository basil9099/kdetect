# kdetect Phase 4a — Network Sockets & Cross-View Correlation Design

**Date:** 2026-09-03
**Status:** Approved, ready for implementation planning
**Scope:** Phase 4a of the phase-4 decomposition (brief deliverable 6). A socket
collector, socket cross-view signals, proc↔socket correlation, and the deferred
HIGH `hidden_process` path. Feeds the existing detect→score pipeline; no new
analysis machinery. Reporting/IOCs/redaction (deliverable 8) is phase 4b.

---

## 1. Context

The phase-1 decomposition put deliverables 6 (network sockets, correlation) and
8 (reporting, IOCs) together as "phase 4". They are independent subsystems —
one produces findings, the other presents them — so this spec covers deliverable
6 as **phase 4a**; reporting, IOC extraction, and the L13 redaction pass become
**phase 4b**.

Phase 3b left the analysis layer as a two-stage pipeline: pure detectors emit
`Signal`s, a pure `score()` groups them per suspect and counts distinct
corroborating channels for confidence (P8/P9). Phase 4a extends it the natural
way — one new collector, one new detector, new channels flowing into the same
scorer. Nothing in `scoring.py`'s grouping or attribution logic changes.

Phase 4a also finally delivers the **HIGH `hidden_process`** path, deferred since
phase 2 and again in 3b for want of "an identity channel the pure differ lacks."
That channel is now here: a socket owned by a pid the `/proc` listing hides.

### 1.1 The cross-view

Sockets are detected the project's central way — the same question through
channels of differing trust. Two `/proc` surfaces answer "which sockets exist":

- the kernel socket **tables** (`/proc/net/{tcp,tcp6,udp,udp6,unix,netlink,packet,raw,raw6}`) — a hookable LOW surface a rootkit can filter;
- per-process **ownership** (`/proc/<pid>/fd/socket:[inode]`) — which process holds which socket inode.

Their disagreement is the signal: a socket a process holds that appears in no
table (a hidden connection), or a socket owned by a pid `/proc` won't list
(a hidden process confirmed from the network). A third independent channel —
`sock_diag` netlink — was considered and **rejected for 4a** (§9): strong, but it
requires hand-built `AF_NETLINK` messaging in stdlib, and the fd↔table cross-view
catches the realistic cases without it.

---

## 2. Principles

Phase 1's P1–P3, phase 2's P4–P5, phase 3a's P6–P7, and phase 3b's P8–P9 all
still hold. Phase 4a adds one, a consequence of P8 for a collector that must see
hidden pids.

**P10 — The socket collector observes the pids it is given, not a list it
trusts.** Attributing a *hidden* pid's sockets requires reading
`/proc/<hidden_pid>/fd` directly, so the collector walks fds over the union of
the readdir pids and the sweep's task ids, supplied by the capture orchestrator
(`cli.py`), exactly as the sandwich supplies the sweep. The collector records
`owner_pids` as evidence and never decides which owner is hidden — that is the
detector's cross-reference against the readdir listing (P8).

---

## 3. Architecture & data flow

```
capture (cli.py orchestration):
  procfs A → sweep → procfs B → modules → kernel.hooks → procfs.sockets
                                                              ▲
     cli.py passes the socket collector the pid union (readdir ∪ sweep task ids)
     so a hidden pid's /proc/<pid>/fd is walked and its sockets attributed
        │
        ▼
  Snapshot
        │
  signals_sockets(snapshot)  ──> [Signal]   (new detector in analysis/signals.py)
        │
  score(all signals)         ──> [Finding]  (analysis/scoring.py, unchanged)
```

**Files:**
- **Create** `src/kdetect/parsers/sockets.py` — pure parsers: `/proc/net/*` table rows (hex addr:port decode, inode, state, uid) and the `socket:[inode]` fd form.
- **Create** `src/kdetect/collectors/sockets.py` — `SocketCollector` (LOW).
- **Modify** `src/kdetect/collectors/base.py` — `SocketSource` ABC.
- **Modify** `src/kdetect/collectors/sources.py` — `LiveSocketSource`, `FixtureSocketSource`.
- **Modify** `src/kdetect/models.py` — `SocketEntity`; register `procfs.sockets`; `Suspect.kind` gains `"socket"` (no structural change).
- **Modify** `src/kdetect/analysis/signals.py` — `signals_sockets`; add to `all_signals`.
- **Modify** `src/kdetect/analysis/scoring.py` — `_HIDING` gains the two socket channels; `_classify` maps `Suspect("socket", …)` → `HIDDEN_CONNECTION`.
- **Modify** `src/kdetect/analysis/models.py` — `FindingKind.HIDDEN_CONNECTION`.
- **Modify** `src/kdetect/cli.py` — capture runs `SocketCollector` with the pid union.

The two stages stay independently testable: the collector against a fixture
socket-tree, the detector/scorer against hand-built snapshots/signal lists.

---

## 4. Socket source, collector & entity

### 4.1 Source

`SocketSource` (ABC; `Live*` reads the real files, `Fixture*` replays a tree):
- `read_net_table(name: str) -> str | None` for each of `tcp, tcp6, udp, udp6, unix, netlink, packet, raw, raw6` — a channel that cannot be read returns `None` and is skipped (as `ModuleSource` does).
- `list_fds(pid: int) -> dict[int, list[str]]` — `readlink` every `/proc/<pid>/fd/*`, returning `{inode: [fd_path, …]}` for entries whose target is `socket:[inode]`; unreadable pids/fds yield `{}` (a hidden pid whose fd dir is unreadable simply contributes nothing, not an error).

**All nine table families are read**, not just tcp/udp: an fd `socket:[inode]`
that is really a unix or netlink socket must be found in *some* table, or it
would look hidden. "Hidden" means "in no family's table."

### 4.2 Collector

`procfs.sockets` → view `sockets`, trust **LOW**, string-keyed by inode.
Constructor takes the pid set to walk: `SocketCollector(pids: set[int])`. It
records **evidence only** (P1/P4): one `SocketEntity` per inode seen in either a
table or a walked fd.

`SocketEntity` (frozen; `to_dict`/`from_dict`):

```
inode: int
kind: str            # "tcp" | "tcp6" | "udp" | ... | "unix" | ... | "unknown"
state: str | None    # "ESTABLISHED" | "LISTEN" | "TIME_WAIT" | ... ; None for fd-only
local: str | None    # "ip:port" decoded; None where the table doesn't give one
remote: str | None
uid: int | None
in_table: bool       # appeared in some /proc/net/* table
owner_pids: list[int]  # pids whose fd walk referenced this inode (sorted)
```

`stats` record counts (tables read, table socket count, fd-attributed count).
The collector concludes nothing: `in_table` and `owner_pids` are facts;
"hidden connection" and "confirms a hidden process" are the detector's calls.

---

## 5. Socket signals & FP calibration

`signals_sockets(snapshot)` reads the `procfs.sockets` observation and the
readdir listing (`procfs.processes` entity_ids, unioned across passes). It emits
**two** channels:

- **`hidden_socket`** → `Suspect("socket", str(inode))`: a `SocketEntity` with
  `owner_pids` non-empty and `in_table == False` — a socket a process holds that
  no kernel table admits. Evidence: inode, kind, `owner_pids`, fd paths. Dissent:
  `"/proc/net tables"`.
- **`socket_visible`** → `Suspect("process", str(pid))`: for a pid in a socket's
  `owner_pids` that is **not** in the readdir listing and that owns a socket with
  `in_table == True` — the network view confirms a process `/proc` hides. Evidence:
  the inode, its local/remote/state. Dissent: `"procfs readdir (all passes)"`.

**Deliberately not emitted — standalone orphan socket** (a table entry with empty
`owner_pids`). On a clean host `TIME_WAIT`/`CLOSE_WAIT` sockets, kernel-internal
sockets, and sockets whose owner's fds were unreadable all present as unowned;
emitting them would fire on every clean machine (the paramount FP guard, §8).
An unowned table socket becomes signal only when its owner is a hidden pid — which
is precisely `socket_visible`.

**Confidence** follows the unchanged count model. A lone `hidden_socket` is one
channel → **LOW**: the capture is not atomic (L8), so a single untabled fd can be
a mid-capture race, "investigate, not proof" — the same honesty as a lone
`module_taint_mismatch` (L17). It rises only under real corroboration (§6).

---

## 6. Correlation & the HIGH `hidden_process` path

Correlation is the scorer's existing per-suspect composition; no new engine.

- **HIGH `hidden_process`** (deferred since phase 2): a swept-but-unlisted pid
  gets `syscall_kill` + `direct_status` from `signals_processes` (2 → MEDIUM); if
  it owns a table-visible socket, `signals_sockets` adds `socket_visible` → **3
  distinct channels → HIGH**. The pid is confirmed real from signal delivery,
  direct status read, and the network stack.
- **A hidden pid holding a hidden connection** yields two cross-referencing
  findings: one `HIDDEN_PROCESS` for the pid (its process/socket channels), and a
  separate `HIDDEN_CONNECTION` for the untabled socket whose evidence names the
  owner pid. The reader sees the process and the connection it hides.
- **proc ↔ module** already composes (separate findings on one capture).

**Module ↔ socket is out of scope (L23).** A kernel backdoor's in-kernel socket
has no owning userspace pid, and "a listening socket with no process" is exactly
the orphan case §5 drops — kernel services legitimately hold such sockets.
Correlating a hidden module to a mystery port would be a heuristic guess, not a
cross-view fact, so 4a keeps correlation to proc ↔ socket.

---

## 7. Schema & CLI

Additive; schema stays **1.1** (a new collector name and entity type, as
`kernel.hooks` was in 3a).

- `SocketEntity` (§4.2), registered in `_ENTITY_TYPES["procfs.sockets"]` and
  `_STRING_ID_COLLECTORS` (inode-string keys).
- `Suspect.kind` gains `"socket"` — `Suspect` is already `(kind, name)`, so no
  dataclass change.
- Two new `Signal` channels: `hidden_socket`, `socket_visible`; both added to
  `scoring.py`'s `_HIDING` set (both indicate concealment).
- One new `FindingKind`: `HIDDEN_CONNECTION`. `_classify` maps
  `Suspect.kind == "socket"` → `HIDDEN_CONNECTION`; the process/module/anonymous
  branches are unchanged.

**CLI.** `cmd_capture` computes `pids = readdir ∪ sweep task ids` and runs
`SocketCollector(pids).collect(LiveSocketSource())` as the sixth-plus observation.
`cmd_analyze` is unchanged (`analyze()` already scores every signal). Findings
section, `--json`, `--baseline`, exit code 3 all unchanged in shape.

---

## 8. Testing, ground truth & limitations

All pure tiers run on Windows with the VM off (V1); only live capture needs Linux.

- **Parsers** (`tests/unit/test_parse_sockets.py`): hex `ip:port` decode for v4/v6,
  state-code mapping, inode/uid extraction, and the `socket:[inode]` fd form —
  each case drawn verbatim from `docs/step0-phase4/`.
- **Collector** (`test_collector_sockets.py`): against a fixture socket-tree,
  asserting `in_table`/`owner_pids` attribution and `None`-channel handling.
- **Detector** (`test_signals.py`, extended): `hidden_socket` fires on an
  untabled owned inode; `socket_visible` fires for an unlisted owner of a table
  socket; neither fires for a normal owned+tabled socket; standalone orphan
  sockets emit nothing.
- **Scorer** (`test_scoring.py`, extended): the three-channel HIGH
  `hidden_process`; `HIDDEN_CONNECTION` as a socket suspect; a lone `hidden_socket`
  → LOW.
- **Ground-truth regression** (`test_ground_truth.py`): the clean fixtures must
  still yield **zero findings** once the socket collector runs — the paramount
  guard extended to the socket view.

### 8.1 Step-0 gate

`docs/step0-phase4/` hand-exploration on the VM before any schema field is final:
the `/proc/net/*` row formats, the fd `socket:[inode]` shape, and **clean-machine
calibration** — how many untabled-fd sockets and unowned-table sockets a clean
idle VM legitimately has. That number decides whether `hidden_socket` needs any
guard beyond "in no table" (e.g. excluding a socket that vanished mid-capture).

### 8.2 Ground truth is largely synthetic (L24)

We have no socket-hiding rootkit: Diamorphine's hooks didn't engage on 6.1 (L16),
and the benign test LKM hides a module, not a connection. So:
- **HIGH `hidden_process`** is validated by a hand-built snapshot — a pid in the
  sweep, absent from readdir, owning a table socket — the same synthetic route
  phase 2 used for process detection under L16.
- **`hidden_socket`** is validated by a hand-built scenario: hold a real socket,
  doctor the `/proc/net` fixture to omit its inode, and confirm the signal.
This is recorded as L24; a live socket-hiding rootkit is out of reach this phase.

### 8.3 Acceptance criteria

1. Clean fixtures → **zero findings** through the full pipeline including the
   socket view.
2. A synthetic capture with a swept-but-unlisted pid owning a table socket →
   exactly one `HIDDEN_PROCESS` at **HIGH**, channels ⊇ {`syscall_kill`,
   `direct_status`, `socket_visible`}.
3. A synthetic capture with a process-owned inode in no table → one
   `HIDDEN_CONNECTION` (socket suspect) at LOW, evidence naming the owner pid.
4. A standalone unowned table socket (e.g. `TIME_WAIT`) → **no finding**.
5. `capture` emits a `procfs.sockets` observation; `analyze` lists it.
6. Unit suite green on Windows; the 3.11 guard (`test_python311_compat.py`) green.

Criterion 1 remains paramount: the socket view must not make a clean machine fire.

---

## 9. Decisions and rationale

| Decision | Alternative rejected | Reason |
|---|---|---|
| Split 4a (sockets/correlation) from 4b (reporting/IOCs) | one phase 4 | independent subsystems — one produces findings, one presents them; each is a clean single spec |
| fd↔table cross-view, `/proc` only | add `sock_diag` netlink channel | netlink needs hand-built `AF_NETLINK` messaging in stdlib; fd↔table catches realistic cases and is honestly bounded — netlink can be a later channel if it earns its place |
| Emit `hidden_socket` + `socket_visible`; drop standalone orphan-socket | detect orphan table sockets | orphan sockets are FP-prone on a clean host (TIME_WAIT, kernel sockets, unreadable owners); an orphan matters only when owned by a hidden pid = `socket_visible` |
| Socket suspect for a hidden connection | key it by the owning process | a hidden connection is a distinct fact (`HIDDEN_CONNECTION`); keying by inode keeps `_classify` clean and lets it stand alongside the owner's `HIDDEN_PROCESS` |
| Collector walks the pid union it is given (P10) | collector sweeps pids itself | reuses the sweep's work; walking `/proc/<pid>/fd` over 1..pid_max would be far slower; keeps the collector pure over a supplied list |
| Confidence = count model, unchanged | boost `hidden_socket` above LOW | the capture is not atomic; a lone untabled fd can be a race — LOW ("investigate") is honest, HIGH comes from corroboration |
| Module ↔ socket not attempted | correlate hidden modules to mystery ports | no owning pid for kernel sockets; "listening socket, no process" is the dropped orphan case — a guess, not a cross-view fact (L23) |

---

## 10. Deferred

Not in phase 4a, by intent: reporting, IOC extraction, and the L13 redaction pass
(**phase 4b**, deliverable 8); a `sock_diag`/netlink independent socket channel
(revisit if fd↔table proves insufficient); module ↔ socket correlation (L23);
active port probing; eBPF and out-of-band memory forensics; off-host baselines.
Phase 4a adds the socket view, its two cross-view signals, and the HIGH
`hidden_process` path, all on the existing `Signal`/`score` seam.

---

## 11. Limitations entering phase 4a

Recorded here and to be mirrored in `docs/limitations.md`.

**L23 — Module↔socket correlation is not attempted.** A kernel backdoor listening
on an in-kernel socket has no owning userspace pid, and an unowned listening
socket is indistinguishable on a clean host from legitimate kernel services
(the orphan-socket false-positive class, §5). kdetect correlates sockets to
processes, not to modules; a hidden module opening a raw kernel socket is not
detected via the socket view.

**L24 — Socket detection is validated synthetically, not against a live
socket-hiding rootkit.** No available rootkit hides a socket on kernel 6.1
(Diamorphine's hooks did not engage, L16; the benign test LKM hides a module,
not a connection). The `hidden_socket` and HIGH `hidden_process` paths are
validated by hand-built snapshots and doctored `/proc/net` fixtures. As with the
phase-2 process detection, "the differ detects this" rests on synthetic ground
truth plus the clean-baseline zero-findings guard, not on a live capture of the
technique.
