# kdetect Phase 1 — Foundation Design

**Date:** 2026-08-18
**Status:** Approved, ready for implementation planning
**Scope:** Phase 1 of 5. Capture → serialise → load → summarise, with one collector.

---

## 1. Context

kdetect is a Linux kernel rootkit detection system. Its central technique is
**cross-view comparison**: ask the same question through several channels of
differing trustworthiness, and treat disagreement as signal.

The source brief lists eight deliverables spanning independent subsystems.
That is too large for one specification, so the work is decomposed:

| Phase | Content | Brief deliverables |
|---|---|---|
| 0 | Lab VM, hand-exploration of `/proc` | groundwork — **complete** |
| **1** | **Snapshot schema, models, CLI, procfs collector, round-trip** | **foundation** |
| 2 | Second/third collectors, cross-view differ, Diamorphine ground truth | 3, 5 |
| 3 | Baseline store, kallsyms integrity, rule engine, scoring | 7 |
| 4 | Network sockets, correlation, reporting, IOCs | 6, 8 |
| 5 | eBPF collectors, Volatility memory analysis, optional LKM | 2, 4 |

`docs/limitations.md` is a running log across all phases, not a phase.

Phase 1 contains **no detection logic**. Its sole purpose is to establish a data
model that later phases can build on without renegotiation. The milestone is a
clean round-trip: a capture written to disk, loaded back into typed objects, and
summarised.

### 1.1 Evidence base

The schema below is derived from direct observation recorded in `docs/step0/`,
captured on Debian 12, kernel `6.1.0-10-amd64`. Two design changes came out of
that exploration and are marked **[Step 0]** where they appear.

---

## 2. Principles

These three decide most of the detailed questions that follow.

**P1 — Snapshots hold evidence, not conclusions.** Collectors record what they
observed, including failures, and never label. No `is_kernel_thread` field; the
raw `flags` integer is stored and analysis derives meaning. A collector that
judges cannot be audited.

**P2 — Disagreement between collectors must be representable.** Per-entity detail
lives inside each observation, never in a shared table keyed by PID. Two
collectors reporting different `comm` for the same PID *is the finding*; a shared
table can only hold one answer.

**P3 — Test code and production code are the same code.** Collectors receive
their data source as an argument. There is no `if testing:` branch anywhere, so a
fixture-driven test exercises the identical path as a live capture.

---

## 3. Snapshot schema

### 3.1 Top level

```json
{
  "schema_version": "1.0",
  "snapshot_id": "b3f1c8e2-7a4d-4f19-9c2e-1d8a3f5b6c07",
  "captured_at": "2026-08-18T02:01:08.412Z",
  "host": {
    "hostname": "kdetect-lab",
    "kernel_release": "6.1.0-10-amd64",
    "arch": "x86_64",
    "boot_id": "4fa7045a-84bd-4d90-a7d8-14980ed01bf9",
    "btime": 1787032782,
    "clock_ticks_per_sec": 100
  },
  "capture": {
    "tool_version": "0.1.0",
    "euid": 0
  },
  "observations": []
}
```

`btime` and `clock_ticks_per_sec` are mandatory because `stat` field 22
(`starttime`) is expressed in clock ticks since boot. Without both it cannot be
converted to wall-clock time. Verified in `docs/step0/01-stat-fields.txt`:
`btime + starttime/CLK_TCK` matched `ps -o lstart=` exactly.

`boot_id` is mandatory because PIDs and start times are only comparable within a
single boot. Diffing captures from different boots is meaningless, and without
`boot_id` nothing detects that mistake.

### 3.2 Observation

An Observation is **one whole view from one collector**, not one entity.

```json
{
  "collector": "procfs.processes",
  "collector_version": "1",
  "view": "processes",
  "trust_level": "LOW",
  "status": "OK",
  "duration_ms": 84,
  "entity_ids": [1, 2, 6009],
  "entities": { "1": {}, "2": {} },
  "stats": { "scanned": 249, "collected": 247, "vanished": 2 },
  "errors": []
}
```

`entity_ids` is a JSON array with set semantics: **unique, sorted ascending**.
`entities` is a map of detail keyed by the same identifier. **These are not
redundant.** A collector may prove an entity exists without reading any detail
about it — phase 2's `kill(pid, 0)` sweep does exactly this. The invariant is:

```
set(entities.keys()) is a subset of set(entity_ids)
```

The differ compares `entity_ids` only. JSON object keys are strings, so
`entities` keys are the decimal string form of the integer id; converting back on
load is a deliberate responsibility of `from_dict`.

`trust_level` is one of `LOW`, `MEDIUM`, `HIGH`. Phase 1 emits only `LOW`; the
full enum is defined now so later phases add values, not meanings.

### 3.3 Process entity

```json
{
  "pid": 1,
  "ppid": 0,
  "comm": "systemd",
  "state": "S",
  "flags": 4194560,
  "num_threads": 1,
  "starttime_ticks": 6,
  "cmdline": ["/sbin/init"],
  "exe": "/usr/lib/systemd/systemd",
  "uid": [0, 0, 0, 0],
  "gid": [0, 0, 0, 0],
  "partial": []
}
```

`uid` and `gid` are four-element arrays `[real, effective, saved, fs]` as given by
the `Uid:` and `Gid:` lines of `/proc/[pid]/status`.

**`flags` is `stat` field 9, stored as a raw integer. [Step 0]** Bit
`0x00200000` is `PF_KTHREAD`, the kernel's own answer to "is this a kernel
thread". This replaces any heuristic based on empty `cmdline`, which would
otherwise have been the project's first false-positive class. Observed values:
`kthreadd` 2129984, a `kworker` 69238880, `systemd` 4194560, `bash` 4194304
(`docs/step0/07-pf-kthread-flags.txt`).

**`exe` is three-state, not a nullable string. [Step 0]**

| `exe` | `partial` | Meaning |
|---|---|---|
| `"/usr/bin/foo"` | `[]` | read successfully |
| `null` | `[]` | genuinely has no executable — `ENOENT`, a kernel thread |
| `null` | `["exe"]` | exists but could not be read — `EACCES` |

Collapsing the last two rows into a bare `null` destroys the distinction.
Confirmed in `docs/step0/06-exe-errno-comparison.txt`: as root `/proc/2/exe`
gives `ENOENT(2)` while as an unprivileged user `/proc/1/exe` gives `EACCES(13)`.

The `(deleted)` suffix that `readlink` may return — indicating the running binary
has been unlinked from disk — is preserved verbatim. It is one of the strongest
single indicators available and must not be stripped.

### 3.4 Worked example — two views

Illustrating P2 and the `entity_ids` / `entities` split. The second observation is
phase 2 work, shown here only to prove the schema accommodates it.

```json
{
  "schema_version": "1.0",
  "snapshot_id": "b3f1c8e2-7a4d-4f19-9c2e-1d8a3f5b6c07",
  "captured_at": "2026-08-18T02:01:08.412Z",
  "host": {
    "hostname": "kdetect-lab",
    "kernel_release": "6.1.0-10-amd64",
    "arch": "x86_64",
    "boot_id": "4fa7045a-84bd-4d90-a7d8-14980ed01bf9",
    "btime": 1787032782,
    "clock_ticks_per_sec": 100
  },
  "capture": { "tool_version": "0.1.0", "euid": 0 },
  "observations": [
    {
      "collector": "procfs.processes",
      "collector_version": "1",
      "view": "processes",
      "trust_level": "LOW",
      "status": "OK",
      "duration_ms": 84,
      "entity_ids": [1, 2],
      "entities": {
        "1": {
          "pid": 1, "ppid": 0, "comm": "systemd", "state": "S",
          "flags": 4194560, "num_threads": 1, "starttime_ticks": 6,
          "cmdline": ["/sbin/init"], "exe": "/usr/lib/systemd/systemd",
          "uid": [0, 0, 0, 0], "gid": [0, 0, 0, 0], "partial": []
        },
        "2": {
          "pid": 2, "ppid": 0, "comm": "kthreadd", "state": "S",
          "flags": 2129984, "num_threads": 1, "starttime_ticks": 6,
          "cmdline": [], "exe": null,
          "uid": [0, 0, 0, 0], "gid": [0, 0, 0, 0], "partial": []
        }
      },
      "stats": { "scanned": 3, "collected": 2, "vanished": 1 },
      "errors": [
        { "entity_id": 4171, "kind": "vanished", "detail": "ENOENT reading stat" }
      ]
    },
    {
      "collector": "syscall_sweep.processes",
      "collector_version": "1",
      "view": "processes",
      "trust_level": "MEDIUM",
      "status": "OK",
      "duration_ms": 312,
      "entity_ids": [1, 2, 31337],
      "entities": {},
      "stats": { "scanned": 32768, "collected": 3, "vanished": 0 },
      "errors": []
    }
  ]
}
```

PID 31337 appears in the second view's `entity_ids` and not the first. That
difference is exactly what phase 2's differ will report, and the schema
represents it without any special case. Note the second observation carries no
`entities` at all — a `kill(pid, 0)` sweep learns existence and nothing else.

### 3.5 Versioning

`schema_version` is `MAJOR.MINOR`.

- **MAJOR** — a field was removed, renamed, or changed meaning. `analyze` refuses
  to load and exits 1 with a clear message.
- **MINOR** — additive only. Loads successfully; unknown fields are ignored with a
  warning on stderr.

The version check runs at the top of `Snapshot.from_dict`, before any observation
is parsed. A partially-parsed Snapshot must never escape into the program: either
a whole valid object is returned, or an `IncompatibleSnapshot` exception is
raised.

---

## 4. Collectors

### 4.1 Three layers

```
Source            ->   Parse             ->   Collector
(all I/O)              (pure functions)       (assembles Observation)
```

Only `Source` touches the operating system.

**`ProcSource`** — two implementations, one interface:

```python
list_pids()           -> list[int]   # numeric dirents only, sorted
read_text(pid, name)  -> str         # "stat", "cmdline", "status"
read_link(pid, name)  -> str         # "exe", "cwd" - raw target, suffix intact
```

Implementations raise domain errors (`Vanished`, `Denied`, `Unreadable`) rather
than leaking `OSError`. `LiveProcSource` reads `/proc`; `FixtureProcSource` reads
a captured tree.

This is an interface rather than a configurable root path because **a fixture must
be able to reproduce failures, not only successes**. A directory of copied files
can replay the happy path alone, yet every false-positive class in this project
lives in the failure paths: the kernel thread with no `exe`, the `EACCES` read,
the process that vanished mid-scan. The fixture format therefore records errors
alongside content (section 7.2).

**Parse functions** — `parse_stat`, `parse_cmdline`, `parse_status`. Pure: text
in, typed values out, no I/O, raising `ParseError` on malformed input.

`parse_stat` must locate the **last** `)` in the line and parse remaining fields
from there. Splitting on whitespace is incorrect because `comm` may contain
spaces and parentheses. Evidence, from `docs/step0/03-comm-paren-trap.txt`:

```
6041 (ev (il) proc) S 6009 6009 6009 0 -1 4194304 ...
```

A naive split yields `state = "(il)"` and `ppid = "proc)"` — silent misalignment
of every subsequent field, not an exception.

**`Collector` ABC:**

```python
class Collector(ABC):
    name: str                 # "procfs.processes"
    view: str                 # "processes"
    trust_level: TrustLevel   # LOW
    version: str
    def collect(self, source: ProcSource) -> Observation: ...
```

`collect()` takes the source as an argument (P3). Choosing live or fixture is a
caller decision, invisible to the collector.

### 4.2 Error taxonomy and status

| Kind | Cause | Effect on `status` |
|---|---|---|
| `vanished` | `ESRCH` / `ENOENT` on a PID that was in the listing | **none** — remains `OK` |
| `denied` | `EACCES` / `EPERM` | `PARTIAL` |
| `malformed` | Read succeeded, parse failed | `PARTIAL` |
| `io_error` | Anything else | `PARTIAL` |

`FAILED` is reserved for the case where `list_pids()` itself fails.

A process exiting mid-scan is normal Linux behaviour, not an error. It is counted
under `stats.vanished` and leaves `status` at `OK`. Letting it degrade status
would raise an alarm on every capture ever taken.

`denied` while running as root is a materially different event from `denied` as an
unprivileged user — potentially a rootkit obstructing inspection. The collector
does not make that judgement. It records the error kind and `capture.euid`;
analysis draws the conclusion in a later phase (P1).

### 4.3 Phase 1 collector

`procfs.processes`, trust level `LOW`. Walks `/proc`, skips non-numeric entries,
reads `stat`, `cmdline` and `status`, and `readlink`s `exe`. Returns one
Observation.

---

## 5. CLI

```
kdetect capture [--out PATH] [--pretty]
kdetect analyze SNAPSHOT
```

`argparse` from the standard library. Two subcommands do not justify a
dependency. No `--collectors` flag and no plugin registry in phase 1 — there is
one collector; the flag arrives when there is a genuine choice to make.

**`capture`** defaults to writing a generated filename and printing that path to
stdout. `--out -` writes the snapshot to stdout for piping.

```
captures/20260818T020108Z_kdetect-lab_4fa7045a.json
```

UTC, with no `:` characters — colons are illegal in Windows filenames and these
files are copied to the Windows host as test fixtures. Lexically sortable. The
`boot_id` prefix makes it visible at a glance which captures share a boot.

If `euid != 0`, `capture` writes a warning to **stderr** stating that
address-bearing data will be zeroed, and proceeds. It does not refuse. It records
`euid` and lets analysis interpret it (P1). Justification in section 11.2.

**`analyze`** loads a snapshot and prints a summary:

```
snapshot:  captures/20260818T020108Z_kdetect-lab_4fa7045a.json
schema:    1.0
host:      kdetect-lab  6.1.0-10-amd64  x86_64
captured:  2026-08-18T02:01:08Z   boot 4fa7045a
euid:      0

collectors:
  procfs.processes   trust=LOW   status=OK   247 entities   84ms
                     scanned=249  collected=247  vanished=2
```

**Exit codes:** `0` success, `1` error, `2` usage. `3` is reserved for "analysis
produced findings" and must not be used for anything else, so that phase 2 can
introduce it without breaking scripts.

### 5.1 Data flow

```
capture   LiveProcSource -> Collector.collect() -> Observation
                                                        |
                    Snapshot(host, capture, [obs]) -> to_dict() -> json.dump

analyze   json.load -> from_dict() -> Snapshot -> summary
```

The governing invariant:

```
from_dict(to_dict(s)) == s          # and re-serialisation is byte-identical
```

Byte-identity requires deterministic serialisation, so it is specified rather
than left to chance:

- `json.dump(..., sort_keys=True, separators=(",", ":"))` for the compact form
- `--pretty` uses `indent=2` with the same `sort_keys=True`
- `entity_ids` sorted ascending (section 3.2)
- `partial` sorted alphabetically
- `errors` in the order encountered, which is `entity_ids` order

Timestamps are UTC ISO-8601 with millisecond precision and a `Z` suffix.
Without these rules "byte-identical" is not a testable property, because Python
dict ordering would silently satisfy it on one run and not the next.

---

## 6. On-disk layout

```
captures/                              # gitignored
tests/fixtures/
  proc-trees/clean-vm-6.1.0-10/        # FixtureProcSource input
    proc/
    _errors.json                       # replayed errnos
  snapshots/clean-vm.json              # full Snapshot, round-trip input
data/baselines/                        # phase 3, gitignored
```

Both gitignore rules already exist in the repository.

---

## 7. Testing

### 7.1 Tiers

| Tier | Exercises | Runs on |
|---|---|---|
| Parse | Pure functions, tables of strings | anywhere |
| Collector | `FixtureProcSource` -> full Observation | anywhere |
| Round-trip | `from_dict(to_dict(s)) == s` | anywhere |
| Integration | `LiveProcSource` against real `/proc` | Linux only |

`pytest`. The integration tier is gated on **capability, not platform**:
`Path("/proc/self/stat").exists()`. What the tests require is a procfs, not a
particular operating system name.

Consequence: the first three tiers run on the Windows development host with the
VM powered off.

### 7.2 Fixtures

Fixtures are **curated, not dumped**. A full `/proc` tree is roughly a thousand
files and tests nothing that ten chosen processes do not: PID 1, `kthreadd`, a
`kworker`, an ordinary user process, one permission-denied, one with parentheses
in `comm`, one staged to vanish.

Format: a directory tree mirroring `/proc`; symlinks recorded as `<name>.readlink`
text files, since Windows cannot create symlinks without elevated privileges; and
a `_errors.json` sidecar mapping relative paths to errno names so failures can be
replayed.

`tools/capture-fixture.sh` builds the tree. It is a lab utility, not part of
kdetect.

The round-trip fixture `tests/fixtures/snapshots/clean-vm.json` is the exception
and may be a full real capture, since it is one file and the point is to prove a
realistic snapshot survives serialisation.

**Fixtures are the only captures that leave the machine.** They contain hostnames,
usernames, paths and command lines. Review before committing.

### 7.3 Cases

Drawn from `docs/step0/`:

- `parse_stat` on `6041 (ev (il) proc) S 6009 ...` gives `state == "S"` and
  `ppid == 6009`
- `parse_stat` on a normal line, on a `comm` at the 15-character limit, and on a
  truncated line raising `ParseError`
- `flags == 2129984` has `PF_KTHREAD` set; `flags == 4194304` has it clear
- `ENOENT` on `exe` gives `exe is None` and `"exe" not in partial`
- `EACCES` on `exe` gives `exe is None` and `"exe" in partial`
- Empty `cmdline` on a kernel thread is not an error
- Process vanishing mid-read leaves `status == "OK"` and `stats.vanished == 1`
- Malformed `stat` gives `status == "PARTIAL"`
- `set(entities.keys())` is a subset of `set(entity_ids)`
- Round-trip preserves integer entity ids across JSON string keys
- Unknown minor-version field loads with a warning; major mismatch raises

Implementation is test-first: transcribe the assertion from the Step 0 evidence,
watch it fail, then write the parser.

---

## 8. Acceptance criteria

```
1.  kdetect capture --help  and  kdetect analyze --help  run
2.  kdetect capture  writes JSON to captures/ and prints its path
3.  kdetect analyze <file>  prints the section 5 summary block
4.  Round-trip: from_dict(to_dict(s)) == s, re-serialisation byte-identical
5.  Curated fixture tree exists under tests/fixtures/proc-trees/
6.  Parse tests cover: paren comm, kernel thread, denied, vanished, malformed
7.  Unit suite passes ON WINDOWS with the VM powered off
8.  Integration suite passes on the VM
9.  A live capture contains kdetect's own PID
10. docs/architecture.md holds the two worked JSON examples from section 3
```

Item 9 asserts that **a snapshot contains the process that produced it** — the
collector, its threads, the shell that launched it. It is the smallest possible
instance of the cross-view principle, it costs three lines, and a snapshot
missing its own author is one that cannot be trusted.

---

## 9. Decisions and rationale

| Decision | Alternative rejected | Reason |
|---|---|---|
| Observation = one whole view | one entity per Observation | the differ compares sets; per-entity records make set operations awkward |
| Detail inside the observation | shared table keyed by PID | a shared table cannot represent two collectors disagreeing (P2) |
| `flags` stored raw | an `is_kernel_thread` boolean | evidence, not conclusions (P1); the derived form cannot be audited |
| `ProcSource` interface | a configurable root path | a fixture must replay failures, not only successes |
| stdlib `dataclasses` | Pydantic | the serialisation boundary is what phase 1 exists to prove, and a library hides it. Revisit in phase 3, where validating user-authored YAML is a real need |
| stdlib `argparse` | click / typer | two subcommands, five flags |
| `capture` defaults to a file | stdout | captures are kept and named; `--out -` covers piping |
| Gate tests on `/proc` existing | a `sys.platform` check | the requirement is a procfs, not an OS name |
| `vanished` leaves status `OK` | treating it as an error | processes exit constantly; otherwise every capture cries wolf |

---

## 10. Deferred

Not in phase 1, by intent: detection, cross-view diffing, rules, baselines, a
second collector, `config.py`, a logging framework, plugin discovery, CI, and
coverage targets. Empty directories are acceptable; empty abstractions are not.

---

## 11. Known limitations entering phase 1

Recorded here and mirrored in `docs/limitations.md`.

**11.1 Lab provenance.** The VM is a third-party prebuilt image with
unverifiable provenance, publicly documented default credentials, and
passwordless sudo. Acceptable for phase 1, which performs no detection.
**Rebuild from the Debian netinst installer before phase 2**, where the baseline
becomes ground truth. The GitHub deploy key held on this VM should be rotated or
removed before any live rootkit is run on it.

**11.2 Kernel address visibility is gated by two sysctls, not one.** On this host
`kptr_restrict=0` but `perf_event_paranoid=3`, so unprivileged reads of
`/proc/kallsyms` and `/proc/modules` return zeroed addresses.
`kallsyms_show_value()` only honours `kptr_restrict=0` when
`perf_event_paranoid <= 1`; otherwise it requires `CAP_SYSLOG`. kdetect
therefore needs root, or `CAP_SYSLOG`, for any address-based detection.
(`docs/step0/09-kallsyms-user-vs-root.txt`)

**11.3 `comm` truncates at 15 characters** and cannot identify longer process
names.

**11.4 The observer appears in the observation.** kdetect's own process and
threads, plus the VS Code Remote-SSH `node` processes, are present in every
capture taken on this host.

**11.5 The invocation environment is recorded in the output.** The same collector
run interactively versus over SSH reports different `tty_nr` and `tpgid` for its
own shell — `34816` (a pty) versus `0`/`-1` (none).
