# Architecture

How kdetect is put together, and why. The full phase 1 specification is in
[`superpowers/specs/2026-08-18-kdetect-phase1-design.md`](superpowers/specs/2026-08-18-kdetect-phase1-design.md);
the raw `/proc` observations every decision here rests on are in
[`step0/`](step0/README.md).

## The idea

A kernel rootkit's job is to lie to userspace. Any single question you ask the
system can be answered falsely, so kdetect does not try to find the one channel
that cannot be lied to — there isn't one. Instead it asks the **same question
through several channels of differing trustworthiness and compares the answers**.
Disagreement is the signal.

Phase 1 builds only one channel. It contains no detection at all. Its whole
purpose is to get the data model right before anything depends on it.

## Three layers

```
Source            ->   Parse             ->   Collector
(all I/O)              (pure functions)       (assembles an Observation)
```

Only `Source` touches the operating system. `Parse` takes text and returns typed
values, raising `ParseError` on malformed input and never touching a file.
`Collector` orchestrates the two and records what happened, including failures.

**A collector receives its source as an argument** rather than constructing one:

```python
ProcfsProcessCollector().collect(LiveProcSource())
ProcfsProcessCollector().collect(FixtureProcSource(path))
```

That single choice is what makes the seam real. There is no `if testing:` branch
anywhere, so a fixture-driven test exercises the identical code path as a live
capture. Measured consequence: 55 of 66 tests run on a Windows host with no
`/proc` at all, including the full collector.

`ProcSource` is an interface rather than a configurable root path because **a
fixture must be able to reproduce failures, not only successes**. A directory of
copied files can replay the happy path alone, but every false-positive class in
this project lives in the failure paths — the kernel thread with no `exe`, the
`EACCES` read, the process that vanished mid-scan. So a fixture tree carries an
`_errors.json` sidecar mapping `"<pid>/<name>"` to an errno name, and those reads
raise instead of returning content.

## Three principles

**P1 — Snapshots hold evidence, not conclusions.** Collectors record what they
observed and never label. There is no `is_kernel_thread` field: `flags` is
`stat` field 9, `PF_KTHREAD` is bit `0x00200000`, and analysis derives the rest.
A collector that judges cannot be audited — and the derived form would have been
wrong anyway, as an unprivileged capture cannot read `exe` at all.

**P2 — Disagreement between collectors must be representable.** Per-entity
detail lives inside each observation, never in a table shared between them. Two
collectors reporting different `comm` for the same PID *is the finding*; a shared
table can only hold one answer.

**P3 — Test code and production code are the same code.** See above.

## Trust levels

| Level | Channel | Why |
|---|---|---|
| `LOW` | `/proc` directory listing | A hooked `getdents` or patched proc handler can simply omit an entry |
| `MEDIUM` | direct syscall sweep, `kill(pid, 0)` across the PID space | Harder to fake consistently; phase 2 |
| `HIGH` | eBPF probes | Observes kernel events directly; phase 5 |

Phase 1 emits only `LOW`. The full enum exists now so later phases add values
rather than change meanings.

## Analysis: detect → score (phase 3b)

The analysis layer is a second two-stage pipeline sitting on top of the
snapshot, split the same way collection is split from parsing:

```
Snapshot (+ optional baseline)
   │
   ├─ detectors (pure, src/kdetect/analysis/signals.py) ──> list[Signal]
   │     signals_processes / signals_modules / signals_hooks / signals_baseline
   │
   └─ score(signals) (pure, src/kdetect/analysis/scoring.py) ─> list[Finding]
         group by suspect → attribute anonymous → count channels → compose
```

Each detector in `signals.py` observes one view and emits `Signal`s — a channel
name, a `Suspect` (`kind` + optional `name`), and evidence — drawing no
confidence and composing nothing. `score()` in `scoring.py` groups signals by
suspect, counts the distinct corroborating channels per suspect for confidence,
and composes one `Finding` per suspect; `analyze(snapshot, baseline=None)` is
`score(all_signals(...))`. `cli.py`'s `analyze` command calls `analyze()`.

This replaced an earlier design (phases 2–3a) of independent per-channel
differs, each computing its own finding and confidence from a corroboration
count scoped to its own view — `crossview.py` and `baseline_diff.py`, calling
into a `diff_all()` entry point. That model could not compose evidence for one
suspect across passes: a module caught by both a module-listing channel and a
hook-surface channel produced two separate low/medium findings instead of one
high-confidence one. Both files are gone; their logic lives in `signals.py`'s
detector functions. See
[`superpowers/specs/2026-08-30-kdetect-phase3b-design.md`](superpowers/specs/2026-08-30-kdetect-phase3b-design.md)
§3–§5 for the full data flow, the `Suspect`/`Signal` model, and the scoring and
attribution rules.

## The snapshot format

### A complete snapshot, with two views

Illustrating P2. The second observation is phase 2 work, shown to prove the
schema accommodates it without a special case.

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

PID 31337 is in the second view's `entity_ids` and not the first. That is what
the phase 2 differ reports. Note the second observation carries no `entities` at
all — a `kill(pid, 0)` sweep learns existence and nothing else.

`host.btime` and `host.clock_ticks_per_sec` are mandatory because `starttime_ticks`
is measured in clock ticks since boot; wall-clock time is
`btime + starttime_ticks / clock_ticks_per_sec`. `host.boot_id` is mandatory
because PIDs and start times are only comparable within one boot.

### One observation in isolation

```json
{
  "collector": "procfs.processes",
  "collector_version": "1",
  "view": "processes",
  "trust_level": "LOW",
  "status": "PARTIAL",
  "duration_ms": 11,
  "entity_ids": [1, 812],
  "entities": {
    "1": {
      "pid": 1, "ppid": 0, "comm": "systemd", "state": "S",
      "flags": 4194560, "num_threads": 1, "starttime_ticks": 72,
      "cmdline": ["/lib/systemd/systemd", "--system"],
      "exe": "/usr/lib/systemd/systemd",
      "uid": [0, 0, 0, 0], "gid": [0, 0, 0, 0], "partial": []
    },
    "812": {
      "pid": 812, "ppid": 1, "comm": "sshd", "state": "S",
      "flags": 4194560, "num_threads": 1, "starttime_ticks": 72,
      "cmdline": ["/usr/sbin/sshd", "-D"], "exe": null,
      "uid": [0, 0, 0, 0], "gid": [0, 0, 0, 0], "partial": ["exe"]
    }
  },
  "stats": { "scanned": 2, "collected": 2, "vanished": 0 },
  "errors": [
    { "entity_id": 812, "kind": "denied", "detail": "resolving /proc/812/exe: Permission denied (errno 13)" }
  ]
}
```

Both entities above could have been written with `exe: null`. They mean
different things, and the schema keeps them apart:

| `exe` | `partial` | Meaning |
|---|---|---|
| `"/usr/bin/foo"` | `[]` | read successfully |
| `null` | `[]` | genuinely has none — `ENOENT`, a kernel thread |
| `null` | `["exe"]` | exists, access denied — `EACCES` |

Collapsing the last two rows destroys the distinction. Evidence:
[`step0/06-exe-errno-comparison.txt`](step0/06-exe-errno-comparison.txt).

## Design questions, and the answers chosen

These are the four questions the project brief asked to be settled on paper,
before any code.

**1. Does an Observation hold one entity, or a whole view?**
A whole view. The differ compares *sets* of identifiers, and per-entity records
would make set operations awkward — you would be grouping rows back into views
on every comparison.

**2. Where does per-entity detail live: inside the observation, or in a lookup
keyed by PID?**
Inside the observation. A shared table keyed by PID would feel DRY-er and would
break the tool: two collectors disagreeing about PID 4171's `comm` is precisely
what kdetect exists to find, and a shared table can only store one answer (P2).

`entity_ids` and `entities` are both present and are not redundant. A collector
can prove an entity exists without reading any detail about it — the phase 2
`kill(pid, 0)` sweep does exactly that — so the invariant is
`set(entities) ⊆ set(entity_ids)`, and the differ compares `entity_ids` only.

**3. How does a collector report partial failure?**
A `status` of `OK` / `PARTIAL` / `FAILED`, plus structured `errors[]` and
`stats`, plus a per-entity `partial[]` listing fields that could not be read.

| Kind | Cause | Effect on status |
|---|---|---|
| `vanished` | `ESRCH`/`ENOENT` on a listed PID | **none** — stays `OK` |
| `denied` | `EACCES`/`EPERM` | `PARTIAL` |
| `malformed` | read succeeded, parse failed | `PARTIAL` |
| `io_error` | anything else | `PARTIAL` |

`FAILED` is reserved for being unable to enumerate at all. The first row is the
important one: a process exiting mid-scan is normal Linux, not an error. Letting
it degrade status would raise an alarm on every capture ever taken.

**4. What is the version field, and what happens when the format changes?**
`schema_version`, as `MAJOR.MINOR`. A differing MAJOR means a field was removed,
renamed, or changed meaning, and `analyze` refuses to load — in either
direction, because silently misreading old data is worse than refusing it. A
newer MINOR is additive-only: it loads, and warns on stderr about keys it does
not recognise. The check runs before anything else is parsed, so a
partially-parsed `Snapshot` never escapes into the program.

## Parsing note

`/proc/[pid]/stat` cannot be split on whitespace. Field 2 is wrapped in
parentheses and may itself contain spaces and parentheses:

```
6041 (ev (il) proc) S 6009 6009 6009 0 -1 4194304 ...
```

A naive `split()` yields `state = "(il)"` and `ppid = "proc)"` — silent
misalignment of every subsequent field, not an exception. The parser locates the
**last** `)` and splits only what follows. Evidence:
[`step0/03-comm-paren-trap.txt`](step0/03-comm-paren-trap.txt).

## Layout

| Path | Responsibility |
|---|---|
| `src/kdetect/models.py` | Schema types, serialisation, version gate |
| `src/kdetect/parsers/procfs.py` | Pure parse functions |
| `src/kdetect/collectors/base.py` | `ProcSource` and `Collector` interfaces, error hierarchy |
| `src/kdetect/collectors/sources.py` | `LiveProcSource`, `FixtureProcSource` |
| `src/kdetect/collectors/procfs.py` | `ProcfsProcessCollector` |
| `src/kdetect/hostfacts.py` | Host context gathering |
| `src/kdetect/analysis/models.py` | `Suspect`, `Signal`, `Finding`, `FindingKind`, `Confidence` |
| `src/kdetect/analysis/signals.py` | Detectors: `Snapshot -> list[Signal]` (pure) |
| `src/kdetect/analysis/scoring.py` | `score`/`analyze`: `list[Signal] -> list[Finding]` (pure) |
| `src/kdetect/cli.py` | `capture` and `analyze` |
| `tools/capture_fixture.py` | Lab utility that builds a fixture tree |
