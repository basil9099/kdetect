# kdetect Phase 2 — Cross-View Detection Design

**Date:** 2026-08-20
**Status:** Approved, ready for implementation planning
**Scope:** Phase 2 of 5. Two views (processes, modules), the cross-view differ,
and Findings. First phase that detects anything.

---

## 1. Context

Phase 1 built a snapshot that records evidence and draws no conclusions. Phase 2
adds the conclusions. Its central technique is **cross-view comparison**: ask the
same question through channels of differing trustworthiness, and treat
disagreement as signal.

Two questions are asked this phase:

- **Which processes exist?** — asked through readdir of `/proc` (LOW, hookable),
  a `kill(id,0)` sweep of the whole pid space (MEDIUM), and direct
  `/proc/<pid>/status` access (MEDIUM, bypasses readdir).
- **Which modules are loaded?** — asked through `/proc/modules` (the list a
  rootkit unlinks itself from) and three channels that do **not** share that
  list's source: kernel taint accounting, `load_module` vmalloc regions, and
  ftrace's per-module function records.

Ground truth is Diamorphine, an LKM rootkit that hides processes by filtering
`getdents64` and hides its own module by unlinking it from the kernel `modules`
list.

Phase 1 left the ground prepared: `TrustLevel.MEDIUM` is defined but unused, exit
code 3 is reserved for "analysis produced findings", the `entity_ids` / `entities`
split lets a sweep prove existence without detail, and the schema already permits
two observations of the same `view` from different collectors (the worked example
in the phase 1 spec §3.4 is a phase 2 sweep).

### 1.1 Evidence base

Every design choice below traces to `docs/step0-phase2/clean/`, captured on the
rebuilt lab VM, kernel `6.1.0-52-amd64`, as root. Where a number appears it is
from that pass and cited by file. The infected half of the evidence
(`docs/step0-phase2/infected-diamorphine/`) is captured during implementation,
per the runbook in `docs/step0-phase2/README.md`; the design is built to be
confirmed by it, not to depend on having it yet.

---

## 2. Principles

Phase 1's P1–P3 still hold. Phase 2 adds two, both consequences of P1.

**P4 — Collectors record channels; the differ draws conclusions.** The sweep
collector records the `Tgid` it read for each task, not "this is a thread". The
module-evidence collector records the taint word and a region count, not "a
module is hidden". Folding threads and declaring a module hidden are the differ's
job, so both are auditable against the recorded evidence rather than trusted.

**P5 — A Finding carries the evidence it was drawn from.** A Finding is a
conclusion, which phase 1 forbade in a snapshot and phase 2 permits only in the
analysis layer. The safeguard is that every Finding cites the exact field values
that produced it, so a reader can trace it back into the snapshot and check it.
A conclusion that cannot be traced to evidence cannot be audited (the mirror of
P1).

---

## 3. What the clean baseline established

These measurements are the reason the differ is shaped the way it is. Each is a
false-positive class the differ must neutralise, or a channel property it relies
on.

**FP class #1 — threads outnumber processes 5:3.** `/proc` top-level lists 133
thread-group leaders; the sweep finds 223 tasks; the 90-task difference is
entirely ordinary threads of visible processes, resolvable by `Tgid`
(`02-sweep-vs-listing.txt`, `01-listing-vs-tasks.txt`). A naive `sweep − listing`
diff reports **90 hidden processes on an idle clean machine**. The differ must
fold tasks into their leader before comparing.

**The sandwich separates timing from hiding.** A sweep takes ~3.1 s; a `/proc`
walk takes milliseconds. Under process churn the channels disagree purely from
timing (`03-sandwich-race.txt`). Running `procfs → sweep → procfs` and requiring
a suspect to be absent from **both** walks reduces the timing-only disagreements
to zero.

**The three module *lists* share one source.** `/proc/modules` (72),
`/sys/module` (136), and kallsyms `[tags]` (73) all read the kernel `modules`
list; a `list_del` hides from all three at once. Their only clean-baseline value
is false-positive calibration (`05-module-three-lists.txt`):

- FP class #2 — `/sys/module` − `/proc/modules` is built-in code with a sysfs
  parameter directory. Discriminator: a real loaded module has a
  `/sys/module/<name>/initstate` file; every built-in lacks one.
- FP class #3 — kallsyms `[bpf]` is a JIT tag, not a module.

**Three independent module channels, each with a measured clean baseline:**

| Channel | Clean baseline | Evidence file |
|---|---|---|
| Taint accounting | bits 12/13 **clear**; 0 listed modules marked `(O)/(E)` | `08-taint-accounting.txt` |
| `load_module` regions | **72** regions == 72 listed modules | `07-vmallocinfo-modules.txt` |
| ftrace tag set | 68 modules tagged; ftrace ⊆ listing (the 4-module gap is listing − ftrace) | `06-ftrace-module-tags.txt` |

**L15 (new limitation) — vmallocinfo addresses are hash-obfuscated.** Region
addresses print as hashed pointers (`0x12b28f67`, not `0xffffffffc0…`),
independent of `kptr_restrict=0`, because `%p` hashing is separate from
`kptr_restrict`. The vmallocinfo channel can therefore yield a **count only** —
never a name, and no address to correlate against `/proc/modules`. Count-mismatch
remains a valid signal; attribution does not come from this channel.

---

## 4. Process view

### 4.1 Collectors

Two new collectors join phase 1's `procfs.processes`.

`procfs.processes` (LOW) is **run twice** in one capture, producing two
observations of view `processes`. They are distinguished by a new optional
`pass` field on the observation (`"A"` / `"B"`); absent on any single-pass
collector. This is the sandwich's two slices of bread.

`syscall_sweep.processes` (**MEDIUM**) is the filling. It:

1. sweeps `kill(id, 0)` across `1..pid_max` and collects every id that returns
   success or `EPERM` (both mean *exists*; `ESRCH` means *gone*);
2. for each responding id, reads `/proc/<id>/status` and records its `Tgid` and
   whether the read succeeded.

Its Observation:

```json
{
  "collector": "syscall_sweep.processes",
  "view": "processes",
  "trust_level": "MEDIUM",
  "entity_ids": [1, 2, 551, 552, ...],
  "entities": {
    "551": { "tgid": 501, "status_readable": true },
    "31337": { "tgid": 31337, "status_readable": true }
  },
  "stats": { "pid_max": 4194304, "responded": 223, "sweep_ms": 3140 }
}
```

`entity_ids` are the alive task-ids (P4: what the sweep observed). `entities`
records the folding evidence per task, not the fold itself. `pid_max` is in
`stats` because a sweep is only meaningful against the space it covered.

Reading `Tgid` directly is deliberate: `/proc/<id>/status` is reached by path
lookup, not readdir, so a `getdents64`-hooking rootkit does not hide it. This is
what keeps the sweep independent of the procfs view rather than folding through
it.

**Schema version → 1.1.** Two optional fields are added to the Observation: `pass`
(§4.1) and `extra` (§5.1). Both are additive, so this is a MINOR bump under phase
1's rule (§3.5 of the phase 1 spec): a 1.0 reader loads a 1.1 snapshot, warning
about the unknown keys; a 1.1 reader loads a 1.0 snapshot, treating the absent
fields as `None`. No field changes meaning, so MAJOR stays 1. `from_dict` must
default both to `None` when absent.

### 4.2 The differ

`analysis/crossview.py`, function `diff_processes(snapshot) -> list[Finding]`,
pure. Given the two procfs passes A and B and the sweep observation:

```
listed        = set(procfs_A.entity_ids) | set(procfs_B.entity_ids)
absent_both    = { id for id in sweep.entity_ids
                     if id not in procfs_A.entity_ids
                    and id not in procfs_B.entity_ids }
```

For each id in `absent_both`, consult the sweep's recorded `tgid`:

- `tgid` is in `listed` → an ordinary **thread** of a visible process. Not a
  finding. (Neutralises FP class #1.)
- `tgid` not in `listed`, `status_readable` true → **hidden_process**. The sweep
  and direct access both see a process that neither readdir pass listed.
- `status_readable` false → the task vanished between the sweep and the fold.
  Counted, not reported.

A finding's subject is the `tgid` (the process), reported once even when several
of its threads were the ones the sweep caught.

**Confidence.** If the differ can additionally read identity for the hidden
process — `comm`, `exe`, `starttime` via `/proc/<tgid>/*`, the direct-access
channel — the finding is **HIGH**: three channels (sweep, direct status, direct
identity) agree the process exists while readdir denies it. Existence via the
sweep alone is **MEDIUM**.

The reverse asymmetry — a pid in a procfs pass but missing from the sweep — is
**not** a hidden-process finding. The sweep covers the whole pid space, so it
cannot be made to under-report by hiding; a listing-only pid is a mid-capture
race (the sweep ran before it started) and is left to the pass-A/pass-B timing
logic.

---

## 5. Module view

### 5.1 Collectors

`procfs.modules` (**LOW**) parses `/proc/modules` and reads
`/sys/module/*/initstate` to mark which sysfs entries are genuinely loaded
modules versus built-ins. This is the listing a rootkit filters. Its entities
carry each module's name, size, refcount, dependents, state, base address, and
taint marker — the raw `/proc/modules` columns (P1).

`kernel.module_evidence` (**MEDIUM**) records the three independent channels as
evidence, judging nothing:

```json
{
  "collector": "kernel.module_evidence",
  "view": "modules",
  "trust_level": "MEDIUM",
  "entity_ids": [],
  "entities": {},
  "stats": {
    "taint": 0,
    "load_module_regions": 72,
    "ftrace_available": true,
    "ftrace_module_count": 68
  },
  "extra": {
    "listed_taint_markers": 0,
    "ftrace_modules": ["ac", "aesni_intel", "..."]
  }
}
```

An `extra` free-form object on the observation holds channel detail that is not
per-entity — the ftrace name set, the per-module taint markers. It is additive
and MINOR-versioned. When a channel is unreadable (no tracefs, or vmallocinfo
denied because not root), its stat is recorded as `null` and the differ skips
that channel rather than treating absence as agreement.

### 5.2 The differ

`diff_modules(snapshot) -> list[Finding]`, pure. Let `listed` be the loaded
modules from `procfs.modules` (initstate-filtered, excluding built-ins — FP class
#2 — and never treating a kallsyms `[bpf]` tag as a module — FP class #3).

- **module_taint_mismatch** — taint bit 12 (out-of-tree) or 13 (unsigned) is set,
  yet no module in `listed` carries an `(O)`/`(E)` marker. Clean baseline: bits
  clear, markers 0, so any firing is real. Subject: the taint bit; no module name
  is available from this channel.
- **unexplained_module_region** — `load_module_regions` > `len(listed)`. Clean:
  72 == 72. Subject: the count delta (anonymous — L15).
- **ftrace_orphan_module** — a name in `ftrace_modules` absent from `listed`.
  Clean: ftrace ⊆ listing, so the set is empty. Subject: the module name — this
  is the only channel that attributes.

### 5.3 Confidence by corroboration

A hidden module tends to trip several of these at once: Diamorphine is
out-of-tree and unsigned (taint), keeps its vmalloc region (region count), and —
if it has traceable functions — keeps its ftrace tag. Confidence is the count of
independent channels that agree a module is hidden:

- three channels → **HIGH**
- two → **MEDIUM**
- one → **LOW**

That is the entire scoring rule. There is no per-channel weight and no tunable
threshold; corroboration count is the score. Findings from channels that name the
module (ftrace) and findings that only count (taint, region) are correlated by
the differ into one finding per hidden module where the names permit, and left
separate where they do not.

---

## 6. Finding model

`analysis/models.py`, `Finding` dataclass. A Finding is analysis output. It is
**never written into a snapshot** (P1). It may be serialised to JSON for phase 4
reporting.

```python
@dataclass(frozen=True)
class Finding:
    kind: FindingKind          # hidden_process | module_taint_mismatch |
                               # unexplained_module_region | ftrace_orphan_module
    subject: str               # "pid 31337" | "module diamorphine" | "taint bit 12"
    confidence: Confidence     # LOW | MEDIUM | HIGH
    channels_agree: list[str]  # collectors/channels that support it
    channels_dissent: list[str]# channels that denied it (e.g. "procfs readdir")
    evidence: dict             # exact values traced from the snapshot (P5)
    summary: str               # one human-readable line
```

`to_dict` is deterministic (sorted keys, sorted channel lists) so a findings dump
round-trips and diffs cleanly, matching phase 1's serialisation discipline.

`evidence` is a plain dict of the cited values — for `hidden_process`:
`{"tgid": 31337, "seen_by_sweep": true, "in_procfs_A": false, "in_procfs_B": false,
"comm": "...", "exe": "..."}`. It is what makes P5 concrete: the reader recomputes
the conclusion from it.

---

## 7. CLI

`capture` gains the new collectors and now runs the process sandwich. No new
flags — there is still one sensible set of collectors and no choice to expose.

`analyze` keeps its phase 1 summary block and appends a findings section:

```
findings:
  [HIGH]   hidden_process   pid 31337  (comm "sleep", exe /usr/bin/sleep)
           seen by: syscall_sweep, direct status, direct identity
           denied by: procfs readdir (both passes)
  [MEDIUM] module_taint_mismatch  taint bit 12 (out-of-tree) set,
           0 listed modules carry (O)/(E)
           seen by: kernel.module_evidence taint
```

**`--json`** dumps `[Finding.to_dict(), ...]` to stdout instead of the text
block, for phase 4 to consume. The summary block is suppressed under `--json`.

**Exit codes.** Phase 1's contract holds: `0` success, `1` error, `2` usage.
Phase 2 activates **`3`**: `analyze` exits 3 if **any** finding fired, of any
confidence. The contract is deliberately blunt — exit 3 means "something to look
at", and confidence lives in the output for a human or phase 4 to weigh. No
confidence threshold gates the exit code, so automation keying on it never
silently drops a low-confidence finding.

---

## 8. Layering

```
Source            ->  Parse            ->  Collector          ->  Differ
(all I/O)             (pure)               (assembles Obs)        (pure: Snapshot
                                                                  -> [Finding])
```

The differ is the new layer and the only new code that draws conclusions. It
reads a whole `Snapshot` and returns Findings, touching no I/O, so it runs
identically on a live capture, a committed fixture, and a hand-built snapshot in
a unit test. New sources needed:

- `ProcSource` gains `read_link`/`read_text` use for `/proc/<id>/status` in the
  sweep (already in the interface) and a `sweep_pids(pid_max)` — but a sweep is
  `kill(id,0)`, not a `/proc` read, so it belongs on a new tiny **`SignalSource`**
  interface (`exists(id) -> Existence`), with a live implementation over
  `os.kill` and a fixture implementation that replays a recorded id set. This
  keeps P3 intact: the sweep collector takes its source as an argument and a
  fixture reproduces a hidden PID without one ever existing.
- A `ModuleSource` for `/proc/modules`, `/sys/module/*`, `/proc/vmallocinfo`,
  `/proc/sys/kernel/tainted`, and the tracefs file, live and fixture, translating
  errno the way `ProcSource` does.

---

## 9. Testing

Phase 1's four tiers extend unchanged (Parse / Collector / Round-trip /
Integration), gated on capability (`/proc` exists), so the first three run on the
Windows host with the VM off. Phase 2 adds a **Differ** tier: a differ test builds
a Snapshot in memory and asserts the Findings, with no source and no disk.

**Regression fixtures — the ground truth.** Two paired snapshots are committed:

- `tests/fixtures/snapshots/clean-phase2.json` — a real capture from
  `clean-baseline`, all four collectors, producing **zero** findings. This is the
  false-positive guard: the 90-thread, sysfs-built-in, and `[bpf]` classes must
  all stay silent.
- `tests/fixtures/snapshots/infected-diamorphine.json` — a real capture taken
  with Diamorphine loaded and a PID hidden, per the runbook. Tests assert the
  `hidden_process` finding names the hidden PID and the module findings name or
  count Diamorphine.

Both are pulled from the VM and committed from a reverted clean tree; neither is
pushed from an infected snapshot (`docs/step0-phase2/README.md`, [[kdetect-lab-env]]).
They contain command lines and hostnames — reviewed before commit, per L13.

Differ cases, drawn from `docs/step0-phase2/`:

- 90 unlisted sweep task-ids whose `tgid` is listed → **zero** hidden_process
  findings (FP #1)
- a sweep task-id whose `tgid` is in neither procfs pass, `status_readable` →
  one hidden_process finding, subject the tgid
- a pid absent from pass A only → no finding (timing)
- a `/sys/module` entry without initstate → excluded from `listed` (FP #2)
- a kallsyms `[bpf]` tag → never a module (FP #3)
- taint bits clear, 0 markers → no module_taint_mismatch
- taint bit 12 set, 0 markers → one module_taint_mismatch
- `load_module_regions` == listed → no region finding; > listed → one
- ftrace name absent from listing → one ftrace_orphan_module; corroborated by
  taint and region → confidence HIGH
- a channel recorded `null` (unreadable) → skipped, not treated as agreement

---

## 10. Acceptance criteria

```
1.  kdetect capture runs four collectors: procfs.processes x2 (passes A/B),
    syscall_sweep.processes, procfs.modules, kernel.module_evidence
2.  A clean capture on clean-baseline produces ZERO findings via analyze
3.  analyze on infected-diamorphine.json reports hidden_process naming the
    hidden PID, and at least one module finding for Diamorphine
4.  analyze exits 3 when any finding fires, 0 when none do
5.  analyze --json emits Finding.to_dict() list; summary suppressed
6.  The differ is pure: diff_processes/diff_modules take a Snapshot, return
    [Finding], touch no disk (a unit test builds the Snapshot in memory)
7.  SignalSource and ModuleSource each have a live and a fixture implementation;
    no if-testing branch anywhere (P3)
8.  Differ tier passes ON WINDOWS with the VM powered off
9.  Integration tier (live sources) passes on the VM
10. clean-phase2.json and infected-diamorphine.json committed; the clean one is
    a standing zero-findings regression guard
11. docs/detection-methods.md gains one page per channel with its clean baseline
    and its Diamorphine result, cited to docs/step0-phase2/
12. docs/limitations.md gains L15 (vmallocinfo hash-obfuscation) and any new
    limitation the infected run surfaces
```

Criterion 2 is the one that matters most: a detector that fires on a clean
machine is worse than none. The 90-thread false positive is designed out, and
the clean fixture proves it stays out under refactoring.

---

## 11. Decisions and rationale

| Decision | Alternative rejected | Reason |
|---|---|---|
| Sweep records `Tgid` per task | differ folds via procfs `/task` lists | keeps the sweep independent of the readdir channel; a rootkit hiding threads from readdir cannot blind the fold |
| procfs run twice (A/B sandwich) | single procfs pass vs sweep | one pass cannot tell a hidden process from a mid-capture race; the clean run showed churn produces exactly that disagreement |
| Differ does the folding | sweep collector labels threads | P4 — the collector records evidence; folding is a conclusion and must be auditable |
| Findings never in the snapshot | capture writes findings | P1 — a snapshot must be re-analysable under improved rules and its conclusions checkable against its evidence |
| Exit 3 on any finding | exit 3 only above a confidence threshold | a blunt scriptable contract; confidence lives in the output, not the exit code, so automation never drops a low-confidence hit |
| Three independent module channels stored raw | compare the three module *lists* | the three lists share one source; a `list_del` hides from all at once, so only independent channels detect it |
| Corroboration count = confidence | weighted per-channel scoring | phase 2 has no data to justify weights; count is honest and explicable. Weighting is a phase 3 concern if it earns its place |
| New `SignalSource` for the sweep | overload `ProcSource` | a `kill(id,0)` sweep is not a `/proc` read; a separate tiny interface keeps each source honest and each fixture simple |

---

## 12. Deferred

Not in phase 2, by intent: baselines and the baseline store, kallsyms integrity
and hashing (phase 3 — and blocked on address visibility, L4/L15), the YAML rule
engine and scoring beyond corroboration count, network sockets, reporting and
IOCs, eBPF and memory forensics, correlation across views (proc ↔ socket ↔
module), and any second rootkit. Phase 2 detects two hiding techniques from one
rootkit and proves the cross-view engine on real ground truth. Everything else is
additive on top of Findings.

---

## 13. Limitations entering phase 2

Recorded here and mirrored in `docs/limitations.md`.

**L15 — vmallocinfo addresses are hash-obfuscated** (§3, above). The region
channel counts; it cannot name or correlate by address.

**Prospective, to confirm or refute in the infected run:**

- Whether Diamorphine's module retains ftrace records after unlinking (it must
  have traceable functions for the ftrace_orphan channel to fire).
- Whether its `load_module` region survives on the `6.1.0-52` kernel, or whether
  module memory is freed/remapped in a way that drops it from vmallocinfo.
- Whether hiding a PID with signal 31 also hides `/proc/<pid>/status` on this
  Diamorphine build; the direct-access channel and the sweep fold both assume it
  does not.

Any of these that come back negative narrows a channel and becomes a numbered
limitation, which is the point of running real ground truth rather than trusting
the design.
