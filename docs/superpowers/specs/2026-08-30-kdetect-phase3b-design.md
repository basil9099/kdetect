# kdetect Phase 3b — Per-Suspect Scoring & Cross-Pass Composition Design

**Date:** 2026-08-30
**Status:** Approved, ready for implementation planning
**Scope:** Phase 3b of the phase-3 decomposition. Restructure the analysis layer
from independent per-channel differs into a two-stage **detect → score**
pipeline, so corroboration is counted per suspect and composes across passes.
No new collectors, no new detection surfaces.

---

## 1. Context

Phase 2 detected hiding by cross-view comparison and reported one `Finding` per
channel, each with a confidence derived from a **global** corroboration count.
Phase 3a added the hook-surface channels and a signed baseline the same way.
Both worked, but the confidence model has two honest defects the ground-truth
runs exposed:

- **Global, not per-suspect.** `diff_modules` computes one corroboration count
  (taint + region + ftrace) and stamps it on every module finding. Two unrelated
  anomalies would inflate each other's confidence.
- **No cross-pass composition.** A hidden module caught by the phase-2 module
  channels *and* the phase-3a hook channel produced separate findings at separate
  confidences — the live kdetect_hooktest run reported a LOW `unexpected_hook`
  beside a MEDIUM `module_taint_mismatch` and a MEDIUM `unexplained_module_region`
  for one and the same hidden module, when the honest verdict is a single HIGH.

Phase 3b fixes both. The phase-1 decomposition named four things for this work —
a YAML rule engine, weighted scoring, per-module corroboration, and the deferred
cross-pass composition. Two are **deliberately dropped** (§10, §11): the YAML
rule engine (a large abstraction whose value the phase-2 decision table already
made conditional on "if it earns its place" — it does not, for ~5 finding kinds
over readable, tested code) and weighted scoring (no data justifies per-channel
weights; corroboration *count* stays the model). Phase 3b delivers the two that
earn their place: **per-suspect corroboration** and **cross-pass composition**.

### 1.1 What phase 3b is not

No new collector, source, parser, or detection surface. The snapshots, fixtures,
and the facts kdetect observes are unchanged; only the analysis layer that turns
them into `Finding`s is restructured. This is a refactor with a behavioural
improvement, validated against the existing committed ground-truth fixtures.

---

## 2. Principles

Phase 1's P1–P3, phase 2's P4–P5, and phase 3a's P6–P7 all still hold. Phase 3b
sharpens P4 into the layer's structure.

**P8 — Detectors observe channels; the scorer draws every conclusion.** A
detector emits `Signal`s — "channel C indicates suspect S is anomalous, and
channel D dissents" — and makes no confidence judgment and no composition
decision. All of that lives in one pure `score()` function, so every confidence
value and every merge is auditable in a single place against the raw signals.
This is P4 (collectors record, differ concludes) applied one level up: the
detection functions themselves now only record.

**P9 — Confidence is a count of distinct corroborating channels, per suspect.**
No channel is weighted above another (phase 2's decision, unchanged — §10). What
phase 3b changes is that the count is scoped to one suspect and spans every
detection pass, rather than being global to a view. A conclusion a reader cannot
reach by counting the cited channels is not one kdetect will draw.

---

## 3. Architecture & data flow

```
Snapshot (+ optional baseline)
   │
   ├─ detectors (pure, analysis/signals.py) ──────> list[Signal]
   │     signals_processes(snapshot)
   │     signals_modules(snapshot)
   │     signals_hooks(snapshot)
   │     signals_baseline(snapshot, baseline)     # only when baseline is not None
   │
   └─ score(signals) (pure, analysis/scoring.py) ─> list[Finding]
         group by suspect → attribute anonymous → count channels → compose
```

**Files:**

- **Create** `src/kdetect/analysis/signals.py` — the detectors, refactored from
  `crossview.py`. Each returns `list[Signal]`; none constructs a `Finding` or a
  `Confidence`.
- **Create** `src/kdetect/analysis/scoring.py` — `score(signals) -> list[Finding]`
  and the top-level `analyze(snapshot, baseline=None) -> list[Finding]`
  (`= score(all detectors' signals)`).
- **Modify** `src/kdetect/analysis/models.py` — add `Suspect`, `Signal`, and the
  new/retired `FindingKind`s (§6).
- **Delete** `src/kdetect/analysis/crossview.py` and
  `src/kdetect/analysis/baseline_diff.py` — their logic moves into `signals.py`
  as `signals_modules`/`signals_hooks`/`signals_processes`/`signals_baseline`.
- **Modify** `src/kdetect/cli.py` — `cmd_analyze` calls `analyze()` instead of
  `diff_all()`; output section unchanged in shape.

The two stages are independently testable: detectors against a snapshot yield a
signal list with no scoring to reason about; the scorer against a hand-built
signal list yields findings with no I/O or snapshot parsing involved.

---

## 4. Signal & Suspect model

```python
@dataclass(frozen=True)
class Suspect:
    kind: str            # "module" | "process"
    name: str | None     # module name, or str(pid); None = anonymous
                         # (a hidden module whose name no channel can supply)

@dataclass(frozen=True)
class Signal:
    channel: str         # see the channel vocabulary below
    suspect: Suspect
    dissent: str         # the channel that fails to corroborate
    evidence: dict       # channel-specific facts (P5)
```

**Channel vocabulary** (closed set, one string per detection surface):
`taint`, `vmalloc_region`, `ftrace_orphan`, `unexpected_hook`, `syscall_kill`,
`direct_status`, `baseline_drift`.

**Detector outputs:**

| Detector | Emits | Suspect | Named? |
|---|---|---|---|
| `signals_modules` | `taint` when bits 12/13 set and no listed module carries the `(O)/(E)` marker | `("module", None)` | anonymous |
| | `vmalloc_region` when `load_module_regions > len(listed)` | `("module", None)` | anonymous |
| | `ftrace_orphan` per module in `ftrace_modules − listed` | `("module", <name>)` | named |
| `signals_hooks` | `unexpected_hook` per hook whose `owner_module` is set and not listed | `("module", <owner_module>)` | named |
| `signals_baseline` | `baseline_drift` per module in `current − baseline` (module view) | `("module", <name>)` | named |
| `signals_processes` | `syscall_kill` per hidden tgid; plus `direct_status` when `status_readable` | `("process", str(pid))` | named |

`signals_baseline` runs only when a baseline is supplied. Removed-since-baseline
modules stay out of scoring (informational only, as in 3a).

The `name=None` marker is the whole reason anonymous signals are a distinct
thing: it lets the scorer *attribute* them (§5) rather than silently dropping or
mis-naming them.

---

## 5. Scoring & attribution

`score(signals) -> list[Finding]` — pure, deterministic, sorted output.

1. **Partition** into named (`suspect.name` set) and anonymous (`name is None`).
2. **Group named signals by suspect.**
3. **Attribute anonymous module signals** (`taint`, `vmalloc_region`):
   - `hidden_named` = the set of module names carrying at least one *hiding*
     channel (`ftrace_orphan` or `unexpected_hook`). A module whose only channel
     is `baseline_drift` is **not** hidden — it may be a benign new module.
   - **Exactly one** `hidden_named` module → fold all anonymous module signals
     into that suspect's group. (The ground-truth case: one hidden module, so the
     anonymous taint/region must be about it.)
   - **Zero or ≥2** `hidden_named` modules → the anonymous signals cannot be
     pinned to a name (L15 makes per-module attribution impossible with more than
     one), so they form a single `SUSPECTED_HIDDEN_MODULE` finding of their own.
4. **Confidence = `_confidence(number of distinct channels in the group)`** — the
   phase-2 mapping unchanged: 1 → LOW, 2 → MEDIUM, ≥3 → HIGH (P9).
5. **Emit one `Finding` per group**: `channels_agree` = sorted distinct channels,
   `channels_dissent` = sorted union of the group's `dissent` values, `evidence`
   = a dict keyed by channel name holding each signal's evidence.

**Kind selection per group** (§6). A *hiding channel* is any channel that
indicates concealment — every channel except `baseline_drift` (which alone means
only "new since the baseline," not "hidden"). Then: a named module group with any
hiding channel → `HIDDEN_MODULE`; a named module group whose only channel is
`baseline_drift` → `BASELINE_DRIFT`; a process group → `HIDDEN_PROCESS`; the
anonymous group → `SUSPECTED_HIDDEN_MODULE`. (A named module group never contains
only `taint`/`vmalloc_region`, because those fold in only when the group already
carries a named hiding channel.)

**Worked examples against the committed fixtures:**

- `infected-hooktest.json`: `unexpected_hook` (named `kdetect_hooktest`) + `taint`
  + `vmalloc_region` (folded, one hidden module) → 3 distinct channels →
  **one `HIDDEN_MODULE` at HIGH**. (Was: LOW hook + MEDIUM taint + MEDIUM region.)
- `infected-diamorphine.json`: `ftrace_orphan` + `taint` + `vmalloc_region` → 3 →
  **one `HIDDEN_MODULE` at HIGH** naming `diamorphine`. (Same verdict as phase 2,
  now a single composed finding.)
- `clean-phase2.json` / `clean-phase3a.json`: no signals → **zero findings**.

---

## 6. Finding model & kinds

`Finding` keeps its fields — `kind, subject, confidence, channels_agree,
channels_dissent, evidence, summary` — so the serialization and CLI rendering are
unchanged in shape. What changes is that one suspect yields one finding, and
`evidence` is keyed by channel.

`FindingKind` after phase 3b:

| Kind | Meaning | Status |
|---|---|---|
| `HIDDEN_MODULE` | a named module with ≥1 hiding channel | **new** |
| `SUSPECTED_HIDDEN_MODULE` | anonymous hiding signals, unattributable | **new** |
| `HIDDEN_PROCESS` | a pid seen by the sweep, absent from every readdir pass | retained |
| `BASELINE_DRIFT` | a new-but-listed module (only channel is `baseline_drift`) | retained |
| `MODULE_TAINT_MISMATCH` | — | **retired** → `taint` channel |
| `UNEXPLAINED_MODULE_REGION` | — | **retired** → `vmalloc_region` channel |
| `FTRACE_ORPHAN_MODULE` | — | **retired** → `ftrace_orphan` channel |
| `UNEXPECTED_HOOK` | — | **retired** → `unexpected_hook` channel |

`subject` becomes the suspect string: `"module diamorphine"`, `"pid 1234"`, or
`"unattributed hidden module"`. The retired kinds live on as channel names inside
`channels_agree`/`evidence`, so no observed fact is lost — a HIDDEN_MODULE finding
still tells the reader the taint bits, the region count, the ftrace tag, and the
hooked function, each under its channel key.

---

## 7. Process view and the HIGH `hidden_process` deferral

`signals_processes` emits, per hidden tgid (seen by the sweep, in no readdir
pass): a `syscall_kill` signal, and — when `SweepEntity.status_readable` — a
`direct_status` signal, both keyed `("process", str(pid))`. Two distinct reads
(a `kill(0)` signal delivery and an `open`/`read` of `/proc/<pid>/status`), both
bypassing readdir, so the scorer counts 2 channels → **MEDIUM**, preserving
phase 2's behaviour without a special case. A pid whose status could not be read
yields only `syscall_kill` → LOW, which is the honest weaker case.

**HIGH `hidden_process` is explicitly out of scope.** The phase-2 parked note
already recorded that it needs an identity channel the pure differ lacks. A third
independent channel — a socket owned by an invisible pid, or a thread appearing
under a parent's `/proc/<ppid>/task/` — is not collected until phase 4. Phase 3b
therefore caps a hidden process at MEDIUM and does not invent a third channel to
reach HIGH. When phase 4 adds sockets/correlation, that channel drops into the
same scorer and HIGH follows from the count with no further change.

---

## 8. CLI

`cmd_analyze` calls `analyze(snapshot, baseline)` in place of `diff_all`. The
`--baseline`/`--verify-key` handling, the baseline verification-before-analysis
ordering (P7), the findings section, `--json`, and exit code 3 are all unchanged.
Because one suspect now yields one finding, an infected capture prints fewer,
stronger findings — e.g. one HIGH `hidden_module` line for kdetect_hooktest with
`seen by: unexpected_hook, taint, vmalloc_region` rather than three separate
lines. No new flags, no output-shape change.

---

## 9. Testing & migration

The whole analysis suite runs on Windows with the VM off (V1) — pure functions,
committed fixtures.

- **New** `tests/unit/test_signals.py` — each detector against a fixture/hand-built
  snapshot yields the expected `Signal` list (channel, suspect, dissent), with no
  scoring involved.
- **New** `tests/unit/test_scoring.py` — `score()` against hand-built signal
  lists: per-suspect channel counting; the one-hidden-module fold; the
  zero-and-≥2 `SUSPECTED_HIDDEN_MODULE` fallback; a benign-new-module `baseline_drift`
  staying LOW and un-hidden; the two-signal process → MEDIUM path.
- **Rewrite** `tests/unit/test_diff_modules.py`, `test_diff_hooks.py`,
  `test_diff_processes.py`, `test_baseline_diff.py` → assertions move from the
  retired per-channel kinds to the composed kinds (or fold into the two new files).
- **Update** `tests/unit/test_ground_truth.py` — the anchor of the migration. Its
  assertions change from "three findings of kinds X/Y/Z" to "one `HIDDEN_MODULE`
  at HIGH naming diamorphine / kdetect_hooktest, with channels {…}", and the clean
  fixtures still yield zero. The fixture JSON does **not** change — same evidence,
  better verdict.
- **Update** `tests/unit/test_finding_model.py` and any `FindingKind` references.

### 9.1 Acceptance criteria

1. `analyze(clean-phase2)` and `analyze(clean-phase3a)` → **zero findings**
   (the false-positive guard, unchanged).
2. `analyze(infected-diamorphine)` → exactly one `HIDDEN_MODULE` at HIGH naming
   `diamorphine`, its `channels_agree` = {`taint`, `vmalloc_region`,
   `ftrace_orphan`}; no `hidden_process`.
3. `analyze(infected-hooktest)` → exactly one `HIDDEN_MODULE` at HIGH naming
   `kdetect_hooktest`, its `channels_agree` ⊇ {`unexpected_hook`, `taint`,
   `vmalloc_region`}; no `hidden_process`.
4. `score()` on two distinct named hidden modules keeps their confidences
   independent and emits a `SUSPECTED_HIDDEN_MODULE` for the anonymous signals
   rather than mis-attributing them.
5. A hidden process yields one `HIDDEN_PROCESS` at MEDIUM (two channels); no
   finding reaches HIGH on the process view.
6. The unit suite is green on Windows with the VM off, and the 3.11 guard
   (`test_python311_compat.py`) still passes.

Criterion 1 remains paramount: the refactor must not make a clean machine fire.

---

## 10. Decisions and rationale

| Decision | Alternative rejected | Reason |
|---|---|---|
| Scoring only; no YAML rule engine | build the rule engine (brief deliverable 7) | phase-2 table made weighting conditional on "earns its place"; a rule DSL is large machinery over readable, tested code for ~5 kinds — YAGNI |
| Corroboration **count**, per suspect | weighted per-channel scoring | still no data to justify weights; count is honest and explicable; the fix that mattered was scoping the count to a suspect, not weighting it |
| Detect → score split (Signal / scorer) | keep `diff_*` and merge findings after | composing/attributing from raw signals is cleaner than un-forming then re-forming findings; puts all conclusions in one auditable unit (P8) |
| Merge to one finding per suspect | keep per-channel findings, share confidence | matches the 3a "one HIGH finding" intent; a single verdict per suspect is what a reader wants |
| Anonymous signals folded only when exactly one hidden module | always attribute to the strongest suspect | with ≥2 hidden modules the taint/region cannot be split (L15); inventing an attribution would be dishonest — `SUSPECTED_HIDDEN_MODULE` states the limit |
| `hidden_process` capped at MEDIUM | synthesize a third channel for HIGH | no third channel exists until phase-4 sockets/correlation; the count model reaches HIGH for free once it does |
| Retire per-channel module kinds into channels | keep them as top-level kinds | one suspect, one finding; the facts survive as channel-keyed evidence |

---

## 11. Deferred

Not in phase 3b, by intent: the **YAML rule engine** and **weighted scoring**
(dropped above — revisit only if a future phase accumulates enough finding kinds
or calibration data to justify them); a **HIGH `hidden_process`** path (needs the
phase-4 socket/`task`-list channel); network sockets and correlation across views
(proc ↔ socket ↔ module); IOCs and shareable reporting; eBPF and out-of-band
memory forensics; off-host baseline storage. Phase 3b makes the existing
detections score honestly per suspect; everything else is additive on the
`Signal`/`score` seam.

---

## 12. Limitations entering phase 3b

Recorded here and to be mirrored in `docs/limitations.md`.

**L21 — Anonymous hidden-module signals cannot be attributed when more than one
module is hidden.** The taint word is a single global bit set, and vmalloc region
addresses are hash-obfuscated (L15), so `taint` and `vmalloc_region` indicate
*that* a module is hidden, never *which*. The scorer folds them into a named
suspect only when exactly one module is hidden; with two or more hidden modules
they collapse into a single `SUSPECTED_HIDDEN_MODULE` finding that counts the
anonymous channels but names no module. Naming multiple hidden modules requires a
channel that survives hiding *and* carries identity (ftrace tags, kallsyms) for
each — the named channels already do this where they fire; the anonymous ones
cannot, by construction.
