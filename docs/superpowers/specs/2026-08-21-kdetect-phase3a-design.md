# kdetect Phase 3a — Baseline Store & Hook-Surface Integrity Design

**Date:** 2026-08-21
**Status:** Approved, ready for implementation planning
**Scope:** Phase 3a of the phase-3 decomposition. A signed baseline store, two
hook-surface integrity collectors, a pure baseline-diff pass, and an
intra-snapshot orphan-hook check. First phase that compares against a
known-good record, and first that inspects the kernel's own hook surfaces.

---

## 1. Context

Phase 1 built a snapshot that records evidence and draws no conclusions. Phase 2
added the first conclusions, via **cross-view comparison**: ask one question
through channels of differing trustworthiness within a single snapshot, and
treat disagreement as signal. It caught Diamorphine's hidden module three
independent ways on the live VM.

The phase-1 decomposition table put four things in phase 3: a baseline store,
kallsyms/syscall integrity, a YAML rule engine, and scoring. That is close to
four independent subsystems in one row. This spec covers the first two —
persistence and integrity — as **phase 3a**. The rule engine and scoring beyond
corroboration count become **phase 3b**, with their own spec; they are a
refactor of logic that already works, whereas integrity detection is genuinely
new observational ground.

Phase 3a asks a new question and adds a new axis:

- **What is hooked in the kernel?** — asked through ftrace's registered ops
  (`/sys/kernel/tracing/enabled_functions`), the kprobe list
  (`/sys/kernel/debug/kprobes/list`), and the kallsyms symbol/module set. These
  are the surfaces a modern (6.x) LKM rootkit actually touches.
- **What changed since the system was known clean?** — asked by diffing a fresh
  capture against a **signed baseline**, across every view.

Phase 2 left the ground prepared: `TrustLevel.MEDIUM` is in use, the exit-3
"analysis produced findings" contract is blunt and scriptable, the
`entity_ids`/`entities` split and the string-id collector pattern
(`procfs.modules`) already exist, and `Observation.extra` already carries
channel detail that is not per-entity.

### 1.1 Why hook surfaces, not the syscall table

`docs/detection-methods.md` §10 names "syscall table integrity" as the phase-3
target. Two observations from phase 2 redirect it:

- **L16** — Diamorphine's syscall-table hooking never engaged on kernel
  `6.1.0-52`; sending signal 31 delivered `SIGSYS` and killed the target. Classic
  `sys_call_table` overwriting is largely a pre-5.7 technique. There is no working
  syscall-table-modifying ground truth on this kernel.
- Modern LKM rootkits hook via **ftrace** or **kprobes** instead, and both leave
  records in world-/root-readable pseudo-files that need **no kernel memory
  reads** — so they are not blocked by **L4** (address visibility) or **L15**
  (vmallocinfo hashing).

Phase 3a therefore targets the hook *mechanisms in current use*, and gets its
ground truth from a benign kdetect-authored LKM (§7) rather than from a rootkit
whose hooks do not fire.

### 1.2 Evidence base

As in every prior phase, the schema is derived from hand-exploration recorded
under `docs/step0-phase3/`, captured on the rebuilt lab VM, kernel
`6.1.0-52-amd64`, as root — both clean and with the test LKM loaded. **No new
schema field is finalized until it traces to a file there.** The field shapes in
§4 are the hypothesis step 0 confirms or corrects; the two prior phases each had
a design assumption overturned by step 0 (the 90-thread thread/process ratio,
the vmallocinfo pointer hashing), and this gate is why.

---

## 2. Principles

Phase 1's P1–P3 and phase 2's P4–P5 all still hold. Phase 3a adds two.

**P6 — A baseline is a snapshot, not a new kind of thing.** The known-good record
is an ordinary phase-1/phase-2 snapshot, captured the same way and re-analysable
under improved rules. The only thing added is a detached signature over its
bytes. This keeps one data model, lets any view be diffed against the baseline,
and means a baseline can itself be re-examined by a future phase's collectors.

**P7 — Verification precedes trust.** A baseline's signature is checked *before*
its JSON is parsed and used. A record that fails verification is refused, not
downgraded, because a silently-accepted tampered baseline certifies exactly the
compromise it was meant to catch (A3). What on-host verification can and cannot
buy is bounded honestly in §6 and L18.

---

## 3. Architecture & data flow

```
capture ──> Snapshot JSON ──┬─> crossview.diff_all()        (intra-snapshot; phase 2)
                            │        + orphan-hook check     (intra-snapshot; NEW)
                            └─> baseline_diff.diff()         (current vs known-good; NEW)
                                       ▲
                    data/baselines/<name>.json  +  <name>.json.sig
                              (ed25519-signed; verify-on-load, P7)
```

Three moving parts are new, each mirroring a pattern phase 2 established:

1. **Collectors** — `kernel.hooks` reads the hook surfaces and emits one
   `kernel_hooks` observation, joining the existing five in the `capture`
   sandwich. Source-as-argument (P3), `None`-when-unreadable channels (like
   `ModuleSource`).
2. **Baseline store** — `baseline/store.py` writes a signed baseline from a
   snapshot and loads one with verification (P6, P7).
3. **Analysis** — `analysis/baseline_diff.py`, a pure `(current, baseline) ->
   [Finding]` function, structurally identical to `crossview.py`. The
   orphan-hook check is a small addition on the intra-snapshot side and needs no
   baseline.

All findings flow through the existing `Finding` model, the existing `analyze`
findings section, and the existing exit-3 contract. Nothing about phase 2's
output shape changes.

### 3.1 CLI surface

- `kdetect baseline <snapshot> --out data/baselines/<name> --sign-key <path>`
  Signs a captured snapshot as a baseline. Writes `<name>.json` and
  `<name>.json.sig`. The private key is a file argument, never repo-resident.
- `kdetect analyze <snapshot> [--baseline <name>] [--verify-key <path>]`
  Without `--baseline`, behaves exactly as today, *plus* the intra-snapshot
  orphan-hook check. With `--baseline`, additionally verifies the baseline
  (refusing on failure, P7) and runs `baseline_diff`.

Exit codes are unchanged: `0` clean, `1` error (now including
`BaselineTampered`), `2` usage, `3` at least one finding.

---

## 4. The kernel_hooks view

### 4.1 Source

New interface `KernelHookSource` (mirrors `ModuleSource`: a channel that cannot
be read returns `None`, and the collector records its absence rather than
treating it as agreement).

```
read_enabled_functions() -> str | None   # /sys/kernel/tracing/enabled_functions
read_kprobes()           -> str | None   # /sys/kernel/debug/kprobes/list
read_kallsyms_index()    -> str | None   # /proc/kallsyms, reduced (see below)
```

`read_kallsyms_index` returns kallsyms reduced to **(symbol name, type, owning
module)** with addresses dropped on the read path. This is deliberate: under L4
the addresses read as zero without `CAP_SYSLOG`, but the symbol *names* and the
`[module]` attribution are readable regardless. Storing zeroed addresses would
invite a future reader to diff noise.

Its role is **attribution, not a view of its own.** The kallsyms module set is
what resolves a callback address to an `owner_module` (§4.2), and the set of
module namespaces present in kallsyms is folded into the *module-view* drift and
corroboration — a rootkit whose module is unlinked from `/proc/modules` but still
owns kallsyms symbols is exactly the kind of disagreement that belongs alongside
phase 2's module channels. It is carried in `Observation.extra`, not as
`entity_ids`, precisely because it is an attribution input rather than an entity
set the differ walks id-by-id.

`Live*` reads the real pseudo-files; `Fixture*` replays captured text, a missing
file replaying "unreadable" (`None`), exactly as `FixtureModuleSource` does.

### 4.2 Collector and entity

`kernel.hooks` → view `kernel_hooks`, trust **MEDIUM** (a hook surface is harder
to forge than the `/proc/modules` listing a rootkit unlinks from, and far easier
than the out-of-band memory analysis of phase 5). String-keyed, like
`procfs.modules`: the entity id is the hooked function's name.

`HookEntity` (hypothesis, pending step-0 confirmation of the real
`enabled_functions` format):

```json
{
  "function": "ip_rcv",
  "hook_type": "ftrace",
  "callback": "e1000_hook+0x0/0x30",
  "owner_module": "e1000",
  "attributable": true
}
```

- `hook_type` — `"ftrace"` or `"kprobe"`.
- `callback` — the dispatch target as the surface names it (symbol+offset, or an
  address if that is all it gives).
- `owner_module` — the module the **callback** attributes to, or `null`.
- `attributable` — `false` when the callback resolves into no currently-listed
  module. This is the orphan-hook signal (§5.2), computable intra-snapshot.

`kallsyms_index` (the name/module set) and any whole-surface counts that are not
per-entity go in `Observation.extra`, as phase 2 put the taint word and region
count there.

**Open until step 0.** Whether `enabled_functions` names the callback's owning
module inline or only an address decides how `owner_module`/`attributable` are
computed — inline is a parse; address-only requires correlating against the
`kallsyms_index` module ranges. §4.1 collects both so either path is possible;
the field set above is finalized against the recorded format, not before.

---

## 5. Findings

Two new `FindingKind`s, in phase 2's style of specific, mechanism-named kinds.

### 5.1 BASELINE_DRIFT

An entity present in the current capture but absent from the signed baseline.
One generic kind, because drift is uniform across views; `evidence` carries the
`view` (`modules` / `kernel_hooks`) and the subject. Produced by
`baseline_diff.diff(current, baseline)`, comparing `entity_ids` per view (the
differ compares ids, never entity detail — P2). Kallsyms drift is not a view of
its own: a module namespace newly present in kallsyms is folded into
`modules`-view drift (§4.1), where it corroborates rather than duplicates.

Direction matters: **additions** since baseline are the signal. **Removals** (a
module unloaded, a hook cleared since the baseline was taken) are reported at
LOW as informational — a rootkit adds capability far more often than it removes
it, and benign config drift removes things routinely.

### 5.2 UNEXPECTED_HOOK

A registered ftrace op or kprobe flagged as suspect. Two independent reasons,
either sufficient to raise it, both together stronger:

- **Orphan (intra-snapshot, no baseline):** a `HookEntity` with `attributable ==
  false` — the callback resolves into no listed module. Runs on every `analyze`.
- **New-vs-baseline:** the hooked function carries a hook absent from the
  baseline's `kernel_hooks` view.

### 5.3 Confidence — corroboration count, unchanged philosophy

Weighted per-channel scoring stays deferred to **phase 3b**, exactly as the
phase-2 decision table promised ("Weighting is a phase 3 concern if it earns its
place"). Phase 3a keeps the honest, explicable **count of agreeing channels** —
what changes is that baseline-diff and crossview now compose into that count.

| Signal | Independent channels | Confidence |
|---|---|---|
| Hook orphan only, or drift only | 1 | LOW |
| Orphan hook **and** new-vs-baseline | 2 | MEDIUM |
| New-vs-baseline module **and** a phase-2 unexplained region / ftrace-orphan | 2–3 | MEDIUM–HIGH |
| Orphan hook whose owning module is itself an unexplained region | 3 | HIGH |

The baseline answers "this was not here when clean"; crossview answers "and it
is hiding". Neither alone is HIGH; corroborated they are, and each Finding cites
the exact channels and field values it drew from (P5).

---

## 6. Baseline store & signing

### 6.1 Layout

A baseline is an ordinary snapshot (P6) plus a **detached** signature:

```
data/baselines/clean-6.1.0-52.json       # the snapshot, byte-canonical (to_json)
data/baselines/clean-6.1.0-52.json.sig   # ed25519 signature over the .json bytes
```

Detached rather than embedded so the signed bytes are exactly the snapshot as
written — no signing a file that must then contain its own signature. The
snapshot already serialises deterministically, so the signed bytes are stable.
`.gitignore` already excludes `data/baselines/*.json`; the `.sig` gets the same
exclusion (a baseline is host-specific and sensitive, L13).

### 6.2 Module

`baseline/store.py`, small and mostly pure:

- `write_baseline(snapshot, out_path, sign_key)` — write `<name>.json` via the
  existing `to_json`, then write the detached `<name>.json.sig`.
- `load_baseline(path, verify_key) -> Snapshot` — read the bytes, **verify the
  signature before parsing** (P7), raise `BaselineTampered` on mismatch,
  otherwise parse via the existing `Snapshot.from_dict`.

Keys are file arguments loaded outside kdetect's data path and never committed
(`.gitignore` already blocks `id_*`, `*_ed25519`, `*.pem`).

### 6.3 Signing scheme — ed25519 (asymmetric)

Sign with a private key, verify with a public key, via the `cryptography`
library. This makes the threat-model claim actually true: kdetect on the
inspected host carries only the **public** key, so a root attacker can *verify*
baselines but **cannot forge** one to match their compromise — the private key
lives off-host, which the VM snapshot discipline already models.

This adds the project's **first runtime dependency** (`dependencies = []` today).
`cryptography` is cross-platform, so V1 ("the unit suite runs without Linux")
still holds. The symmetric HMAC alternative was rejected: its verify key equals
its sign key, so any on-host attacker who can run `analyze` can also forge a
baseline — collapsing back to the corruption-detection-only guarantee of the
plain-hash option, under a different name.

### 6.4 What on-host signing does and does not buy (L18)

Recorded as a new limitation. On-host verification defeats an attacker who lacks
the **signing** key: with the private key kept off-host, a baseline cannot be
forged on the inspected machine, only verified. It does **not** defeat an
attacker who obtains the signing key, and if the private key is left on the
inspected host the guarantee degrades to detecting accidental corruption and
careless edits (A2: a root attacker can edit kdetect and its keys alike). The
honest strengthening is off-host key storage — the same direction A3 already
points at, and a phase-5 concern. Phase 3a delivers the mechanism and states its
boundary; it does not claim to have closed A3.

---

## 7. Ground truth — the benign test LKM

Because L16 leaves no working hook-modifying rootkit on this kernel, phase 3a
supplies its own ground truth: `kmod/kdetect_hooktest.c` (+ `Makefile`), a
benign kdetect-authored module. Source is committed (it is benign and ours);
`.ko` stays gitignored (already covered).

Two build modes so most testing stays safe and reversible:

- **visible (default)** — registers an ftrace hook on a harmless function; the
  callback tail-calls the original and does nothing else. `rmmod`-able. Exercises
  the collector and the *attributable* hook path against real ground truth.
- **hidden (compile flag)** — additionally `list_del`s itself, so the hook's
  owning module is unlisted → `attributable == false` and the HIGH-corroborated
  case (orphan hook + unexplained region). Like Diamorphine, removal needs a
  reboot, so this is a deliberate snapshot-guarded run under the existing
  discipline: push from `clean-baseline`, snapshot `infected-hooktest`, switch
  the adapter to Host-only, revert afterwards. Never push from the infected
  snapshot.

The module does nothing but hook a harmless function and, in hidden mode, hide
itself. It grants no privilege, hides no other process or file, and opens no
channel.

---

## 8. Testing

The pure tiers — parsers, the `kernel.hooks` collector against fixtures, the
differ, and the baseline store — all run on Windows with the VM off, preserving
V1. Only live capture needs the VM.

- **Collector, against fixtures.** A clean `kernel_hooks` capture and a hooked
  one (LKM visible) become fixtures under `tests/fixtures/`, replayed through
  `FixtureKernelHookSource`.
- **Orphan detection, synthetic.** A hand-doctored fixture with an unattributable
  callback unit-tests `UNEXPECTED_HOOK` independent of a live hidden run —
  mirroring how phase 2 kept process-hiding tested synthetically after L16.
- **Baseline store.** A signed baseline fixture; a **tampered** one (one flipped
  byte) asserting `load_baseline` raises `BaselineTampered`; and a clean
  baseline-diff producing **zero findings** — the regression guard, alongside the
  existing `clean-phase2.json`.
- **Live validation.** The phase-2 arc repeated: capture clean → sign a baseline
  → load `kdetect_hooktest` → capture → `analyze --baseline` catches the hook,
  corroborated as designed. Any channel weaker than designed (e.g.
  `enabled_functions` empty on a hooked kernel, or the callback module unnamed)
  becomes a numbered limitation — the L15/L16 discipline.

### 8.1 Acceptance criteria

1. `capture` emits a `kernel_hooks` observation; `analyze` reports it in the
   collectors list.
2. Clean baseline-diff produces **zero findings** (regression fixture).
3. `analyze --baseline` on a capture with the visible test LKM loaded reports the
   hook as `UNEXPECTED_HOOK` / `BASELINE_DRIFT`, corroborated per §5.3.
4. `load_baseline` refuses a tampered baseline with `BaselineTampered` and a
   non-zero exit, before any analysis runs.
5. The intra-snapshot orphan-hook check fires on the synthetic orphan fixture
   with no baseline supplied.
6. The unit suite still runs green on Windows with the VM off (V1).

Criterion 2 is, as in phase 2, the one that matters most: a detector that fires
on a clean machine is worse than none.

---

## 9. Decisions and rationale

| Decision | Alternative rejected | Reason |
|---|---|---|
| Target ftrace/kprobe hook surfaces | syscall-table hashing (§10 as written) | L16: no working table-modifying ground truth on 6.1; modern rootkits hook via ftrace/kprobes, which need no memory reads (dodges L4/L15) |
| Baseline is a signed snapshot (P6) | a new bespoke baseline format | one data model; any view diffs against it; a baseline is itself re-analysable by later phases |
| Detached `.sig`, verify before parse (P7) | embedded signature | signed bytes == snapshot bytes exactly; a tampered baseline is refused, not downgraded |
| ed25519 (asymmetric) | HMAC-SHA256 (symmetric) | asymmetric gives verify-but-not-forge on-host; HMAC's verify key == sign key, collapsing to corruption-detection only |
| Baseline-diff a separate pure pass | fold into `crossview.diff_all` | keeps two distinct axes separate — channels-disagree-within-a-snapshot vs. drift-from-known-good; phase 2 kept the differ single-purpose on purpose |
| Orphan-hook check needs no baseline | baseline-only hook detection | a hook whose callback belongs to no listed module is rootkit-specific intra-snapshot; not depending on stored state survives A1 |
| Confidence = corroboration count still | weighted scoring now | phase 3a still lacks data to justify weights; count is honest and composes baseline + crossview channels; weighting is phase 3b |
| Kallsyms stored as names/modules, no addresses | store addresses too | under L4 addresses read zero unprivileged; the name/module set is what drift needs and is readable regardless |
| Benign kdetect-authored test LKM | source a third-party ftrace rootkit | controllable, safe to commit, teaches the mechanism; no guarantee a third-party PoC engages on 6.1 any more than Diamorphine did |

---

## 10. Deferred

Not in phase 3a, by intent, and carried to **phase 3b** or later: the YAML rule
engine (extracting `crossview.py`'s hardcoded logic into `rules/*.yaml`),
weighted scoring beyond corroboration count, per-module (not global)
corroboration confidence and the richer `hidden_process` paths parked from phase
2, `/proc/kcore`-based syscall-table reading (blocked on kcore usability and
lacking ground truth, L16), network sockets and correlation across views, IOCs
and shareable reporting with redaction (L13), eBPF collectors, and out-of-band
memory forensics and off-host baseline storage (the real answer to A3, phase 5).

Phase 3a delivers a signed baseline and detection of the hook mechanisms modern
LKM rootkits actually use, validated against ground truth built for the purpose.
Everything else is additive on top of the `Finding` model and the baseline
store.

---

## 11. Limitations entering phase 3a

Recorded here and to be mirrored in `docs/limitations.md`.

**L18 — On-host baseline signing detects forgery only from an attacker without
the signing key.** ed25519 keeps the public (verify) key on the inspected host
and the private (sign) key off-host, so a baseline cannot be forged on the host,
only verified (§6.4). An attacker who obtains the signing key, or a private key
left on the inspected host, reduces the guarantee to corruption detection (A2).
The honest strengthening is off-host key storage (A3, phase 5).

**Prospective, to confirm or refute in the step-0 and infected runs:**

- Whether `/sys/kernel/tracing/enabled_functions` names the callback's owning
  module inline, or only an address requiring correlation against the kallsyms
  module ranges (decides how `attributable` is computed — §4.2).
- Whether a clean idle VM has any legitimately registered ftrace ops or kprobes,
  and if so which, so the clean baseline for `kernel_hooks` is calibrated rather
  than assumed empty.
- Whether the test LKM's ftrace hook remains visible in `enabled_functions` after
  it `list_del`s itself in hidden mode (the orphan channel depends on the hook
  record outliving the module's listing, the same way phase 2 depended on ftrace
  tags outliving `/proc/modules`).

Any that come back negative narrows a channel and becomes a numbered limitation —
the point of running real ground truth rather than trusting the design.
