# kdetect Phase 4c — Evidence Discipline in the Analysis Layer

**Date:** 2026-09-20
**Status:** Approved, ready for implementation planning
**Scope:** Analysis layer, plus the thin output path that renders its new channel
notes. Three defects in which a **conclusion is drawn at capture time** and frozen
into the snapshot as a scalar, where analysis cannot revisit it. No collector
changes, no parser changes, no schema change, no exit-code change. The parser
hardening these defects were found alongside is deferred to phase 4d (§10).

**Revision 2026-09-23:** §4's central claim was wrong and is withdrawn — see §1.2.
Per-bit taint reconciliation does not recover the NVIDIA/ZFS hosts the first draft
said it did. §4.4 (report channel saturation) is the response, and is new.

---

## 1. Context

Phase 4b was the v1.0 finish line. This phase is remedial. An adversarial probe of
the parse and analysis layers, run 2026-09-20, executed hostile input against the
real code and traced 34 findings up to `capture` and `analyze`. The outcome
distribution was the surprise:

| Outcome | Count |
|---|---|
| Silently wrong snapshot or verdict | 22 |
| Aborts the capture | 2 |
| Not reachable in practice | 10 |

The expectation going in was that missing error handling in the module, hook and
socket collectors would dominate — those three hardcode `errors=[]` and catch
nothing, unlike `procfs.py`. That gap is real but small. What dominates is
**misattribution**: code that succeeds and returns a confident wrong answer.

Within the misattribution class the findings split cleanly in two:

- **Naming attacks** — every channel that can name a module derives the name by
  scraping the last `[...]` from a line whose payload is an attacker-chosen
  56-byte field. Deferred to 4d (§10), because settling how much of that class is
  reachable requires loading a hostilely-named module on the lab VM.
- **Counting defects** — a scalar computed during capture stands in for the
  evidence it came from. That is this phase.

### 1.1 The demonstration that set the priority

Run against the real `infected-hooktest.json` capture, mutating only the
in-memory snapshot:

```
BASELINE (unmodified real capture)            HIGH   ['taint','unexpected_hook','vmalloc_region']
+ one listed module carrying a taint marker   MEDIUM ['unexpected_hook','vmalloc_region']
+ one phantom /proc/modules row               LOW    ['unexpected_hook']
```

The second line involves no attacker. Any host with a legitimately loaded
out-of-tree driver — NVIDIA, ZFS, VirtualBox, VMware — carries a taint marker on
a listed module, and that permanently silences the taint channel, including when
a rootkit is present. Both committed infected fixtures have
`listed_taint_markers=0`, which is *why* taint fires on them. It is a clean-room
artifact of a lab VM with no third-party drivers.

### 1.2 How much of that per-bit reconciliation actually recovers

An earlier draft of this spec claimed the fix in §4 restores the channel on those
hosts. **It does not, and the claim is withdrawn.** Measured against the same
capture, comparing today's logic with the §4 logic for realistic marker letters:

| Listed module carries | Today fires | §4 fires | Unexplained bits |
|---|---|---|---|
| nothing (the lab VM) | yes | yes | 12, 13 |
| `(OE)` — vboxdrv, zfs | no | **no** | — |
| `(POE)` — nvidia | no | **no** | — |
| `(O)` — out-of-tree but signed | no | yes | 13 |
| `(P)` — proprietary only | no | yes | 12, 13 |
| `(E)` — unsigned only | no | yes | 12 |

The two headline cases are **not** recovered, and the reason is
information-theoretic rather than a defect in the reconciliation. Taint is a set
of sticky booleans about the whole boot: *"at least one out-of-tree module was
loaded"* cannot distinguish one from two. Once any legitimate out-of-tree module
is listed, bits 12 and 13 are honestly explained, and no reconciliation can
recover the hidden module's contribution. L17 reached the same conclusion three
phases ago — the region-count and ftrace channels, which track currently-loaded
state rather than sticky history, are the robust ones.

What per-bit reconciliation genuinely buys is the middle rows: a **signed**
out-of-tree module carries `(O)` without `(E)`, which is normal under Secure Boot
and DKMS signing, and today that silences bit 13 completely. That is a real
class of host and a real recovery.

The rest of the value is in §4.4: making the silence **visible**. Where the
channel cannot contribute, saying so is worth more than reconciling harder.

---

## 2. Principles

All prior principles hold (P1–P11). This phase adds one, and it is a restatement
of P1 aimed at the place P1 was quietly broken.

**P12 — A count is a conclusion, so a collector must not compute one in place of
the evidence.** P1 says snapshots hold evidence and never conclusions. A scalar
derived from a set — how many modules carried a taint marker, how many vmalloc
regions matched — is a conclusion about that set, drawn at capture time, in a
layer forbidden to conclude. Once frozen it cannot be re-examined, re-weighted or
audited against a later understanding of what the data meant. Collectors record
sets; analysis reduces them.

Every defect in §§4–6 is an instance of P12 being violated, and each is fixable
because the evidence P12 says should have been carried **already is** carried
somewhere in the snapshot. That is what makes this phase analysis-only.

---

## 3. Scope boundary: why analysis-only

For each defect in scope, the evidence needed to fix it is already present in
every snapshot kdetect has ever written:

| Defect | Evidence already in the snapshot |
|---|---|
| Taint marker count (§4) | `procfs.modules` entities carry `ModuleEntity.taint`, the per-module letters |
| Phantom listing row (§5) | `kernel.module_evidence.extra.ftrace_modules`, `kernel.hooks.extra.kallsyms_modules` |
| Attribution gate (§6) | Entirely internal to `scoring.score` |

Consequences, all of which become acceptance criteria:

- **No `schema_version` bump.** Nothing is added to or removed from the snapshot.
- **Every existing snapshot stays valid**, including the committed fixtures.
- **The whole phase is testable without the VM, without root, and without
  recapture**, by mutating real captures in memory.

Where the boundary does not hold, the work is out of scope by construction.
`count_module_regions` returns an `int` and discards which lines matched, so the
substring-inflation false positive — a vmalloc caller symbol containing the
literal text `load_module` inflates the region count — genuinely cannot be fixed
in analysis. It needs the collector to carry the matched callers, so it goes to 4d
with the other capture-side work.

---

## 4. Taint: reconcile bits, do not count markers

### 4.1 The defect

`collectors/modules.py:55` reduces the listing's per-module taint letters to
`markers = sum(1 for r in listed if r.taint)`. `signals.py:42` then fires the
taint signal only when `markers == 0`. The count has no correspondence to *which*
module set *which* bit, so a single marker anywhere in the listing suppresses the
whole channel.

### 4.2 The change

Read per-module taint letters from the `procfs.modules` observation. Map each
letter to the taint bit it corresponds to. A bit set in the global taint word is
**explained** if some listed module carries the letter for that bit. Fire the
signal on the bits that remain **unexplained**, carrying them in the evidence.

Scope of the recovery is exactly the middle rows of the §1.2 table: markers that
explain *some other* bit stop silencing the bits they have nothing to do with.
A rootkit forging `(OE)` on a listed row still buys silence on bits 12 and 13,
because `(OE)` genuinely explains them — that is not a hole this phase can close,
and §4.4 is the response to it.

### 4.3 Two details the implementation must get right

**Only module-attributable bits may be reconciled.** The global taint word carries
bits no module can account for; `TAINT_USER` and `TAINT_WARN` among others are set
by events unrelated to module loading. Reconciling those would fire on any host
that has ever emitted a kernel warning.

The table must be **evidenced, not recalled**. The repository already holds the
evidence for exactly two letters — `docs/step0-phase2/clean/08-taint-accounting.txt`
records bit 12 as out-of-tree and bit 13 as unsigned, and names the `(O)` and
`(E)` markers that correspond. **The implementation carries those two and no
more.** That is not a placeholder: bits 12 and 13 are the only bits the taint
signal has ever tested, so a wider table would be unused code justified by
unevidenced belief — the exact failure the `enabled_functions` format guess taught
in phase 3a. Widening the table is a later change, gated on capturing the evidence
for the additional letters first.

**Taint bits are sticky.** Once set they are never cleared for the life of the
boot. A module loaded and then `rmmod`ed leaves its bit set with no listed module
to explain it. An unexplained bit therefore means *"an out-of-tree or unsigned
module was loaded at some point this boot"*, not *"one is loaded now"*. The
signal's summary text must say so, and it is a further argument for taint
remaining an anonymous, single-channel, LOW contribution that cannot carry a
finding alone.

This is **already recorded as L17** and must not be re-filed as a new limitation.
What L17 does not yet cover is the opposite direction this phase found — a listed
module carrying a marker silencing the channel altogether. L17 is amended rather
than duplicated; see §11.1.

---

### 4.4 Report channel saturation, so the silence is visible

A channel is **saturated** when it cannot contribute because the evidence it would
rely on is already, honestly, fully explained by legitimate listed state. Taint on
an NVIDIA host is the case: bits 12 and 13 are set and accounted for, so the
channel has nothing left to say about a hidden module. Today that is
indistinguishable in the output from a host where taint is clean, and the two mean
opposite things to an analyst.

So where the reconciliation in §4.2 finds every set bit explained, analysis
records **why** the channel did not contribute, naming the listed modules that
explain each bit. "Taint could not corroborate: bits 12 and 13 are explained by
`nvidia (POE)`" is materially different information from silence, and it tells an
operator that on this host a hidden module must be caught by the region and hook
channels alone.

**A saturation note must not be a `Finding`.** Exit code 3 means findings were
produced, and that is a scriptable contract (`README`, "Commands"). A channel
being uninformative is not a detection, and emitting it as a `Finding` would make
every NVIDIA host exit 3 forever. The note is therefore carried on a separate
path:

- a pure `channel_notes(snapshot) -> list[ChannelNote]` in the analysis layer,
  computed from the same reconciliation as §4.2;
- rendered by `analyze` beneath the observations and by `report` as a short
  "Channel coverage" section;
- absent from `Finding`, from the IOC extractor, and from the exit code.

This also generalises: `ChannelNote` is the natural home for "this channel was
unreadable", which is where phase 4d's *unparseable channel is a finding*
decision will need to record the difference between a channel that answered
"nothing" and one that could not answer at all.

---

## 5. Over-listed modules: a new signal, provisionally

### 5.1 Rationale

`signals_modules` fires `vmalloc_region` when `regions > len(listed)`. An attacker
who can unlink a row from `/proc/modules` can equally add one, and each phantom
row absorbs exactly one unaccounted region. The channel is one phantom row deep.

The mirror image of `ftrace_orphan` closes it: a module present in the LOW listing
that **no other channel corroborates** is what a phantom row looks like. Both
corroborating sets are already in `extra` and cost nothing to read.

### 5.2 The guard, and the honest evidence base

Measured against the committed captures:

| Capture | Listed | Corroborated by no other channel |
|---|---|---|
| `infected-hooktest` | 74 | 0 |
| `infected-diamorphine` | 72 | 4 — `crc16`, `crc64`, `crc64_rocksoft`, `crc_t10dif` |

Those four are legitimate CRC helper modules, and the reason they surface is that
the capture has `kallsyms_modules=0` — an entire corroborating channel was
unavailable, so absence was read as dissent. That is the failure mode
`ModuleSource`'s own docstring already forbids: *"A channel that cannot be read
returns None, and the differ skips it rather than treating absence as
agreement."*

**Guard: emit `over_listed` only when every corroborating channel is available.**
With the guard, both captures emit nothing.

"Available" means the channel's recorded availability flag is true — **not** that
its name set is non-empty. The distinction is load-bearing and the two captures
demonstrate both halves of it: `infected-hooktest` carries
`kernel.hooks.stats.kallsyms_available = True`, while `infected-diamorphine` has
no `kernel.hooks` observation at all. An implementation testing emptiness
(`if kallsyms_modules:`) would read a legitimately empty set as dissent and
reintroduce exactly the false positive the guard exists to prevent. The flags to
read are `kernel.hooks.stats.kallsyms_available` and
`kernel.module_evidence.stats.ftrace_available`, with an absent observation
counting as unavailable.

That is a calibration set of two, one of which is degenerate. So:

- the signal ships at **LOW** confidence;
- `detection-methods.md` records explicitly that its false-positive rate is
  calibrated on two captures from one host and one kernel;
- it is marked **provisional** until clean captures from more kernels exist.

A module with no traceable functions and no exported symbols is a plausible
legitimate trigger that neither capture would have revealed. Treat a report of
this signal from a real host as evidence about the signal, not only about the
host.

---

## 6. Ambiguous attribution: name the candidates, do not discard them

`scoring.score` attributes anonymous module evidence — taint, vmalloc regions — to
a hidden module only when `len(hidden_named) == 1`. With two or more it silently
parks that evidence on an unnamed placeholder.

The gate is sound in intent. Phase 3b chose it to avoid mis-attributing under
L15/L21. But it is attacker-controllable: one appended string in a channel that
names modules manufactures a second candidate, and the real rootkit drops from
HIGH to LOW while its corroborating evidence is filed under "unattributed".

The change is to make ambiguity **explicit rather than silent**. When more than
one candidate exists, the finding names all of them and states that the anonymous
evidence could not be pinned to one. The evidence stays attached to the suspects
it might belong to instead of being discarded into a placeholder.

Confidence semantics for the ambiguous case are a decision for the implementation
plan. The requirement here is that an attacker cannot make corroborating evidence
*disappear* merely by creating a second name.

---

## 7. Architecture and module layout

No new modules, no new I/O, no interface changes at the collector seam.

| File | Change |
|---|---|
| `analysis/taint.py` | **New.** The letter-to-bit table and the pure reconciliation (§4.2), so the table has one home and one test file |
| `analysis/signals.py` | Rewrite the `taint` branch of `signals_modules` (§4); add the over-listed detector (§5); add `channel_notes` (§4.4) |
| `analysis/scoring.py` | Replace the silent `len(hidden_named) == 1` gate (§6) |
| `analysis/models.py` | One new `FindingKind.OVER_LISTED_MODULE = "over_listed_module"` (§7.1); new `ChannelNote` (§4.4) |
| `reporting/report.py` | Render a "Channel coverage" section from `channel_notes` (§4.4) |
| `cli.py` | Print channel notes under `analyze`'s observation list (§4.4); **exit codes unchanged** |
| `collectors/modules.py` | **Unchanged.** `listed_taint_markers` stays in `extra` for snapshot compatibility; analysis stops reading it |

`listed_taint_markers` is deliberately left in place rather than removed. Removing
it would be a schema change, and this phase's whole claim is that it needs none.
It becomes a vestigial field that `detection-methods.md` records as superseded.

### 7.1 Why the over-listed case needs its own `FindingKind`

`scoring._classify` has no correct branch for it today, and both available
branches are wrong in opposite directions. Left out of `_HIDING`, a named module
suspect falls through to `BASELINE_DRIFT`, which asserts something the snapshot
does not support. Added to `_HIDING`, it classifies as `HIDDEN_MODULE` — the
precise inverse of the truth, since an over-listed module is one the listing
claims and no other channel corroborates, not one the listing conceals.

So: add `OVER_LISTED_MODULE`, and **do not add `over_listed` to `_HIDING`**.
Adding it there is the natural move and it is wrong. The consequence of getting
this wrong is a report telling an analyst a module is concealed when the evidence
says the opposite.

---

## 8. Testing and acceptance

The testing technique is the one that produced §1.1 and §5.2: load a committed
capture, mutate the in-memory snapshot, run `analyze`, assert on the findings. No
new fixture files, no redaction burden, and every test states its own attack in
the mutation it performs.

### 8.1 Acceptance criteria

1. `infected-hooktest.json` and `infected-diamorphine.json` produce the same
   **kind, subject, confidence, `channels_agree` and `channels_dissent`** as
   today. This phase must not change what kdetect *concludes* about the captures
   it was validated on.
   The taint signal's **evidence dict** does change, and that is intended: it
   loses `listed_taint_markers` (the vestigial count) and gains `explained_by`,
   mapping each explained bit to the listed modules accounting for it. On both
   fixtures `explained_by` is empty, so the rendered evidence gains one field and
   loses one. The `to_dict()` round-trip and the report snapshot tests must be
   updated deliberately, not silenced.
2. Adding a `(P)`-only marker to a listed module no longer degrades
   `infected-hooktest` from HIGH. Today it does; a proprietary-module marker has
   nothing to do with bits 12 and 13. This is the §1.2 middle-row recovery, as a
   test, and it is the honest version of what an earlier draft claimed.
3. Adding an `(OE)` marker **does** still silence the taint channel — asserted
   explicitly, so the limit is pinned by a test rather than assumed — **and** a
   channel note is emitted naming the module that explains bits 12 and 13.
4. A non-module taint bit (`TAINT_WARN`, `TAINT_USER`) never contributes a signal.
5. A channel note never becomes a `Finding`, never reaches the IOC extractor, and
   never changes an exit code: a clean capture whose taint is saturated still
   exits 0.
6. A phantom `/proc/modules` row is caught by the over-listed signal when all
   corroborating channels are available, and produces **nothing** when any is
   unavailable. Specifically: `infected-diamorphine`, which has no `kernel.hooks`
   observation, emits no over-listed signal for its four CRC helper modules.
7. A channel that is available but legitimately returns an **empty** name set is
   treated as available, not as dissent — the emptiness-versus-availability
   distinction in §5.2, asserted directly.
8. Appending a second module name to a naming channel does not reduce the real
   suspect's confidence or detach its evidence.
9. No fixture is modified, `schema_version` is unchanged, and every committed
   snapshot still parses.
10. The letter-to-bit table cites its source, and the reconcilable set is limited
    to the letters that source actually evidences (§4.3).

---

## 9. Decisions and rationale

**Analysis-only, even though the vmalloc substring defect is in the same family.**
Fixing that one needs the collector to carry matched callers, which is a schema
change. Splitting on "is the evidence already in the snapshot" produces a phase
that cannot break existing captures and needs no VM time.

**`listed_taint_markers` is left in the snapshot.** Vestigial and documented beats
a schema bump for tidiness.

**The over-listed signal ships provisional rather than waiting for calibration.**
It is the only thing in this phase answering the phantom-row attack, and gated at
LOW it cannot manufacture a HIGH finding on its own. The alternative — block the
phase on gathering clean captures from more kernels — was considered and rejected
as making a correct fix wait on lab logistics.

**Taint stickiness is documented, not solved.** No channel distinguishes "loaded
now" from "loaded earlier this boot" using the taint word. Claiming otherwise
would be the kind of unbacked assertion `limitations.md` exists to prevent.

---

## 10. Deferred

**Phase 4d — parser hardening.** The naming-attack class, and the collector error
contract:

- All three naming channels (`parse_ftrace_modules`, `reduce_kallsyms`,
  `_callback_and_module`) derive a module name by scraping the last `[...]`, so a
  module named `evilkit][ext4` is read as `ext4` by every one of them at once.
  Cross-view corroboration cannot recover the name because all three fail
  identically.
- Record boundaries come from `splitlines()` over text whose payload is an
  attacker-controlled fixed-width field.
- `struct.error` is **not** a subclass of `ValueError`, so `parse_net_tcp`'s
  `except (ValueError, IndexError)` does not catch it and it escapes a socket
  collector that catches nothing. Verified: `issubclass(struct.error, ValueError)`
  is `False`.
- `parse_kprobes` raises `KernelHookParseError` on any line with fewer than three
  whitespace-separated tokens, and `KernelHookCollector.collect` hardcodes
  `errors=[]` and `status=Status.OK`.
- The decision that **an unparseable channel is a finding**, not merely an
  absence, belongs to 4d. There is nothing for analysis to read until the
  collectors record `ErrorKind.MALFORMED` errors the way `procfs.py` already does.

**Prerequisite for 4d.** How much of the naming class is reachable depends on what
`load_module` accepts in the `name` field of `.gnu.linkonce.this_module`. The
parser behaviour is confirmed; the kernel constraint is not. Settling it means
building a `.ko` with a hostile name and loading it on the lab VM. 4d should be
designed against what survives that experiment, not against the parser findings
alone.

**Phase 5 — a fourth naming channel.** The naming attacks work because all three
existing channels fold identically. `/sys/module/` enumeration has a different
failure mode and would break the monoculture. `collectors/modules.py:33`
deliberately declines `/sys/module`, but as the LOW *listing*, which is a
different role from an independent corroborator, and the built-in false-positive
class named in that comment is addressable by checking `initstate`. This is a new
collector with new I/O and deserves its own phase.

---

## 11. Limitations: one amendment, three additions

### 11.1 Amend L17 — the stickiness limitation already exists, and is half the story

L17 already documents taint stickiness, and does it well: bits 12 and 13 persist
for the boot, so a host that loaded and unloaded a legitimate out-of-tree module
fires the channel with no rootkit present. It even names the cases — VirtualBox,
nvidia, vmware. **This phase must not add a duplicate.**

What L17 records is the **false-positive** direction: the channel firing when it
should not. This phase found the **false-negative** direction, which L17 does not
cover and which is the more dangerous of the two: because the implementation tests
`markers == 0`, a single *currently listed* module carrying any marker silences
the channel entirely — including when a rootkit is present. The same hosts L17
names as false-positive risks are false-negative risks once their driver is loaded
rather than unloaded.

L17 is therefore **amended, not superseded**:

- add the false-negative direction and the §1.1 demonstration;
- record what phase 4c does and does not change. Per-bit reconciliation recovers
  only the case where a listed module's marker explains a *different* bit — a
  signed out-of-tree module carrying `(O)` without `(E)`, normal under Secure Boot
  and DKMS signing, which today silences bit 13 for no reason. It does **not**
  recover the `(OE)`/`(POE)` hosts, because those markers honestly explain bits 12
  and 13, and one bit cannot distinguish one out-of-tree module from two (§1.2);
- state the consequence plainly: **on any host with a listed out-of-tree module,
  the taint channel cannot corroborate a hidden one, and a hidden module must be
  caught by the region and hook channels alone.** Phase 4c makes that visible as a
  channel note (§4.4) rather than leaving it as silence;
- fix the stale identifier: L17 is written against `module_taint_mismatch`, a
  `FindingKind` that phase 3b deleted. It is now the `taint` **channel**
  contributing to `hidden_module`.

### 11.2 New limitations

**L27 — The over-listed signal is calibrated on two captures from one host.** Its
false-positive rate against legitimately loaded modules that export no symbols and
have no traceable functions is unmeasured. Provisional until clean captures from
more kernels exist.

**L28 — The vmalloc region count is derived from an unanchored substring match.**
`count_module_regions` counts any line containing the text `load_module`, so a
vmalloc caller symbol containing that substring inflates the count and can
manufacture a `suspected_hidden_module` finding on a clean host. Not fixable in
analysis; deferred to 4d.

**L29 — A module name can steer its own attribution.** All three naming channels
scrape the last bracketed group on a line, so a module named to contain `][`
attributes its own records to the trailing name. Confirmed against the parsers;
the kernel-side reachability is unverified pending the 4d experiment.
