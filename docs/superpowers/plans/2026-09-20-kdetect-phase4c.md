# kdetect Phase 4c Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the analysis layer trusting capture-time scalars — reconcile taint per bit, report when a channel is saturated, catch over-listed modules, and stop one attacker-chosen name from demoting a real finding.

**Architecture:** Pure additions to `src/kdetect/analysis/`, plus a thin render path in `reporting/report.py` and `cli.py`. No collector, parser, source or schema change. Every fix reads evidence already present in existing snapshots, so the whole phase is testable against the committed fixtures with no VM, no root and no recapture.

**Tech Stack:** Python 3.11+, stdlib only (`cryptography` is the sole runtime dep and is untouched), pytest, ruff.

**Spec:** [`docs/superpowers/specs/2026-09-20-kdetect-phase4c-design.md`](../specs/2026-09-20-kdetect-phase4c-design.md) — read it before Task 1. §1.2 in particular records a claim that was withdrawn; do not reinstate it.

## Global Constraints

- **Python 3.11 is the floor and it is enforced.** No 3.12-only syntax. `tests/unit/test_python311_compat.py` scans `src/` and `tests/` and will fail the build. (L20: a 3.12-only f-string once passed on Windows and broke on import on the VM.)
- **No new runtime dependencies.** Analysis is stdlib-only.
- **No schema change and no `schema_version` bump.** Nothing is added to, or removed from, the snapshot. `ChannelNote` is an analysis *output*, never serialised into a capture.
- **No fixture file may be modified.** Tests mutate a deep copy in memory.
- **Exit codes are a scriptable contract and do not change:** 3 = findings present, 0 = none, 1 = error, 2 = usage.
- **`analyze --json` keeps its exact current shape** — a bare JSON list of findings. Consumers parse it positionally; adding a key would break them. Channel notes go to the human output and to `report` only.
- **Untrusted-string discipline.** Every snapshot-derived value printed to a terminal goes through `escape.printable()`; every one rendered into Markdown goes through `escape.md_code()` or `md_block()`. A module name is attacker-chosen.
- **Purity.** Nothing under `src/kdetect/analysis/` performs I/O or imports from `collectors/`.
- **ruff** with `select = ["E4","E7","E9","F","B"]`; run `ruff check .` before every commit.
- **Run the suite on the VM as well as Windows** before the branch is considered done. The integration tier only runs where `/proc` is real.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/kdetect/analysis/taint.py` | **New.** The taint bit→letter table and the pure reconciliation. One home for the table, one test file, so widening it later is a single reviewable change. |
| `src/kdetect/analysis/models.py` | Add `ChannelNote` and `FindingKind.OVER_LISTED_MODULE`. |
| `src/kdetect/analysis/signals.py` | Taint branch reads the reconciliation; new `signals_over_listed`; new `channel_notes`. |
| `src/kdetect/analysis/scoring.py` | `_classify` branch for the over-listed kind; ambiguous-attribution replacement for the `len(hidden_named) == 1` gate. |
| `src/kdetect/reporting/report.py` | "Channel coverage" section in Markdown and a `channel_notes` key in JSON. |
| `src/kdetect/cli.py` | Print channel notes in `analyze`'s human output. Exit codes untouched. |
| `tests/unit/test_taint.py` | **New.** Table and reconciliation. |
| `tests/unit/test_signals.py` | Taint branch, over-listed detector, channel notes. |
| `tests/unit/test_scoring.py` | Over-listed classification, ambiguous attribution. |
| `tests/unit/test_report.py` | Channel coverage rendering. |
| `tests/unit/test_cli_report.py` | Exit code unchanged when a channel is saturated. |
| `tests/unit/test_ground_truth.py` | The two real captures still conclude the same thing. |

A shared helper for building hostile snapshots is added to `tests/unit/test_signals.py` in Task 2 and imported by later test modules, so the mutation technique is written once.

---

### Task 1: The taint table and pure reconciliation

**Files:**
- Create: `src/kdetect/analysis/taint.py`
- Test: `tests/unit/test_taint.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `TAINT_BIT_LETTER: dict[int, str]`; `TaintReconciliation` (frozen dataclass, fields `unexplained: list[int]`, `explained_by: dict[int, list[str]]`, property `saturated: bool`); `reconcile(taint: int, listed: dict[str, str | None]) -> TaintReconciliation`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_taint.py`:

```python
from kdetect.analysis.taint import TAINT_BIT_LETTER, reconcile


def test_table_carries_only_the_evidenced_letters():
    # docs/step0-phase2/clean/08-taint-accounting.txt evidences bit 12 = (O)
    # out-of-tree and bit 13 = (E) unsigned, and nothing else. Widening the
    # table without capturing evidence first is the phase 3a format-guess
    # mistake (spec section 4.3).
    assert TAINT_BIT_LETTER == {12: "O", 13: "E"}


def test_no_listed_marker_leaves_every_set_bit_unexplained():
    rec = reconcile((1 << 12) | (1 << 13), {"ext4": None, "xfs": None})
    assert rec.unexplained == [12, 13]
    assert rec.explained_by == {}
    assert rec.saturated is False


def test_marker_explains_only_its_own_bit():
    # The whole point: a (P) proprietary marker has nothing to do with bits
    # 12 and 13, and must not silence them.
    rec = reconcile((1 << 12) | (1 << 13), {"nv": "P"})
    assert rec.unexplained == [12, 13]

    # (O) explains out-of-tree but leaves unsigned unexplained.
    rec = reconcile((1 << 12) | (1 << 13), {"dkms_mod": "O"})
    assert rec.unexplained == [13]
    assert rec.explained_by == {12: ["dkms_mod"]}


def test_oe_module_explains_both_bits_and_saturates_the_channel():
    # This is a LIMIT, not a bug: (OE) honestly explains both bits, so the
    # channel cannot speak about a hidden module (spec section 1.2).
    rec = reconcile((1 << 12) | (1 << 13), {"vboxdrv": "OE", "ext4": None})
    assert rec.unexplained == []
    assert rec.explained_by == {12: ["vboxdrv"], 13: ["vboxdrv"]}
    assert rec.saturated is True


def test_non_reconcilable_bits_are_ignored():
    # Bit 9 is TAINT_WARN; no module can account for it and it must never
    # produce an unexplained bit.
    rec = reconcile(1 << 9, {"ext4": None})
    assert rec.unexplained == []
    assert rec.saturated is False


def test_clean_taint_word_is_not_saturated():
    rec = reconcile(0, {"ext4": "OE"})
    assert rec.unexplained == []
    assert rec.explained_by == {}
    assert rec.saturated is False


def test_owners_are_sorted_and_deduplicated_across_modules():
    rec = reconcile(1 << 12, {"zz": "O", "aa": "OE", "ext4": None})
    assert rec.explained_by == {12: ["aa", "zz"]}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/unit/test_taint.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'kdetect.analysis.taint'`

- [ ] **Step 3: Write the implementation**

Create `src/kdetect/analysis/taint.py`:

```python
"""Taint-word reconciliation (spec section 4). Pure.

/proc/sys/kernel/tainted is one bitmask for the whole kernel; /proc/modules
marks each listed module with the letters it contributed. A set bit is
*explained* when some listed module carries that bit's letter.

Reconciliation replaces a count. A count cannot say WHICH bit a module
accounts for, which is how one legitimately tainted module came to silence the
entire channel.

The table carries only the two letters this repository has evidence for:
docs/step0-phase2/clean/08-taint-accounting.txt records bit 12 as out-of-tree
with marker (O) and bit 13 as unsigned with marker (E). Those are also the only
bits the taint signal has ever tested. Widening the table needs the evidence
captured first (spec section 4.3).

Note the limit this cannot pass, recorded in spec section 1.2 and L17: taint is
a set of sticky booleans about the whole boot. "At least one out-of-tree module
was loaded" cannot distinguish one from two, so on a host with a listed (O)
module a hidden out-of-tree module adds no observable bit. Reconciliation makes
that state visible (`saturated`); it cannot detect through it.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Taint bit -> the /proc/modules marker letter that accounts for it.
#: Evidence: docs/step0-phase2/clean/08-taint-accounting.txt
TAINT_BIT_LETTER: dict[int, str] = {12: "O", 13: "E"}


@dataclass(frozen=True)
class TaintReconciliation:
    """Which reconcilable taint bits are set, and what accounts for them."""

    unexplained: list[int]
    explained_by: dict[int, list[str]]

    @property
    def saturated(self) -> bool:
        """Every reconcilable set bit is explained by a listed module.

        The channel is answering honestly and has nothing left to say about a
        hidden module. Distinct from a clean taint word, where no bit is set at
        all -- which is why this requires explained_by to be non-empty.
        """
        return not self.unexplained and bool(self.explained_by)


def reconcile(taint: int, listed: dict[str, str | None]) -> TaintReconciliation:
    """Reconcile the global taint word against per-module markers.

    `listed` maps each listed module's name to its /proc/modules marker string
    (e.g. "OE") or None. Bits outside TAINT_BIT_LETTER are ignored: they are set
    by events no module can account for, and reconciling them would fire on any
    host that has ever emitted a kernel warning.
    """
    unexplained: list[int] = []
    explained: dict[int, list[str]] = {}
    for bit, letter in sorted(TAINT_BIT_LETTER.items()):
        if not taint & (1 << bit):
            continue
        owners = sorted(n for n, marker in listed.items() if marker and letter in marker)
        if owners:
            explained[bit] = owners
        else:
            unexplained.append(bit)
    return TaintReconciliation(unexplained=unexplained, explained_by=explained)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/unit/test_taint.py -v`
Expected: PASS, 7 tests.

- [ ] **Step 5: Lint and commit**

```bash
ruff check .
git add src/kdetect/analysis/taint.py tests/unit/test_taint.py
git commit -m "feat(analysis): reconcile taint bits against per-module markers"
```

---

### Task 2: Wire the taint signal to the reconciliation

**Files:**
- Modify: `src/kdetect/analysis/signals.py` — `signals_modules`, the taint branch
- Test: `tests/unit/test_signals.py`

**Interfaces:**
- Consumes: `reconcile`, `TaintReconciliation` from Task 1.
- Produces: `_listed_markers(snapshot) -> dict[str, str | None]` (module name → marker string, read from the `procfs.modules` observation's entities), used again in Task 3. The `taint` Signal's evidence dict becomes `{"taint": int, "bits": list[int], "explained_by": dict[str, list[str]]}` — note the keys of `explained_by` are **strings**, because the evidence dict is serialised to JSON.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_signals.py`. This also adds the mutation helper later tasks import:

```python
import copy


def _mutate(name):
    """Load a committed capture as a raw dict for hostile mutation.

    Fixtures are never modified on disk (spec section 8); every test deep-copies
    the parsed JSON, edits the copy, and rebuilds a Snapshot from it.
    """
    return copy.deepcopy(json.loads((SNAP / name).read_text(encoding="utf-8")))


def _obs(raw, collector):
    return next(o for o in raw["observations"] if o["collector"] == collector)


def _mark(raw, marker):
    """Give the first listed module a /proc/modules taint marker."""
    mods = _obs(raw, "procfs.modules")
    mods["entities"][mods["entity_ids"][0]]["taint"] = marker
    return raw


def _taint_signal(raw):
    sigs = signals_modules(Snapshot.from_dict(raw))
    found = [s for s in sigs if s.channel == "taint"]
    return found[0] if found else None


def test_taint_fires_on_the_unmodified_captures():
    for name in ("infected-hooktest.json", "infected-diamorphine.json"):
        sig = _taint_signal(_mutate(name))
        assert sig is not None, name
        assert sig.evidence["bits"] == [12, 13]
        assert sig.evidence["explained_by"] == {}


def test_proprietary_marker_no_longer_silences_the_out_of_tree_bits():
    # Today a (P) marker sets listed_taint_markers to 1 and kills the channel.
    # It has nothing to do with bits 12 and 13 (spec section 1.2, middle rows).
    sig = _taint_signal(_mark(_mutate("infected-hooktest.json"), "P"))
    assert sig is not None
    assert sig.evidence["bits"] == [12, 13]


def test_signed_out_of_tree_marker_leaves_the_unsigned_bit_unexplained():
    sig = _taint_signal(_mark(_mutate("infected-hooktest.json"), "O"))
    assert sig is not None
    assert sig.evidence["bits"] == [13]
    assert list(sig.evidence["explained_by"]) == ["12"]


def test_oe_marker_still_silences_the_channel():
    # Pinning the LIMIT with a test so it cannot be mistaken for a regression:
    # (OE) honestly explains both bits, and no reconciliation recovers this.
    assert _taint_signal(_mark(_mutate("infected-hooktest.json"), "OE")) is None


def test_non_module_taint_bit_never_fires():
    raw = _mutate("infected-hooktest.json")
    _obs(raw, "kernel.module_evidence")["stats"]["taint"] = 1 << 9   # TAINT_WARN
    assert _taint_signal(raw) is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_signals.py -k taint -v`
Expected: FAIL — `test_taint_fires_on_the_unmodified_captures` fails with `KeyError: 'explained_by'`, and `test_proprietary_marker_no_longer_silences_the_out_of_tree_bits` fails because the signal is `None`.

- [ ] **Step 3: Write the implementation**

In `src/kdetect/analysis/signals.py`, add the import:

```python
from kdetect.analysis.taint import reconcile
```

Add this helper next to `_module_ids`:

```python
def _listed_markers(snapshot: Snapshot) -> dict[str, str | None]:
    """Each listed module's /proc/modules taint marker, or None.

    The letters are already in every snapshot ever captured -- ModuleEntity.taint
    -- and were being discarded in favour of a count (P12).
    """
    obs = _observations(snapshot, "procfs.modules")
    if not obs:
        return {}
    return {name: ent.taint for name, ent in obs[0].entities.items()}
```

Replace the taint branch of `signals_modules`. Delete these three lines:

```python
    markers = (ev.extra or {}).get("listed_taint_markers", 0)
```
and
```python
    if bool(taint & ((1 << 12) | (1 << 13))) and markers == 0:
        bits = [b for b in (12, 13) if taint & (1 << b)]
        out.append(Signal("taint", Suspect("module", None), _MODULE_DISSENT,
                          {"taint": taint, "listed_taint_markers": markers, "bits": bits}))
```

with:

```python
    rec = reconcile(taint, _listed_markers(snapshot))
    if rec.unexplained:
        # explained_by keys are stringified: this dict is serialised into the
        # finding's evidence and JSON object keys must be strings.
        out.append(Signal("taint", Suspect("module", None), _MODULE_DISSENT,
                          {"taint": taint, "bits": rec.unexplained,
                           "explained_by": {str(b): v
                                            for b, v in rec.explained_by.items()}}))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_signals.py -v`
Expected: PASS.

- [ ] **Step 5: Run the whole suite and fix the expected breakage**

Run: `python -m pytest tests -q`
Expected: failures in `tests/unit/test_ground_truth.py` and `tests/unit/test_report.py` wherever the taint evidence dict is asserted verbatim. This is intended, not a regression — spec §8.1 criterion 1. Update those assertions to expect `explained_by` present and `listed_taint_markers` absent. Do **not** loosen an assertion to make it pass; change it to the new expected value.

Re-run: `python -m pytest tests -q`
Expected: PASS.

- [ ] **Step 6: Lint and commit**

```bash
ruff check .
git add src/kdetect/analysis/signals.py tests/unit/test_signals.py tests/unit/test_ground_truth.py tests/unit/test_report.py
git commit -m "fix(analysis): reconcile taint per bit instead of counting markers"
```

---

### Task 3: `ChannelNote` and `channel_notes()`

**Files:**
- Modify: `src/kdetect/analysis/models.py` — add `ChannelNote`
- Modify: `src/kdetect/analysis/signals.py` — add `channel_notes`
- Test: `tests/unit/test_signals.py`

**Interfaces:**
- Consumes: `_listed_markers` and `reconcile` from Task 2.
- Produces: `ChannelNote` (frozen dataclass, fields `channel: str`, `reason: str`, `detail: dict`, method `to_dict() -> dict`); `channel_notes(snapshot: Snapshot) -> list[ChannelNote]`. Tasks 4 consumes both.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_signals.py`:

```python
from kdetect.analysis.models import ChannelNote
from kdetect.analysis.signals import channel_notes


def test_no_note_when_taint_is_clean():
    raw = _mutate("infected-hooktest.json")
    _obs(raw, "kernel.module_evidence")["stats"]["taint"] = 0
    assert channel_notes(Snapshot.from_dict(raw)) == []


def test_no_note_when_the_channel_still_speaks():
    # Bits set and unexplained: the channel is contributing, not saturated.
    assert channel_notes(_load("infected-hooktest.json")) == []


def test_saturated_taint_emits_a_note_naming_the_explaining_module():
    raw = _mark(_mutate("infected-hooktest.json"), "OE")
    notes = channel_notes(Snapshot.from_dict(raw))
    assert len(notes) == 1
    note = notes[0]
    assert isinstance(note, ChannelNote)
    assert note.channel == "taint"
    assert note.reason == "saturated"
    explaining = _obs(raw, "procfs.modules")["entity_ids"][0]
    assert note.detail["explained_by"] == {"12": [explaining], "13": [explaining]}


def test_note_round_trips_to_a_json_safe_dict():
    raw = _mark(_mutate("infected-hooktest.json"), "OE")
    d = channel_notes(Snapshot.from_dict(raw))[0].to_dict()
    assert json.loads(json.dumps(d)) == d
    assert set(d) == {"channel", "reason", "detail"}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_signals.py -k channel_note -v`
Expected: FAIL — `ImportError: cannot import name 'ChannelNote'`

- [ ] **Step 3: Add `ChannelNote` to `src/kdetect/analysis/models.py`**

```python
@dataclass(frozen=True)
class ChannelNote:
    """Why a channel did not contribute (spec section 4.4).

    NOT a Finding. A channel being uninformative is not a detection, and exit
    code 3 means findings were produced -- emitting this as a Finding would make
    every host with an out-of-tree driver exit 3 forever. Channel notes are
    carried on their own path, are absent from the IOC extractor, and never
    influence an exit code.
    """

    channel: str
    reason: str          # "saturated"
    detail: dict

    def to_dict(self) -> dict:
        return {"channel": self.channel, "reason": self.reason,
                "detail": dict(self.detail)}
```

- [ ] **Step 4: Add `channel_notes` to `src/kdetect/analysis/signals.py`**

Add `ChannelNote` to the existing `kdetect.analysis.models` import, then append:

```python
def channel_notes(snapshot: Snapshot) -> list[ChannelNote]:
    """Channels that could not contribute, and why (spec section 4.4).

    A saturated channel and a clean one look identical in the output today, and
    they mean opposite things: "taint is clear" versus "taint is set and fully
    accounted for by a listed module, so it can say nothing about a hidden one".
    """
    notes: list[ChannelNote] = []
    evidences = _observations(snapshot, "kernel.module_evidence")
    if evidences:
        rec = reconcile(evidences[0].stats.get("taint", 0), _listed_markers(snapshot))
        if rec.saturated:
            notes.append(ChannelNote(
                "taint", "saturated",
                {"explained_by": {str(b): v for b, v in rec.explained_by.items()}},
            ))
    return notes
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/unit/test_signals.py -v`
Expected: PASS.

- [ ] **Step 6: Lint and commit**

```bash
ruff check .
git add src/kdetect/analysis/models.py src/kdetect/analysis/signals.py tests/unit/test_signals.py
git commit -m "feat(analysis): record why a channel could not contribute"
```

---

### Task 4: Render channel notes in `report` and `analyze`

**Files:**
- Modify: `src/kdetect/reporting/report.py` — `render_markdown`, `render_json`
- Modify: `src/kdetect/cli.py` — `cmd_analyze`
- Test: `tests/unit/test_report.py`, `tests/unit/test_cli_report.py`

**Interfaces:**
- Consumes: `ChannelNote`, `channel_notes` from Task 3.
- Produces: `render_markdown(...)` and `render_json(...)` gain a keyword-only parameter `notes: list[ChannelNote] | None = None`, defaulted so every existing caller and test keeps working.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_report.py`:

```python
from kdetect.analysis.models import ChannelNote
from kdetect.reporting.iocs import extract as _extract

_NOTE = ChannelNote("taint", "saturated",
                    {"explained_by": {"12": ["vboxdrv"], "13": ["vboxdrv"]}})


def test_markdown_omits_channel_coverage_when_there_are_no_notes():
    md = report.render_markdown(_snap(), [], [])
    assert "Channel coverage" not in md


def test_markdown_renders_channel_coverage_and_escapes_module_names():
    md = report.render_markdown(_snap(), [], [], notes=[_NOTE])
    assert "## Channel coverage" in md
    assert "taint" in md
    # A module name is attacker-chosen, so it must be inline code, not bare text.
    assert "`vboxdrv`" in md


def test_json_carries_notes_as_a_named_key():
    payload = json.loads(report.render_json(_snap(), [], [], notes=[_NOTE]))
    assert payload["channel_notes"] == [_NOTE.to_dict()]


def test_json_notes_key_is_present_and_empty_when_there_are_none():
    payload = json.loads(report.render_json(_snap(), [], []))
    assert payload["channel_notes"] == []


def test_a_channel_note_never_becomes_an_ioc():
    """Criterion 5: notes are not findings and carry no indicators."""
    assert _extract([]) == []
    md = report.render_markdown(_snap(), [], [], notes=[_NOTE])
    ioc_section = md.split("## Indicators of Compromise", 1)[1]
    assert "vboxdrv" not in ioc_section.split("## Channel coverage")[0]
```

Append to `tests/unit/test_cli_report.py`. Note this module drives the CLI through `main()` with `capsys` — there is no subprocess helper:

```python
import copy


def test_saturated_channel_does_not_change_the_exit_code(tmp_path, capsys):
    """A channel note is not a finding (spec section 4.4, criterion 5)."""
    raw = copy.deepcopy(json.loads(
        (FIX / "infected-hooktest.json").read_text(encoding="utf-8")))

    # Saturate taint AND neutralise the other module channels, so the only
    # module evidence left is the saturated one -> no findings at all.
    mods = next(o for o in raw["observations"] if o["collector"] == "procfs.modules")
    mods["entities"][mods["entity_ids"][0]]["taint"] = "OE"
    ev = next(o for o in raw["observations"]
              if o["collector"] == "kernel.module_evidence")
    ev["stats"]["load_module_regions"] = len(mods["entity_ids"])
    ev["extra"]["ftrace_modules"] = []
    raw["observations"] = [o for o in raw["observations"]
                           if o["collector"] != "kernel.hooks"]

    snap = tmp_path / "saturated.json"
    snap.write_text(json.dumps(raw), encoding="utf-8")

    rc = main(["analyze", str(snap)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "saturated" in out
    assert "taint" in out
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_report.py tests/unit/test_cli_report.py -v`
Expected: FAIL — `TypeError: render_markdown() got an unexpected keyword argument 'notes'`

- [ ] **Step 3: Implement the renderers**

In `src/kdetect/reporting/report.py`, import `ChannelNote` from `kdetect.analysis.models`, then change both signatures and add the section.

`render_json` — add the parameter and one payload key:

```python
def render_json(snapshot: Snapshot, findings: list[Finding], iocs: list[IOC],
                baseline_name: str | None = None,
                notes: list[ChannelNote] | None = None) -> str:
```

and inside `payload`, after `"iocs"`:

```python
        "channel_notes": [n.to_dict() for n in (notes or [])],
```

`render_markdown` — add the parameter:

```python
def render_markdown(snapshot: Snapshot, findings: list[Finding], iocs: list[IOC],
                    baseline_name: str | None = None,
                    notes: list[ChannelNote] | None = None) -> str:
```

and before the final `return "\n".join(out)`, after the IOC block:

```python
    if notes:
        out.append("## Channel coverage")
        out.append("")
        for n in notes:
            if n.reason == "saturated":
                out.append(
                    f"- `{n.channel}` could not corroborate: every bit it reads is "
                    f"already explained by a listed module, so it cannot speak to a "
                    f"hidden one."
                )
                for bit, owners in sorted(n.detail.get("explained_by", {}).items()):
                    named = ", ".join(md_code(o) for o in owners)
                    out.append(f"  - bit {md_code(bit)}: {named}")
        out.append("")
```

- [ ] **Step 4: Implement the CLI output**

In `src/kdetect/cli.py`, import `channel_notes` alongside the existing `analyze` import, and in `cmd_analyze` insert this immediately **after** `findings = analyze(snapshot, baseline)` and **before** the `if getattr(args, "json", False):` block, so the JSON path is untouched:

```python
    notes = channel_notes(snapshot)
```

Then, in the human path only, after `print()` and before the `if not findings:` test:

```python
    for n in notes:
        if n.reason == "saturated":
            print(f"note:      {printable(n.channel)} could not corroborate "
                  f"(saturated); every bit it reads is explained by a listed module")
            for bit, owners in sorted(n.detail.get("explained_by", {}).items()):
                print(f"{' ' * 11}bit {printable(bit)}: "
                      f"{printable(', '.join(owners))}")
```

Find the `report` command handler in the same file and pass the notes through to both renderers, so a report shows the same coverage the terminal does.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests -q`
Expected: PASS. If `analyze --json` output changed shape, that is a constraint violation — revert it; notes belong only to the human path.

- [ ] **Step 6: Lint and commit**

```bash
ruff check .
git add src/kdetect/reporting/report.py src/kdetect/cli.py tests/unit/test_report.py tests/unit/test_cli_report.py
git commit -m "feat(reporting): show channel coverage so a saturated channel is visible"
```

---

### Task 5: The over-listed module signal

**Files:**
- Modify: `src/kdetect/analysis/models.py` — add `FindingKind.OVER_LISTED_MODULE`
- Modify: `src/kdetect/analysis/signals.py` — add `signals_over_listed`, call it from `all_signals`
- Modify: `src/kdetect/analysis/scoring.py` — `_classify` branch
- Test: `tests/unit/test_signals.py`, `tests/unit/test_scoring.py`

**Interfaces:**
- Consumes: `_observations`, `_module_ids` from `signals.py`.
- Produces: `FindingKind.OVER_LISTED_MODULE = "over_listed_module"`; `signals_over_listed(snapshot) -> list[Signal]` emitting channel `"over_listed"` with `Suspect("module", name)`.

**Critical:** do **not** add `"over_listed"` to `_HIDING` in `scoring.py`. Spec §7.1 — it would classify an over-listed module as *hidden*, the exact inverse of the evidence.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_signals.py`:

```python
from kdetect.analysis.signals import signals_over_listed


def _corroborators(raw, ftrace, kallsyms):
    _obs(raw, "kernel.module_evidence")["extra"]["ftrace_modules"] = ftrace
    _obs(raw, "kernel.module_evidence")["stats"]["ftrace_available"] = True
    hooks = _obs(raw, "kernel.hooks")
    hooks["extra"]["kallsyms_modules"] = kallsyms
    hooks["stats"]["kallsyms_available"] = True
    return raw


def test_no_over_listed_signal_on_the_real_captures():
    # Measured in spec section 5.2: zero on hooktest, and diamorphine has no
    # kernel.hooks observation at all so the guard suppresses it there.
    for name in ("infected-hooktest.json", "infected-diamorphine.json"):
        assert signals_over_listed(_load(name)) == [], name


def test_phantom_row_is_caught_when_every_channel_is_available():
    raw = _mutate("infected-hooktest.json")
    mods = _obs(raw, "procfs.modules")
    mods["entities"]["phantom_mod"] = {
        "name": "phantom_mod", "size": 1, "refcount": 0, "dependents": [],
        "state": "Live", "base_addr": "0x0", "taint": None,
    }
    mods["entity_ids"] = sorted(mods["entity_ids"] + ["phantom_mod"])
    raw = _corroborators(raw, ftrace=["ext4"], kallsyms=["ext4"])

    sigs = signals_over_listed(Snapshot.from_dict(raw))
    assert [s.suspect.name for s in sigs] == ["phantom_mod"]
    assert sigs[0].channel == "over_listed"


def test_unavailable_channel_suppresses_the_signal_entirely():
    raw = _mutate("infected-hooktest.json")
    _obs(raw, "kernel.hooks")["stats"]["kallsyms_available"] = False
    assert signals_over_listed(Snapshot.from_dict(raw)) == []


def test_available_but_empty_channel_is_not_treated_as_dissent():
    # The distinction spec section 5.2 calls load-bearing: an available channel
    # that legitimately names nothing must not make every module over-listed.
    raw = _corroborators(_mutate("infected-hooktest.json"), ftrace=[], kallsyms=[])
    sigs = signals_over_listed(Snapshot.from_dict(raw))
    listed = len(_obs(raw, "procfs.modules")["entity_ids"])
    assert len(sigs) == listed          # every module really is uncorroborated
    assert listed > 0
```

> The last test documents that an available-but-empty pair *does* flag everything. That is correct behaviour for a genuinely empty corroborating set — the guard protects against *unavailable*, not *empty*. If the calibration in L27 later shows this is too noisy, that is a signal-design change, not a guard change.

Append to `tests/unit/test_scoring.py`:

```python
def test_over_listed_module_gets_its_own_kind_and_is_not_hidden():
    findings = score([_mod("over_listed", "phantom_mod")])
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.OVER_LISTED_MODULE
    assert f.confidence is Confidence.LOW
    # The inverse-classification trap from spec section 7.1.
    assert f.kind is not FindingKind.HIDDEN_MODULE
    assert f.kind is not FindingKind.BASELINE_DRIFT


def test_over_listed_does_not_absorb_anonymous_hidden_evidence():
    sigs = [_mod("over_listed", "phantom_mod"), _mod("taint", None, bits=[12])]
    findings = score(sigs)
    over = [f for f in findings if f.kind is FindingKind.OVER_LISTED_MODULE]
    assert len(over) == 1
    assert over[0].channels_agree == ["over_listed"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_signals.py tests/unit/test_scoring.py -k "over_listed or phantom or available" -v`
Expected: FAIL — `ImportError: cannot import name 'signals_over_listed'`

- [ ] **Step 3: Add the `FindingKind`**

In `src/kdetect/analysis/models.py`:

```python
    OVER_LISTED_MODULE = "over_listed_module"              # NEW (phase 4c)
```

- [ ] **Step 4: Add the detector**

In `src/kdetect/analysis/signals.py`, add the dissent constant near the others:

```python
_LISTING_DISSENT = "every corroborating channel"
```

and the detector:

```python
def signals_over_listed(snapshot: Snapshot) -> list[Signal]:
    """A listed module that no other channel corroborates (spec section 5).

    The mirror of ftrace_orphan. An attacker who can unlink a row from
    /proc/modules can equally add one, and each phantom row absorbs exactly one
    unaccounted vmalloc region -- so the region arithmetic is one phantom row
    deep without this.

    Guarded on channel AVAILABILITY, never on emptiness: a channel that cannot
    be read must be skipped rather than read as dissent, which is the rule
    ModuleSource's own docstring states. Reading emptiness as unavailability
    would flag every module on a host whose channels legitimately name nothing.
    """
    listings = _observations(snapshot, "procfs.modules")
    evidences = _observations(snapshot, "kernel.module_evidence")
    hooks = _observations(snapshot, "kernel.hooks")
    if not listings or not evidences or not hooks:
        return []
    if not evidences[0].stats.get("ftrace_available"):
        return []
    if not hooks[0].stats.get("kallsyms_available"):
        return []

    ftrace = (evidences[0].extra or {}).get("ftrace_modules")
    kallsyms = (hooks[0].extra or {}).get("kallsyms_modules")
    if ftrace is None or kallsyms is None:
        return []

    corroborated = set(ftrace) | set(kallsyms)
    return [
        Signal("over_listed", Suspect("module", name), _LISTING_DISSENT,
               {"listed": True, "corroborated_by": []})
        for name in sorted(set(listings[0].entity_ids) - corroborated)
    ]
```

Add it to `all_signals`:

```python
    sigs = (signals_processes(snapshot) + signals_modules(snapshot)
            + signals_hooks(snapshot) + signals_sockets(snapshot)
            + signals_over_listed(snapshot))
```

- [ ] **Step 5: Classify it in `scoring.py`**

In `_classify`, add this branch **before** the `any(c in _HIDING ...)` test:

```python
    if channels == ["over_listed"]:
        return (FindingKind.OVER_LISTED_MODULE, f"module {suspect.name}",
                f"module {suspect.name} is listed in /proc/modules but named by "
                f"no other channel")
```

Leave `_HIDING` and `_HIDING_NAMED` unchanged — see spec §7.1.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests -q`
Expected: PASS, including the unchanged ground-truth assertions.

- [ ] **Step 7: Lint and commit**

```bash
ruff check .
git add src/kdetect/analysis/models.py src/kdetect/analysis/signals.py src/kdetect/analysis/scoring.py tests/unit/test_signals.py tests/unit/test_scoring.py
git commit -m "feat(analysis): flag modules the listing claims and no channel corroborates"
```

---

### Task 6: Ambiguous attribution

**Files:**
- Modify: `src/kdetect/analysis/scoring.py` — `score`, `_classify`
- Test: `tests/unit/test_scoring.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: no new names. `SUSPECTED_HIDDEN_MODULE` findings gain a `candidates: list[str]` key in their evidence when more than one module is hidden-named.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_scoring.py`:

```python
def test_a_second_name_does_not_strip_the_real_suspects_evidence():
    """One appended module name must not demote a real finding (spec section 6)."""
    real = [
        _mod("unexpected_hook", "kdetect_hooktest", function="__x64_sys_newuname"),
        _mod("taint", None, bits=[12, 13]),
        _mod("vmalloc_region", None, unaccounted=1),
    ]
    alone = score(real)
    assert alone[0].confidence is Confidence.HIGH

    # The attack: manufacture one extra hidden name to force a tie.
    with_decoy = score(real + [_mod("ftrace_orphan", "e1000_dbg")])
    unattributed = [f for f in with_decoy
                    if f.kind is FindingKind.SUSPECTED_HIDDEN_MODULE]
    assert len(unattributed) == 1

    # The anonymous evidence is still reachable: it names BOTH candidates
    # instead of silently discarding the attribution.
    assert unattributed[0].evidence["candidates"] == ["e1000_dbg", "kdetect_hooktest"]
    assert "e1000_dbg" in unattributed[0].summary
    assert "kdetect_hooktest" in unattributed[0].summary


def test_single_candidate_still_attributes_and_carries_no_candidate_list():
    sigs = [_mod("unexpected_hook", "solo", function="x"), _mod("taint", None, bits=[12])]
    findings = score(sigs)
    assert len(findings) == 1
    assert findings[0].subject == "module solo"
    assert "candidates" not in findings[0].evidence
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/unit/test_scoring.py -k candidate -v`
Expected: FAIL — `KeyError: 'candidates'`

- [ ] **Step 3: Implement**

In `src/kdetect/analysis/scoring.py`, change `score` so the ambiguous case records the candidates instead of dropping them. Replace:

```python
    if len(hidden_named) == 1 and anon:
        target = Suspect("module", next(iter(hidden_named)))
        groups.setdefault(target, []).extend(anon)
        anon = []
```

with:

```python
    candidates = sorted(hidden_named)
    if len(candidates) == 1 and anon:
        target = Suspect("module", candidates[0])
        groups.setdefault(target, []).extend(anon)
        anon = []
```

and change the trailing unattributed block:

```python
    if anon:
        findings.append(_compose(Suspect("module", None), anon))
```

to:

```python
    if anon:
        unattributed = _compose(Suspect("module", None), anon)
        if len(candidates) > 1:
            # Ambiguity is reported, not discarded (spec section 6). An attacker
            # who manufactures a second hidden name must not be able to make the
            # corroborating evidence vanish from the report.
            evidence = dict(unattributed.evidence)
            evidence["candidates"] = candidates
            unattributed = replace(
                unattributed, evidence=evidence,
                summary=(f"{unattributed.summary}; candidates: "
                         f"{', '.join(candidates)}"),
            )
        findings.append(unattributed)
```

Add `replace` to the imports at the top of the file:

```python
from dataclasses import replace
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests -q`
Expected: PASS. `test_two_hidden_modules_do_not_absorb_anonymous` still passes — it asserts one `SUSPECTED_HIDDEN_MODULE` exists, which is unchanged; only its evidence and summary are richer.

- [ ] **Step 5: Lint and commit**

```bash
ruff check .
git add src/kdetect/analysis/scoring.py tests/unit/test_scoring.py
git commit -m "fix(analysis): name the candidates instead of discarding ambiguous attribution"
```

---

### Task 7: Documentation

**Files:**
- Modify: `docs/limitations.md` — amend L17, add L27–L29
- Modify: `docs/detection-methods.md` — taint section, new over-listed entry
- Modify: `README.md` — the "What it detects" finding table

**Interfaces:** none — documentation only.

- [ ] **Step 1: Amend L17**

L17 records only the false-positive direction and names `module_taint_mismatch`, a `FindingKind` phase 3b deleted. Keep its existing first paragraph (the stickiness argument is correct and well evidenced) and **append** this, then replace every occurrence of `module_taint_mismatch` in the entry with "the `taint` channel":

```markdown
**Amended phase 4c (2026-09-20).** The entry above records the false-positive
direction. The implementation also had the opposite failure, which is worse. It
tested `markers == 0` — a bare count of listed modules carrying any taint marker
at all — so a *single currently listed* module with any marker silenced the
channel completely, including when a rootkit was present. The same drivers named
above are false-negative risks whenever they are loaded rather than unloaded.

Phase 4c replaced the count with per-bit reconciliation: a set bit is explained
only by a listed module carrying that bit's own letter. That recovers the case
where a marker explains some *other* bit — a signed out-of-tree module carries
`(O)` without `(E)`, normal under Secure Boot and DKMS signing, and used to
silence bit 13 for no reason.

It does **not** recover a host carrying `(OE)` or `(POE)` — nvidia, zfs,
vboxdrv. Those markers honestly explain bits 12 and 13, and taint is one sticky
boolean per class: "at least one out-of-tree module was loaded" cannot
distinguish one from two. **On any host with a listed out-of-tree module the
taint channel cannot corroborate a hidden one, and a hidden module must be
caught by the region and hook channels alone.** kdetect now says so rather than
staying silent — see the "Channel coverage" section of a report.
```

- [ ] **Step 2: Add L27, L28 and L29**

Append a `## Phase 4c` heading at the end of `limitations.md`, matching the existing per-phase headings, then these three entries:

```markdown
## Phase 4c — evidence discipline in analysis

**L27 — The over-listed signal is calibrated on two captures from one host.**
Its false-positive rate against legitimately loaded modules that export no
symbols and have no traceable functions is unmeasured. Measured on the committed
captures: zero on `infected-hooktest`, and suppressed on `infected-diamorphine`
by the availability guard, which has no `kernel.hooks` observation. That is a
calibration set of two, one of them degenerate. Provisional until clean captures
from more kernels exist; treat a report of this signal from a real host as
evidence about the signal, not only about the host.

**L28 — The vmalloc region count is derived from an unanchored substring
match.** `count_module_regions` counts any `/proc/vmallocinfo` line containing
the text `load_module`, so a vmalloc caller symbol containing that substring
inflates the count and can manufacture a `suspected_hidden_module` finding on a
clean host. Not fixable in the analysis layer — the collector records only the
count, discarding which lines matched (P12) — so it is deferred to phase 4d.

**L29 — A module name can steer its own attribution.** All three channels that
can name a module (`parse_ftrace_modules`, `reduce_kallsyms`, and
`_callback_and_module`) derive the name by scraping the last bracketed group on
a line, so a module named to contain `][` attributes its own records to the
trailing name — and all three fail identically, so cross-view corroboration
cannot recover it. Confirmed against the parsers. The kernel-side reachability
is unverified: whether `load_module` accepts such a name in the `name` field of
`.gnu.linkonce.this_module` has not been tested on a real kernel, and phase 4d
is gated on that experiment.
```

- [ ] **Step 3: Update `detection-methods.md`**

Two edits. In the taint entry, replace the marker-count description with per-bit reconciliation, cite `docs/step0-phase2/clean/08-taint-accounting.txt` for the two-letter table, and state the saturation limit. Add a new entry for the over-listed channel marked **[implemented]**, recording explicitly that its false-positive rate is calibrated on two captures from one host and one kernel, and that it is provisional (L27).

- [ ] **Step 4: Update the README finding table**

Add a row to the "What it detects" table:

```markdown
| `over_listed_module` | `/proc/modules` listing vs `ftrace_modules`, `kallsyms_modules` |
```

and bump the count sentence above the table if it states how many methods are implemented.

- [ ] **Step 5: Verify the docs match the code**

Run: `python -m pytest tests -q`
Then re-read spec §8.1 and tick each of the ten criteria against a test that asserts it. Any criterion without a test is a gap — add the test before finishing.

- [ ] **Step 6: Commit**

```bash
git add docs/limitations.md docs/detection-methods.md README.md
git commit -m "docs: phase 4c limitations, detection methods and finding table"
```

---

## Final verification

- [ ] `ruff check .` clean
- [ ] `python -m pytest tests -q` green on Windows
- [ ] **`pytest tests` green on the lab VM** — the integration tier only runs on a real `/proc`, and the 3.11 import guard only proves itself on 3.11 (L20)
- [ ] `kdetect analyze tests/fixtures/snapshots/infected-hooktest.json` still reports `HIGH hidden_module module kdetect_hooktest`, exit 3
- [ ] `kdetect analyze tests/fixtures/snapshots/clean-phase2.json` reports no findings, exit 0
- [ ] `git diff main --stat` touches no file under `tests/fixtures/` and no `schema_version`
