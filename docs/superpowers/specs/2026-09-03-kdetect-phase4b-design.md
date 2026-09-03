# kdetect Phase 4b — Reporting, IOCs & Redaction Design

**Date:** 2026-09-03
**Status:** Approved, ready for implementation planning
**Scope:** Phase 4b of the phase-4 decomposition (brief deliverable 8). A
`report` command producing Markdown + JSON, IOC extraction, and the L13
redaction pass as a first-class command. Plus one small detection touch —
`comm` on the sweep — so a hidden process has a name in the report. This is the
v1.0 finish line: the detection engine made shareable.

---

## 1. Context

Phases 1–4a built the detection engine: cross-view process/module/hook/socket
detection, per-suspect scoring, signed baselines. `analyze` prints findings to
the terminal and dumps them as JSON. Phase 4b adds the **output layer** that
turns those findings into a shareable artifact — deliverable 8 (reporting, IOCs)
and the L13 redaction pass deferred since phase 1.

Almost everything 4b needs already exists: `analyze(snapshot, baseline)` returns
composed `Finding`s, `Finding.to_dict()` serialises them, and
`tools/redact_snapshot.py` is a working start on cmdline redaction. 4b is
therefore a thin, pure layer over that, plus one small detection change (§3).

### 1.1 What reporting is and isn't here

A report is a **pure function of `(snapshot, findings, iocs)`** — a Markdown
document for a human triaging and a JSON document for a pipeline. It draws no new
conclusions; it presents `analyze`'s. IOC extraction pulls the **portable**
indicators (a module name, a hooked syscall, a C2 endpoint) out of findings,
leaving host-local artifacts (pids, inodes) as report context. Redaction's real
job is making a **snapshot** safe to share (L13); the report itself is secret-free
by construction (§6).

HTML output, STIX/OpenIOC IOC formats, and a `sock_diag` channel are all out of
scope (§9) — v1.0 is the readable, honest, shareable minimum.

---

## 2. Principles

All prior principles hold. Phase 4b adds one, governing the output layer.

**P11 — The report concludes nothing; it presents `analyze`'s findings.** Every
statement in a report traces to a `Finding` (P5) or a recorded snapshot fact
(P1). Rendering, IOC extraction, and redaction are pure transforms over data the
detection layer already produced — no new detection, no new confidence, no
re-interpretation. A report a reader cannot trace back to a finding or the
snapshot is a report that has overstepped.

---

## 3. `comm` on the sweep (the one detection touch)

A `hidden_process` finding is, by definition, about a process hidden from
`/proc` readdir — the collector (`procfs.processes`) that records
`comm`/`cmdline`/`exe`. So a hidden process has **no `ProcessEntity`** in the
snapshot, and a report would have no name for it. The sweep already reads
`/proc/<tid>/status` (to get `Tgid:`), and that same file carries `Name:` (the
`comm`), so a name is one field away.

- `parsers/procfs.py`: `parse_status` also exposes the `Name:` field.
- `collectors/base.py`: `SignalSource.read_tgid` returns tgid **and** comm (a
  small `(tgid, comm)` result); `LiveSignalSource`/`FixtureSignalSource` updated;
  signal-set fixtures gain a `comm` field.
- `models.py`: `SweepEntity` gains `comm: str | None` (None when status
  unreadable), with `to_dict`/`from_dict`. **Schema stays 1.1** — additive; a
  fixture without `comm` loads as `None`.
- `collectors/syscall_sweep.py`: stores `comm` per `SweepEntity`.
- `analysis/signals.py`: `signals_processes` copies `comm` into the
  `hidden_process` finding's `evidence`, so the report reads it from the finding.

This is evidence-only (P1/P4): `comm` is a recorded fact, and nothing concludes
from it (the differ's logic is unchanged — it still folds threads by `tgid` and
flags absence from readdir). `comm` is world-readable and low-secret, so it needs
no redaction. `exe` remains genuinely unavailable for a hidden process (it needs
the readdir path that hid it); the report says so (L26).

---

## 4. Architecture & module layout

```
kdetect report <snapshot> [--format md|json] [--out PATH] [--baseline P --verify-key P]
   │
   ├─ load snapshot  →  analyze(snapshot, baseline)  →  [Finding]     (existing)
   ├─ iocs.extract(findings)                          →  [IOC]
   └─ report.render_markdown | render_json(snapshot, findings, iocs)  →  stdout | --out

kdetect redact <in.json> <out.json>
   └─ redact.redact_snapshot(load(in))  →  write(out)     # L13 snapshot scrub
```

**Files:**
- **Create** `src/kdetect/reporting/redact.py` — `redact_snapshot(dict) -> dict` (cmdline scrub, promoted from `tools/redact_snapshot.py`).
- **Create** `src/kdetect/reporting/iocs.py` — `IOC` dataclass + `extract(findings) -> list[IOC]`.
- **Create** `src/kdetect/reporting/report.py` — `render_markdown(snapshot, findings, iocs) -> str`, `render_json(snapshot, findings, iocs) -> str`.
- **Modify** `src/kdetect/cli.py` — `report` and `redact` subcommands.
- **Modify** `tools/redact_snapshot.py` — thin wrapper over `reporting/redact.py`.
- **Modify** (§3) `parsers/procfs.py`, `collectors/base.py`, `collectors/sources.py`, `collectors/syscall_sweep.py`, `models.py`, `analysis/signals.py`.

Each reporting unit is pure and independently testable — redaction is dict→dict,
IOC extraction is findings→IOCs, rendering is (snapshot, findings, IOCs)→string.
Only the CLI touches the filesystem.

---

## 5. Report content

Both formats derive from `(snapshot, findings, iocs)`; JSON reuses
`Finding.to_dict()`.

**Markdown** — a readable triage document, findings most-severe first:
- **Header:** hostname, kernel, arch; `captured_at` + boot id + euid; tool
  version + schema; baseline (name + "verified", or "none").
- **Summary:** counts by confidence (HIGH/MEDIUM/LOW) and a one-line verdict
  ("1 hidden module, 1 hidden process — investigate", or "No findings.").
- **Findings:** per finding — a `[CONF] kind — subject` heading, "seen by" /
  "denied by" channel lists, and evidence rendered readably. A `hidden_process`
  shows `comm=<name>` (§3), the socket endpoint(s) it owns (from
  `socket_visible` evidence), and `exe: unavailable (hidden from /proc)` (L26). A
  `hidden_module` shows taint bits, unaccounted region count, and hooked
  functions.
- **Indicators of Compromise:** the typed IOC list as bullets.

**JSON** — the machine artifact:
```json
{ "host": {…}, "captured_at": …, "euid": …, "tool_version": …, "schema": "1.1",
  "baseline": {"name": …, "verified": true},
  "summary": {"high": 1, "medium": 2, "low": 0},
  "findings": [ <Finding.to_dict()> … ],
  "iocs": [ <IOC.to_dict()> … ] }
```

A zero-findings report renders a valid document with an empty findings/IOC list
and a "No findings." verdict — a clean bill of health is a legitimate report.

---

## 6. IOC extraction

`iocs.extract(findings) -> list[IOC]`; `IOC(type: str, value: str, confidence:
str, source_finding: str)` with `to_dict`. Types map from the **portable**
indicators in findings:

- **`kernel_module`** — a `hidden_module` finding's module name.
- **`hooked_function`** — each hooked function in a `hidden_module`'s
  `unexpected_hook` evidence (the technique indicator).
- **`network_endpoint`** — from a `hidden_process`'s `socket_visible` evidence:
  the *remote* `addr:port` of an ESTABLISHED socket (a C2 candidate), or the
  *local* `addr:port` of a LISTEN socket (a backdoor port). `0.0.0.0:0` /
  `:::0` placeholders are skipped.
- **`process_name`** — a `hidden_process`'s `comm` (the malware's own name,
  portable across hosts unlike its pid).

Host-local artifacts (pids, inodes, region counts, taint words) stay as report
**context**, not IOCs — that is the portable-vs-local line. Output is
deterministic: deduplicated and sorted by `(type, value)`.

---

## 7. Redaction

The report is **secret-free by construction**: every finding is about a *hidden*
thing, a hidden process has no `ProcessEntity` (so no `cmdline`) in the snapshot,
and the only identity a report adds is `comm` (low-secret) and socket endpoints.
So the report path carries no `cmdline` and needs no redaction flag.

Redaction's real job is L13's original one — making a **snapshot** safe to share,
since a snapshot holds every *visible* process's `cmdline` (credentials and all):

- **`reporting/redact.py`** — `redact_snapshot(dict) -> dict`, replacing every
  process entity's `cmdline` with `["[redacted]"]`, re-serialised through the
  `Snapshot` model (canonicalises + proves schema-valid). Logic promoted verbatim
  from `tools/redact_snapshot.py`.
- **`tools/redact_snapshot.py`** — kept as a thin CLI wrapper over the module (no
  duplicated logic), so existing fixture-prep muscle memory still works.
- **`kdetect redact <in.json> <out.json>`** — the same scrub as a first-class
  command.

Cross-view findings never depend on `cmdline` (they key on pids/tgids/module/
socket data), so redaction removes the secrets without changing any conclusion.

---

## 8. CLI

- **`kdetect report <snapshot> [--format md|json] [--out PATH] [--baseline P --verify-key P]`**
  — loads the snapshot, runs `analyze(snapshot, baseline)`, extracts IOCs,
  renders the chosen format (default `md`), writes to `--out` or stdout. Baseline
  verify-before-analysis handling is the existing `analyze` path (`BaselineTampered`
  → exit 1). Exit codes match the project contract: **3** when findings are
  present, **0** when none, **1** on error, **2** on usage.
- **`kdetect redact <in.json> <out.json>`** — scrub a snapshot for sharing;
  exit 0 on success, 1 on error.

`analyze` is unchanged (fast terminal triage stays where it is). No new runtime
dependency — Markdown is string building, JSON and redaction are stdlib.

---

## 9. Testing & acceptance

All tiers are pure and run on Windows with the VM off (V1).

- **`test_redact.py`** — `cmdline` scrubbed to the placeholder; non-cmdline
  fields untouched; output round-trips through `Snapshot`; a snapshot with no
  process cmdline is a no-op.
- **`test_iocs.py`** — each type extracted from a synthetic findings list;
  `0.0.0.0:0` skipped; ESTABLISHED→remote vs LISTEN→local endpoint; host-local
  artifacts excluded; dedup + deterministic sort.
- **`test_report.py`** — Markdown has the header/summary/findings/IOC sections,
  the verdict line, `comm=` for a hidden process, and the `exe: unavailable`
  line; JSON has the documented keys and reuses `Finding.to_dict()`; a
  zero-findings snapshot renders "No findings." and an empty IOC list.
- **§3 sweep `comm`** — `parse_status` name extraction; `SweepEntity` round-trip
  with and without `comm`; `signals_processes` puts `comm` in the finding
  evidence; the sweep collector stores it. Existing fixtures without `comm` load
  as `None` (schema-1.1 additive) and the whole suite stays green.
- **CLI** — `report` writes the artifact to `--out` and to stdout, honours
  `--format`, returns exit 3 on findings / 0 on none / 1 on a tampered baseline;
  `redact` scrubs and writes.

### 9.1 Acceptance criteria

1. `report tests/fixtures/snapshots/infected-hooktest.json` → a Markdown doc
   naming `kdetect_hooktest` as a HIGH `hidden_module`, listing
   `__x64_sys_newuname` as a `hooked_function` IOC, with a HIGH verdict.
2. `report` on a clean fixture → a valid doc, "No findings.", empty IOC list,
   exit 0.
3. `report --format json` → parses as JSON with `host`/`summary`/`findings`/
   `iocs` and findings equal to `analyze --json`'s.
4. `redact` on a snapshot removes every process `cmdline` and the output
   re-serialises through `Snapshot`.
5. A `hidden_process` finding (synthetic) renders with `comm=<name>` and
   `exe: unavailable`.
6. Unit suite green on Windows; the 3.11 guard passes.

---

## 10. Decisions and rationale

| Decision | Alternative rejected | Reason |
|---|---|---|
| Markdown + JSON | HTML too | HTML needs templating/escaping surface beyond a v1.0 finish; MD is readable + shareable, JSON reuses `to_dict` |
| New `report` subcommand | extend `analyze --format/--out` | one command, one job — `analyze` stays fast terminal triage; `report` produces the artifact |
| Simple typed IOC list | STIX 2.x / OpenIOC | standards are heavy and several kdetect indicators (a hooked syscall, a taint state) don't map to standard observables; portable typed indicators are honest and stdlib |
| Add `comm` to `SweepEntity` | reporting-only, no detection touch | a hidden process's `comm` is the single most useful report identifier and is one field off the `status` the sweep already reads; without it a hidden-process report has no name |
| Report is cmdline-free by construction; no redaction flag | `--include-cmdline` opt-out | a hidden process has no `ProcessEntity`/`cmdline` in the snapshot, and no finding is about a visible process, so a report never carries `cmdline` — the flag would act on nothing |
| Redaction = snapshot scrub (`kdetect redact` + module) | redact the report | the report is secret-free; L13's real risk is sharing the snapshot, which holds visible processes' cmdline |
| P11 — report concludes nothing | let the report add its own scoring/notes | conclusions belong to `analyze` (P5/P8); the report presents and must stay traceable |

---

## 11. Deferred

Not in phase 4b: HTML reports; STIX/OpenIOC IOC export; a `sock_diag` channel for
hidden-connection detection (L25); report diffing across captures; signing or
timestamping reports; and everything in phase 5 (eBPF, out-of-band memory
forensics, off-host baselines). Phase 4b makes the existing findings shareable and
safe; it is the v1.0 finish line, not the last phase.

---

## 12. Limitations entering phase 4b

Recorded here and to be mirrored in `docs/limitations.md`.

**L26 — A hidden process's `exe` and `cmdline` are unavailable to reports.** A
process hidden from `/proc` readdir has no `ProcessEntity` — the collector that
records `comm`/`cmdline`/`exe` never saw it. The sweep recovers `comm` from
`/proc/<tid>/status` (§3), but `exe` (a readdir-path symlink) and `cmdline` are
not captured for a hidden process, so a report identifies it by `comm`, `tgid`,
and the sockets it owns, and states `exe`/`cmdline` are unavailable. This is a
property of the process being hidden, not of the report: the richer identity
lives on the very readdir path the rootkit suppressed. Recovering it would need a
channel that reads process identity outside readdir (a future collector, or the
out-of-band memory analysis of phase 5).
