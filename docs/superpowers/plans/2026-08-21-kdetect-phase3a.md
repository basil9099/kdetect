# kdetect Phase 3a — Baseline Store & Hook-Surface Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a signed baseline store, a `kernel_hooks` view that captures ftrace/kprobe/kallsyms hook surfaces, a pure baseline-diff pass, and an intra-snapshot orphan-hook check, so `kdetect analyze --baseline` detects a benign ftrace-hooking LKM the same way phase 2 detected Diamorphine's hidden module.

**Architecture:** Snapshots stay evidence-only (P1). A new MEDIUM collector `kernel.hooks` records what is hooked, recording `owner_module` as evidence and never labelling. A signed baseline is an ordinary snapshot plus a detached ed25519 signature, verified before use (P6/P7). Two pure differ functions turn "new since clean" (`baseline_diff`) and "hooked by an unlisted module" (`diff_hooks`) into `Finding`s, composing into the existing corroboration-count confidence.

**Tech Stack:** Python 3.11+, pytest. **One new runtime dependency: `cryptography`** (ed25519), the project's first. The test LKM is C (kernel module), built on the VM only.

**Spec:** `docs/superpowers/specs/2026-08-21-kdetect-phase3a-design.md` (read it alongside this plan; principles P1–P7, the L16 redirect, and the confidence model are argued there and cited by task).

## Global Constraints

- **P1 — snapshots hold evidence, not conclusions.** Collectors never label. `HookEntity` records `owner_module` (evidence); `attributable` is *derived by the differ* (P4), not stored. No finding is ever serialised into a snapshot.
- **P3 — test code == production code.** Every collector takes its source as an argument; no `if testing:` branch. `KernelHookSource` has a live and a fixture implementation behind one interface.
- **P5 — a Finding carries the evidence it was drawn from.** Every `Finding.evidence` holds the exact snapshot values that produced it.
- **P6 — a baseline is a snapshot** plus a detached signature; it round-trips through the existing `Snapshot.to_json`/`from_dict`.
- **P7 — verification precedes trust.** `load_baseline` checks the signature *before* `json.loads`; a bad signature raises `BaselineTampered` and analysis never runs on it.
- **Determinism.** `to_dict`/`to_json` use `sort_keys=True`; `entity_ids` sorted; `from_dict(to_dict(s)) == s`. New optional fields are **omitted when `None`**, so phase 1/2 fixtures still round-trip. The bytes signed are exactly the bytes written to `<name>.json`.
- **Schema stays 1.1** — additive only (a new collector name, a new entity type). MAJOR stays 1; no existing field changes.
- **Capability-gated tests, not OS-gated.** Live-source tests use `@needs_procfs` from `tests/conftest.py`. Parser, source-fixture, collector, model, differ, and baseline-store tiers run on Windows with the VM off. `cryptography` is cross-platform, so V1 ("unit suite runs without Linux") still holds.
- **Exit codes:** 0 ok, 1 error (**now including `BaselineTampered`**), 2 usage, 3 = any finding fired.
- **Step-0 gate.** No `kernel_hooks` schema field is finalised until Task 2 records the real `enabled_functions`/`kprobes`/`kallsyms` format under `docs/step0-phase3/`. Parser tests draw their input verbatim from that capture; where the sample lines in this plan differ from the live capture, **the capture wins** and the field extraction adjusts.
- **Angus commits.** Do not run `git commit`. Each task's final step **stages** files with `git add` and states the commit message for Angus to run. Never `git push` while the (even benign) test LKM is loaded; use the `clean-baseline` → snapshot → Host-only → revert discipline from `docs/step0-phase2/README.md`.

---

## File Structure

**Create:**
- `kmod/kdetect_hooktest.c`, `kmod/Makefile` — the benign test LKM (visible + hidden build modes). Source committed; `.ko` gitignored (already).
- `docs/step0-phase3/README.md` + `docs/step0-phase3/clean/*.txt` — hand-exploration evidence (the gate).
- `src/kdetect/parsers/kernel_hooks.py` — pure parsers: `parse_enabled_functions`, `parse_kprobes`, `reduce_kallsyms`.
- `src/kdetect/collectors/kernel_hooks.py` — `KernelHookCollector` (MEDIUM).
- `src/kdetect/baseline/store.py` — `write_baseline`, `load_baseline`, `BaselineTampered`, key loaders.
- `src/kdetect/analysis/baseline_diff.py` — `diff(current, baseline) -> [Finding]` (module-view drift).
- Tests: `tests/unit/test_parse_kernel_hooks.py`, `test_kernel_hook_source.py`, `test_collector_kernel_hooks.py`, `test_hook_entity.py`, `test_diff_hooks.py`, `test_baseline_store.py`, `test_baseline_diff.py`; `tests/integration/test_phase3a_live.py`.

**Modify:**
- `src/kdetect/models.py` — add `HookEntity`; register `"kernel.hooks"` in `_ENTITY_TYPES` and `_STRING_ID_COLLECTORS`.
- `src/kdetect/collectors/base.py` — add `KernelHookSource` ABC.
- `src/kdetect/collectors/sources.py` — `LiveKernelHookSource`, `FixtureKernelHookSource`.
- `src/kdetect/analysis/models.py` — add `FindingKind.UNEXPECTED_HOOK`, `FindingKind.BASELINE_DRIFT`.
- `src/kdetect/analysis/crossview.py` — add `diff_hooks(snapshot, baseline=None)`; `diff_all(snapshot, baseline=None)` threads the baseline.
- `src/kdetect/cli.py` — `capture` runs `KernelHookCollector`; new `baseline` subcommand; `analyze --baseline/--verify-key`.
- `pyproject.toml` — `dependencies = ["cryptography>=42"]`.
- `docs/limitations.md` — add L18; `docs/detection-methods.md` — rewrite §10 for hook surfaces; `docs/architecture.md` — note the baseline store.

**Fixtures (small, curated; hooked/orphan fixtures hand-authored, live captures added in Task 11):**
- `tests/fixtures/hook-trees/clean/` (`enabled_functions.txt`, `kprobes.txt`, `kallsyms.txt`) and `.../hooked/`, `.../orphan/`.
- `tests/fixtures/baselines/clean.json` + `clean.json.sig` + `test_ed25519.pub.pem` (+ a throwaway private key for the sign test); `tests/fixtures/baselines/tampered.json` + `.sig`.
- `tests/fixtures/snapshots/clean-phase3a.json` (zero-findings guard), `infected-hooktest.json` (Task 11, redacted).

---

## Task 1: The benign test LKM

**This task's `.ko` is built and loaded on the VM (Angus).** The C source is authored and reviewed on Windows; only `make` and `insmod` need the VM. It exists so Task 2 can capture a *real* hook's format and Task 11 has ground truth.

**Files:**
- Create: `kmod/kdetect_hooktest.c`, `kmod/Makefile`

**Interfaces:**
- Produces: a module `kdetect_hooktest` that registers an ftrace hook on `__x64_sys_newuname` (a harmless syscall). Default build is **visible** (`rmmod`-able). Building with `KDETECT_HIDDEN=1` also `list_del`s the module from the kernel module list (removal then needs a reboot).

- [ ] **Step 1: Write the module source**

Create `kmod/kdetect_hooktest.c`:

```c
// SPDX-License-Identifier: GPL-2.0
// kdetect test module: registers a benign ftrace hook so the detector has
// ground truth. It does NOTHING hostile — the hook tail-calls the original.
// Build KDETECT_HIDDEN=1 to also unlink the module (the orphan-hook case);
// removal then requires a reboot, so run only under the VM snapshot discipline.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kdetect");
MODULE_DESCRIPTION("Benign ftrace-hook ground truth for kdetect phase 3a");

// The function we hook. Harmless: the uname syscall handler.
#define HOOKED_SYMBOL "__x64_sys_newuname"

static struct ftrace_ops kdetect_ops;

// ftrace callback: do nothing but hand control straight back. We deliberately
// do not alter regs->ip, so behaviour is unchanged — the point is only that a
// registered ftrace op becomes visible in enabled_functions.
static void notrace kdetect_callback(unsigned long ip, unsigned long parent_ip,
                                     struct ftrace_ops *op,
                                     struct ftrace_regs *fregs)
{
    // no-op
}

static int __init kdetect_init(void)
{
    int ret;
    unsigned long addr;
    struct kprobe kp = { .symbol_name = HOOKED_SYMBOL };

    // Resolve the address via a throwaway kprobe (the post-5.7 idiom, since
    // kallsyms_lookup_name is no longer exported).
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("kdetect_hooktest: cannot resolve %s (%d)\n", HOOKED_SYMBOL, ret);
        return ret;
    }
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);

    kdetect_ops.func = kdetect_callback;
    kdetect_ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&kdetect_ops, addr, 0, 0);
    if (ret) {
        pr_err("kdetect_hooktest: set_filter_ip failed (%d)\n", ret);
        return ret;
    }
    ret = register_ftrace_function(&kdetect_ops);
    if (ret) {
        pr_err("kdetect_hooktest: register_ftrace_function failed (%d)\n", ret);
        return ret;
    }
    pr_info("kdetect_hooktest: hooked %s\n", HOOKED_SYMBOL);

#ifdef KDETECT_HIDDEN
    // Unlink from the module list (the Diamorphine-style hide). Removal now
    // needs a reboot; run only under the snapshot discipline.
    list_del(&THIS_MODULE->list);
    pr_info("kdetect_hooktest: hidden from module list\n");
#endif
    return 0;
}

static void __exit kdetect_exit(void)
{
    unregister_ftrace_function(&kdetect_ops);
    pr_info("kdetect_hooktest: unhooked\n");
}

module_init(kdetect_init);
module_exit(kdetect_exit);
```

- [ ] **Step 2: Write the Makefile**

Create `kmod/Makefile`:

```makefile
# Build: make            (visible mode, rmmod-able)
#        make hidden     (also unlinks the module; needs a reboot to remove)
obj-m += kdetect_hooktest.o
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

hidden:
	$(MAKE) -C $(KDIR) M=$(PWD) ccflags-y="-DKDETECT_HIDDEN" modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

- [ ] **Step 3: Build and load on the VM (Angus)**

On the VM, from a `clean-baseline` snapshot with the adapter set Host-only:

```bash
cd ~/kdetect/kmod && make
sudo insmod kdetect_hooktest.ko
sudo dmesg | tail -3        # expect: "hooked __x64_sys_newuname"
cat /sys/kernel/tracing/enabled_functions   # expect __x64_sys_newuname listed
```

Expected: the module loads, `dmesg` shows the hook, and `enabled_functions` now names the hooked function. `sudo rmmod kdetect_hooktest` removes it (visible mode).

- [ ] **Step 4: Stage and hand off the commit**

`.ko`/`.o`/`.cmd` are already gitignored. Stage the source only:

```bash
git add kmod/kdetect_hooktest.c kmod/Makefile
```

Commit message for Angus:
`feat(kmod): benign ftrace-hook test module for phase 3a ground truth`

---

## Task 2: Step-0 exploration — the hook-surface format gate

**VM task (Angus), and the gate for every later schema decision.** Captures the real text of the three surfaces, clean and with the visible LKM from Task 1 loaded, and pins how `owner_module` is resolved.

**Files:**
- Create: `docs/step0-phase3/README.md`, `docs/step0-phase3/clean/*.txt`
- Create (from the LKM-loaded capture): `docs/step0-phase3/hooked/*.txt`

**Interfaces:**
- Produces: verbatim sample lines that become the parser fixtures in Task 3, and a recorded answer to: *does `enabled_functions` name the callback's owning module inline, or must it be resolved via kallsyms?* This decides the `reduce_kallsyms` / attribution path.

- [ ] **Step 1: Capture the clean surfaces (VM, root)**

```bash
K=$(uname -r); D=~/kdetect/docs/step0-phase3/clean; mkdir -p "$D"
sudo cat /sys/kernel/tracing/enabled_functions > "$D/01-enabled_functions.txt"
sudo cat /sys/kernel/debug/kprobes/list        > "$D/02-kprobes.txt"
sudo head -50 /proc/kallsyms                    > "$D/03-kallsyms-head.txt"
# module-attributed symbols only (the [mod] tag), a few for shape:
sudo grep -m 20 '\[' /proc/kallsyms             > "$D/04-kallsyms-module-tags.txt"
```

- [ ] **Step 2: Capture with the hook present (VM, root)**

With `kdetect_hooktest.ko` loaded (Task 1 Step 3):

```bash
D=~/kdetect/docs/step0-phase3/hooked; mkdir -p "$D"
sudo cat /sys/kernel/tracing/enabled_functions > "$D/01-enabled_functions.txt"
# how does the hooked function's callback line read? does it name a module?
sudo grep -A3 newuname /sys/kernel/tracing/enabled_functions > "$D/05-hooked-callback.txt"
sudo grep kdetect /proc/kallsyms > "$D/06-kdetect-symbols.txt"  # module symbols visible?
```

- [ ] **Step 3: Record findings and the format decision**

Write `docs/step0-phase3/README.md` in the style of `docs/step0-phase2/README.md`: the reproduce-by-hand commands, kernel/euid/date, and — critically — a section **"How owner_module is resolved"** stating whether the callback line carries an inline `[module]` tag or whether the callback symbol must be looked up in `reduce_kallsyms`'s symbol→module map. Note whether a clean idle VM has *any* pre-existing `enabled_functions`/`kprobes` entries (calibration for the zero-findings guard), and whether `kdetect_hooktest`'s symbols appear in `/proc/kallsyms`.

- [ ] **Step 4: Stage and hand off the commit (from the reverted clean tree)**

```bash
git add docs/step0-phase3/
```

Commit message for Angus:
`docs: phase 3a step 0 — hook-surface format evidence (clean + hooked)`

---

## Task 3: Parsers for the hook surfaces

**Files:**
- Create: `src/kdetect/parsers/kernel_hooks.py`
- Test: `tests/unit/test_parse_kernel_hooks.py`

**Interfaces:**
- Produces: `HookRow(function: str, hook_type: str, callback: str | None, owner_module: str | None)`; `parse_enabled_functions(text) -> list[HookRow]`; `parse_kprobes(text) -> list[HookRow]`; `reduce_kallsyms(text) -> dict[str, str]` (symbol name → module name, module-tagged symbols only); `KernelHookParseError(ValueError)`.
- Note: `owner_module` on the `HookRow` from `parse_enabled_functions` is populated **only** if the callback line carries an inline module tag (per Task 2 Step 3). Otherwise it stays `None` and the collector resolves it via `reduce_kallsyms`.

- [ ] **Step 1: Write the failing parser tests**

The sample lines below are the *hypothesised* format; **replace them with the verbatim lines captured in `docs/step0-phase3/hooked/` and `.../clean/` (Task 2)** before implementing, and adjust field extraction if they differ.

Create `tests/unit/test_parse_kernel_hooks.py`:

```python
import pytest
from kdetect.parsers.kernel_hooks import (
    HookRow, KernelHookParseError,
    parse_enabled_functions, parse_kprobes, reduce_kallsyms,
)

# Verbatim from docs/step0-phase3/hooked/01-enabled_functions.txt
ENABLED = """\
__x64_sys_newuname (1)
	 tramp: 0xffffffffc0451000 (kdetect_callback+0x0/0x10)
	  ->ftrace_ops_list_func+0x0/0x1a0
"""

def test_parse_enabled_functions_extracts_function_and_callback():
    rows = parse_enabled_functions(ENABLED)
    assert len(rows) == 1
    r = rows[0]
    assert r.function == "__x64_sys_newuname"
    assert r.hook_type == "ftrace"
    assert "kdetect_callback" in r.callback

def test_parse_enabled_functions_empty_is_no_rows():
    assert parse_enabled_functions("") == []

# Verbatim from docs/step0-phase3/clean/02-kprobes.txt
KPROBES = """\
ffffffff81234560  k  do_int3+0x0    [DISABLED]
ffffffffc0451000  k  __x64_sys_newuname+0x0
"""

def test_parse_kprobes_extracts_symbol():
    rows = parse_kprobes(KPROBES)
    funcs = {r.function for r in rows}
    assert "__x64_sys_newuname" in funcs
    assert all(r.hook_type == "kprobe" for r in rows)

# Verbatim from docs/step0-phase3/clean/04-kallsyms-module-tags.txt
KALLSYMS = """\
ffffffff81000000 T commit_creds
0000000000000000 t e1000_hook\t[e1000]
0000000000000000 t kdetect_callback\t[kdetect_hooktest]
"""

def test_reduce_kallsyms_maps_symbol_to_module():
    m = reduce_kallsyms(KALLSYMS)
    assert m["kdetect_callback"] == "kdetect_hooktest"
    assert m["e1000_hook"] == "e1000"
    assert "commit_creds" not in m          # no [module] tag -> core kernel

def test_reduce_kallsyms_ignores_addresses():
    # zeroed addresses (L4) must not appear anywhere in the reduced output
    m = reduce_kallsyms(KALLSYMS)
    assert all(not k.startswith("0x") for k in m)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_parse_kernel_hooks.py -v`
Expected: FAIL with `ModuleNotFoundError: kdetect.parsers.kernel_hooks`.

- [ ] **Step 3: Write the parsers**

Create `src/kdetect/parsers/kernel_hooks.py`:

```python
"""Pure parsers for the hook-surface channels (spec §4).

Text in, typed values out, no I/O. Each mirrors a file in docs/step0-phase3/
and every case in the tests is drawn from there. Addresses are never carried
out of these parsers: under L4 they read as zero unprivileged, and it is the
symbol/module names that later phases diff.
"""
from __future__ import annotations

from dataclasses import dataclass


class KernelHookParseError(ValueError):
    """A hook-surface file could not be parsed."""


@dataclass(frozen=True)
class HookRow:
    function: str
    hook_type: str                 # "ftrace" | "kprobe"
    callback: str | None           # dispatch target as the surface names it
    owner_module: str | None       # only if the surface tags it inline


def parse_enabled_functions(text: str) -> list[HookRow]:
    """Parse /sys/kernel/tracing/enabled_functions.

    A hooked function is a line that starts in column 0: "name (count)".
    Indented lines beneath it describe the ops/callback; we keep the first
    callback symbol we see. Format confirmed in docs/step0-phase3/hooked/.
    """
    rows: list[HookRow] = []
    function: str | None = None
    callback: str | None = None

    def flush() -> None:
        nonlocal function, callback
        if function is not None:
            rows.append(HookRow(function, "ftrace", callback, None))
        function, callback = None, None

    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():          # column-0 line: a new hooked function
            flush()
            function = line.split()[0]
        elif callback is None:             # first indented callback line
            # e.g. "->ftrace_ops_list_func+..." or "tramp: 0x.. (sym+0x../..)"
            if "(" in line and ")" in line:
                callback = line[line.index("(") + 1 : line.rindex(")")].split("+")[0]
            elif "->" in line:
                callback = line.split("->", 1)[1].split("+")[0].strip()
    flush()
    return rows


def parse_kprobes(text: str) -> list[HookRow]:
    """Parse /sys/kernel/debug/kprobes/list.

    Columns: <addr> <type> <symbol>+<offset> [flags...]. We keep the symbol,
    dropping the address (L4). Type letter is 'k'/'r' (kprobe/kretprobe)."""
    rows: list[HookRow] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 3:
            raise KernelHookParseError(f"short kprobes line: {line!r}")
        symbol = parts[2].split("+")[0]
        rows.append(HookRow(symbol, "kprobe", None, None))
    return rows


def reduce_kallsyms(text: str) -> dict[str, str]:
    """Map symbol name -> owning module, for module-tagged symbols only.

    A module symbol reads "<addr> <type> <name>\\t[module]"; core-kernel
    symbols have no bracket. Addresses are discarded (L4). This is the map the
    collector uses to attribute a callback symbol to a module."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.rstrip()
        if not (stripped.endswith("]") and "[" in stripped):
            continue
        module = stripped[stripped.rindex("[") + 1 : -1]
        parts = stripped.split()
        if len(parts) >= 3:
            out[parts[2]] = module
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_parse_kernel_hooks.py -v`
Expected: PASS (5 tests). If a case fails against the real Task-2 capture, adjust the parser to the captured format — the capture is authoritative.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/parsers/kernel_hooks.py tests/unit/test_parse_kernel_hooks.py
```

Commit message for Angus:
`feat(parsers): hook-surface parsers (enabled_functions, kprobes, kallsyms)`

---

## Task 4: KernelHookSource — the hook-surface channels

**Files:**
- Modify: `src/kdetect/collectors/base.py`, `src/kdetect/collectors/sources.py`
- Test: `tests/unit/test_kernel_hook_source.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (parsers are used by the collector, not the source).
- Produces: `KernelHookSource(ABC)` with `read_enabled_functions() -> str | None`, `read_kprobes() -> str | None`, `read_kallsyms_index() -> str | None`; `LiveKernelHookSource` (reads the real files, `None` on `OSError`); `FixtureKernelHookSource(root)` (reads `enabled_functions.txt`/`kprobes.txt`/`kallsyms.txt`, missing file → `None`).

- [ ] **Step 1: Write the failing source tests**

Create `tests/unit/test_kernel_hook_source.py`:

```python
from kdetect.collectors.sources import FixtureKernelHookSource

def test_fixture_reads_present_files(tmp_path):
    (tmp_path / "enabled_functions.txt").write_text("foo (1)\n")
    (tmp_path / "kprobes.txt").write_text("addr k foo+0x0\n")
    (tmp_path / "kallsyms.txt").write_text("addr t foo\t[bar]\n")
    src = FixtureKernelHookSource(tmp_path)
    assert src.read_enabled_functions() == "foo (1)\n"
    assert "foo" in src.read_kprobes()
    assert "[bar]" in src.read_kallsyms_index()

def test_fixture_missing_file_reads_none(tmp_path):
    src = FixtureKernelHookSource(tmp_path)      # empty dir
    assert src.read_enabled_functions() is None
    assert src.read_kprobes() is None
    assert src.read_kallsyms_index() is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_kernel_hook_source.py -v`
Expected: FAIL with `ImportError: cannot import name 'FixtureKernelHookSource'`.

- [ ] **Step 3: Add the ABC and implementations**

Add to `src/kdetect/collectors/base.py` (after `ModuleSource`):

```python
class KernelHookSource(ABC):
    """The hook-surface channels (spec §4). enabled_functions and kprobes are
    what modern LKM rootkits light up; kallsyms attributes a callback symbol to
    a module. A channel that cannot be read returns None, and the collector
    records its absence rather than treating it as agreement."""

    @abstractmethod
    def read_enabled_functions(self) -> str | None: ...
    @abstractmethod
    def read_kprobes(self) -> str | None: ...
    @abstractmethod
    def read_kallsyms_index(self) -> str | None: ...
```

Add to `src/kdetect/collectors/sources.py` (import `KernelHookSource` from `base`):

```python
class LiveKernelHookSource(KernelHookSource):
    _ENABLED = ("/sys/kernel/tracing/enabled_functions",
                "/sys/kernel/debug/tracing/enabled_functions")
    _KPROBES = ("/sys/kernel/debug/kprobes/list",
                "/sys/kernel/tracing/kprobes/list")

    @staticmethod
    def _try(paths) -> str | None:
        for p in paths:
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except OSError:
                continue
        return None

    def read_enabled_functions(self) -> str | None:
        return self._try(self._ENABLED)

    def read_kprobes(self) -> str | None:
        return self._try(self._KPROBES)

    def read_kallsyms_index(self) -> str | None:
        try:
            with open("/proc/kallsyms", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None


class FixtureKernelHookSource(KernelHookSource):
    """Replays a captured hook tree; a missing file replays 'unreadable'."""

    def __init__(self, root) -> None:
        self._root = Path(root)

    def _read(self, name: str) -> str | None:
        p = self._root / name
        return p.read_text(encoding="utf-8") if p.exists() else None

    def read_enabled_functions(self) -> str | None:
        return self._read("enabled_functions.txt")

    def read_kprobes(self) -> str | None:
        return self._read("kprobes.txt")

    def read_kallsyms_index(self) -> str | None:
        return self._read("kallsyms.txt")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_kernel_hook_source.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/collectors/base.py src/kdetect/collectors/sources.py tests/unit/test_kernel_hook_source.py
```

Commit message for Angus:
`feat(collectors): KernelHookSource with live and fixture implementations`

---

## Task 5: HookEntity and the Observation registry

**Files:**
- Modify: `src/kdetect/models.py`
- Test: `tests/unit/test_hook_entity.py`, `tests/unit/test_models_roundtrip.py` (extend)

**Interfaces:**
- Consumes: nothing.
- Produces: `HookEntity(function: str, hook_type: str, callback: str | None, owner_module: str | None)` with `to_dict`/`from_dict`; `"kernel.hooks"` registered in `_ENTITY_TYPES` (→ `HookEntity`) and `_STRING_ID_COLLECTORS`. **No `attributable` field** — that is derived by the differ (P1/P4).

- [ ] **Step 1: Write the failing entity tests**

Create `tests/unit/test_hook_entity.py`:

```python
from kdetect.models import HookEntity, Observation, Status, TrustLevel

def test_hook_entity_roundtrips():
    e = HookEntity(function="__x64_sys_newuname", hook_type="ftrace",
                   callback="kdetect_callback", owner_module="kdetect_hooktest")
    assert HookEntity.from_dict(e.to_dict()) == e

def test_hook_entity_null_owner_module():
    e = HookEntity(function="ip_rcv", hook_type="ftrace",
                   callback="0xdeadbeef", owner_module=None)
    assert HookEntity.from_dict(e.to_dict()).owner_module is None

def test_kernel_hooks_observation_uses_string_ids():
    obs = Observation(
        collector="kernel.hooks", collector_version="1", view="kernel_hooks",
        trust_level=TrustLevel.MEDIUM, status=Status.OK, duration_ms=1,
        entity_ids=["ftrace:__x64_sys_newuname"],
        entities={"ftrace:__x64_sys_newuname": HookEntity(
            "__x64_sys_newuname", "ftrace", "kdetect_callback", "kdetect_hooktest")},
        stats={}, errors=[],
    )
    back = Observation.from_dict(obs.to_dict())
    assert back == obs
    assert list(back.entities.keys()) == ["ftrace:__x64_sys_newuname"]  # stayed str
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_hook_entity.py -v`
Expected: FAIL with `ImportError: cannot import name 'HookEntity'`.

- [ ] **Step 3: Add the entity and register it**

Add to `src/kdetect/models.py` (after `ModuleEntity`):

```python
@dataclass(frozen=True)
class HookEntity:
    """One hooked kernel function, as observed on a hook surface (spec §4.2).

    Evidence only (P1): the function, the surface it came from, the callback the
    surface names, and the module that callback attributes to (or None). Whether
    that makes it an ORPHAN hook is a conclusion the differ draws (P4), so there
    is deliberately no `attributable` field here.
    """

    function: str
    hook_type: str                 # "ftrace" | "kprobe"
    callback: str | None
    owner_module: str | None

    def to_dict(self) -> dict:
        return {
            "function": self.function, "hook_type": self.hook_type,
            "callback": self.callback, "owner_module": self.owner_module,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HookEntity":
        return cls(
            function=d["function"], hook_type=d["hook_type"],
            callback=d["callback"], owner_module=d["owner_module"],
        )
```

Register it in the two lookup tables:

```python
_ENTITY_TYPES = {
    "procfs.processes": ProcessEntity,
    "syscall_sweep.processes": SweepEntity,
    "procfs.modules": ModuleEntity,
    "kernel.module_evidence": None,
    "kernel.hooks": HookEntity,           # NEW
}

_STRING_ID_COLLECTORS = frozenset({"procfs.modules", "kernel.hooks"})  # + kernel.hooks
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_hook_entity.py tests/unit/test_models_roundtrip.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/models.py tests/unit/test_hook_entity.py
```

Commit message for Angus:
`feat(models): HookEntity and kernel.hooks registry entries`

---

## Task 6: The kernel.hooks collector

**Files:**
- Create: `src/kdetect/collectors/kernel_hooks.py`
- Test: `tests/unit/test_collector_kernel_hooks.py`
- Fixtures: `tests/fixtures/hook-trees/clean/`, `.../hooked/`

**Interfaces:**
- Consumes: `KernelHookSource` (Task 4); `parse_enabled_functions`, `parse_kprobes`, `reduce_kallsyms`, `HookRow` (Task 3); `HookEntity`, `Observation` (Task 5).
- Produces: `KernelHookCollector` with `name="kernel.hooks"`, `view="kernel_hooks"`, `trust_level=MEDIUM`, `version="1"`, `collect(source) -> Observation`. Entity id is `f"{hook_type}:{function}"`. `owner_module` filled from the row's inline tag, else resolved via `reduce_kallsyms(callback)`. `extra={"kallsyms_modules": [...]}` holds the set of module namespaces seen in kallsyms; `stats` records channel availability.

- [ ] **Step 1: Create the fixtures**

Copy the small verbatim captures from Task 2 into the fixture tree (or hand-author to match). `tests/fixtures/hook-trees/clean/`:
- `enabled_functions.txt` — empty or the clean baseline (per Task 2's calibration note).
- `kprobes.txt` — the clean kprobe list.
- `kallsyms.txt` — a handful of module-tagged lines including at least one real module.

`tests/fixtures/hook-trees/hooked/` — the same three with `kdetect_hooktest`'s hook present:
```
# enabled_functions.txt
__x64_sys_newuname (1)
	 tramp: 0xffffffffc0451000 (kdetect_callback+0x0/0x10)
```
```
# kallsyms.txt   (callback attributes to the module)
0000000000000000 t kdetect_callback	[kdetect_hooktest]
```

- [ ] **Step 2: Write the failing collector tests**

Create `tests/unit/test_collector_kernel_hooks.py`:

```python
from pathlib import Path
from kdetect.collectors.kernel_hooks import KernelHookCollector
from kdetect.collectors.sources import FixtureKernelHookSource
from kdetect.models import Observation, TrustLevel

CLEAN = Path(__file__).parent.parent / "fixtures" / "hook-trees" / "clean"
HOOKED = Path(__file__).parent.parent / "fixtures" / "hook-trees" / "hooked"

def test_collector_attributes_hook_to_its_module():
    obs = KernelHookCollector().collect(FixtureKernelHookSource(HOOKED))
    assert obs.trust_level is TrustLevel.MEDIUM
    assert obs.view == "kernel_hooks"
    e = obs.entities["ftrace:__x64_sys_newuname"]
    assert e.callback and "kdetect_callback" in e.callback
    assert e.owner_module == "kdetect_hooktest"

def test_collector_records_absent_channel_as_unavailable(tmp_path):
    # no files at all -> channels unavailable, no entities, still status OK
    obs = KernelHookCollector().collect(FixtureKernelHookSource(tmp_path))
    assert obs.entity_ids == []
    assert obs.stats["enabled_functions_available"] is False

def test_collector_observation_round_trips():
    obs = KernelHookCollector().collect(FixtureKernelHookSource(HOOKED))
    assert Observation.from_dict(obs.to_dict()) == obs
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_collector_kernel_hooks.py -v`
Expected: FAIL with `ModuleNotFoundError: kdetect.collectors.kernel_hooks`.

- [ ] **Step 4: Write the collector**

Create `src/kdetect/collectors/kernel_hooks.py`:

```python
"""The hook-surface collector (spec §4.2).

kernel.hooks (MEDIUM) records what is hooked and, where it can, which module a
hook's callback belongs to. It never decides whether a hook is an orphan — that
is the differ's job (P4). A callback whose module cannot be found is recorded
with owner_module=None; the differ reads that as the orphan signal.
"""
from __future__ import annotations

import time

from kdetect.collectors.base import KernelHookSource
from kdetect.models import HookEntity, Observation, Status, TrustLevel
from kdetect.parsers.kernel_hooks import (
    parse_enabled_functions, parse_kprobes, reduce_kallsyms,
)


class KernelHookCollector:
    name = "kernel.hooks"
    view = "kernel_hooks"
    trust_level = TrustLevel.MEDIUM
    version = "1"

    def collect(self, source: KernelHookSource) -> Observation:
        started = time.monotonic()

        kallsyms_text = source.read_kallsyms_index()
        sym_to_mod = reduce_kallsyms(kallsyms_text) if kallsyms_text else {}

        enabled = source.read_enabled_functions()
        kprobes = source.read_kprobes()

        rows = []
        if enabled is not None:
            rows += parse_enabled_functions(enabled)
        if kprobes is not None:
            rows += parse_kprobes(kprobes)

        entities: dict[str, HookEntity] = {}
        for r in rows:
            # Prefer an inline module tag; else attribute the callback symbol
            # via kallsyms. Either may be None -> the orphan signal for the differ.
            owner = r.owner_module
            if owner is None and r.callback:
                owner = sym_to_mod.get(r.callback)
            key = f"{r.hook_type}:{r.function}"
            entities[key] = HookEntity(r.function, r.hook_type, r.callback, owner)

        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=sorted(entities), entities=entities,
            stats={
                "enabled_functions_available": enabled is not None,
                "kprobes_available": kprobes is not None,
                "kallsyms_available": kallsyms_text is not None,
                "hooks": len(entities),
            },
            extra={"kallsyms_modules": sorted(set(sym_to_mod.values()))},
            errors=[],
        )
```

- [ ] **Step 5: Run tests, then commit**

Run: `python -m pytest tests/unit/test_collector_kernel_hooks.py -v`
Expected: PASS (3 tests).

```bash
git add src/kdetect/collectors/kernel_hooks.py tests/unit/test_collector_kernel_hooks.py tests/fixtures/hook-trees/
```

Commit message for Angus:
`feat(collectors): kernel.hooks collector with kallsyms attribution`

---

## Task 7: Finding kinds and the orphan-hook differ

**Files:**
- Modify: `src/kdetect/analysis/models.py`, `src/kdetect/analysis/crossview.py`
- Test: `tests/unit/test_diff_hooks.py`

**Interfaces:**
- Consumes: `Snapshot`, the `kernel_hooks` and `procfs.modules` observations; `_observations`, `_confidence` (existing in `crossview.py`).
- Produces: `FindingKind.UNEXPECTED_HOOK`, `FindingKind.BASELINE_DRIFT` (added to the enum now; `BASELINE_DRIFT` is used in Task 8); `diff_hooks(snapshot, baseline=None) -> list[Finding]`; `diff_all(snapshot, baseline=None)` now also calls `diff_hooks`. **`attributable` is derived here:** a hook is an orphan when `owner_module` is `None`, or is set but not among the modules listed by `procfs.modules`. Corroboration count = orphan-hit + drift-hit (drift only when a baseline is given).

- [ ] **Step 1: Add the new FindingKinds**

Edit `src/kdetect/analysis/models.py`:

```python
class FindingKind(str, Enum):
    HIDDEN_PROCESS = "hidden_process"
    MODULE_TAINT_MISMATCH = "module_taint_mismatch"
    UNEXPLAINED_MODULE_REGION = "unexplained_module_region"
    FTRACE_ORPHAN_MODULE = "ftrace_orphan_module"
    UNEXPECTED_HOOK = "unexpected_hook"            # NEW
    BASELINE_DRIFT = "baseline_drift"              # NEW
```

- [ ] **Step 2: Write the failing differ tests**

Create `tests/unit/test_diff_hooks.py`:

```python
from kdetect.analysis.crossview import diff_hooks
from kdetect.analysis.models import Confidence, FindingKind
from kdetect.models import (
    HookEntity, ModuleEntity, Observation, Snapshot, Status, TrustLevel,
    CaptureMeta, HostFacts, SCHEMA_VERSION,
)

def _host():
    return HostFacts(hostname="t", kernel_release="6.1", arch="x86_64",
                     boot_id="b", btime=1, clock_ticks_per_sec=100)

def _snap(hook_entities, listed_modules):
    hooks = Observation(
        collector="kernel.hooks", collector_version="1", view="kernel_hooks",
        trust_level=TrustLevel.MEDIUM, status=Status.OK, duration_ms=1,
        entity_ids=sorted(hook_entities), entities=hook_entities,
        stats={}, errors=[], extra={"kallsyms_modules": []},
    )
    mods = Observation(
        collector="procfs.modules", collector_version="1", view="modules",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(listed_modules),
        entities={m: ModuleEntity(m, 1, 0, [], "Live", "0x0", None)
                  for m in listed_modules},
        stats={}, errors=[],
    )
    return Snapshot(SCHEMA_VERSION, "id", "t", _host(),
                    CaptureMeta("0.1.0", 0), [hooks, mods])

def test_orphan_hook_fires_without_baseline():
    # callback owned by a module NOT in the listing -> orphan
    ents = {"ftrace:sys_x": HookEntity("sys_x", "ftrace", "evil", "hidden_mod")}
    findings = diff_hooks(_snap(ents, listed_modules=["ext4"]))
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.UNEXPECTED_HOOK
    assert f.confidence is Confidence.LOW          # one channel (orphan only)
    assert f.evidence["owner_module"] == "hidden_mod"

def test_attributable_hook_does_not_fire():
    ents = {"ftrace:sys_x": HookEntity("sys_x", "ftrace", "cb", "ext4")}
    assert diff_hooks(_snap(ents, listed_modules=["ext4"])) == []

def test_orphan_plus_baseline_drift_is_medium():
    ents = {"ftrace:sys_x": HookEntity("sys_x", "ftrace", "evil", None)}
    current = _snap(ents, listed_modules=["ext4"])
    baseline = _snap({}, listed_modules=["ext4"])   # hook absent when clean
    findings = diff_hooks(current, baseline)
    assert findings[0].confidence is Confidence.MEDIUM   # orphan + drift
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_diff_hooks.py -v`
Expected: FAIL with `ImportError: cannot import name 'diff_hooks'`.

- [ ] **Step 4: Write `diff_hooks` and thread it through `diff_all`**

Add to `src/kdetect/analysis/crossview.py`:

```python
def _hook_ids(snapshot: Snapshot) -> set[str]:
    obs = _observations(snapshot, "kernel.hooks")
    return set(obs[0].entity_ids) if obs else set()


def diff_hooks(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Finding]:
    """UNEXPECTED_HOOK: a hooked function whose callback belongs to no listed
    module (orphan, intra-snapshot), and/or a hook absent from the baseline.

    attributable is DERIVED here (P4): owner_module None, or set but not among
    the modules procfs.modules lists, means the hook is an orphan."""
    hook_obs = _observations(snapshot, "kernel.hooks")
    if not hook_obs:
        return []
    hooks = hook_obs[0]

    module_obs = _observations(snapshot, "procfs.modules")
    listed = set(module_obs[0].entity_ids) if module_obs else set()
    baseline_hooks = _hook_ids(baseline) if baseline is not None else None

    findings: list[Finding] = []
    for key in hooks.entity_ids:
        ent = hooks.entities[key]
        orphan = ent.owner_module is None or ent.owner_module not in listed
        drift = baseline_hooks is not None and key not in baseline_hooks
        corroboration = sum([orphan, drift])
        if corroboration == 0:
            continue
        agree, dissent = [], []
        if orphan:
            agree.append("kernel.hooks callback attribution")
            dissent.append("procfs.modules listing")
        if drift:
            agree.append("baseline (hook absent when clean)")
        findings.append(Finding(
            FindingKind.UNEXPECTED_HOOK, f"{ent.hook_type} hook on {ent.function}",
            _confidence(corroboration), agree, dissent,
            {"function": ent.function, "hook_type": ent.hook_type,
             "callback": ent.callback, "owner_module": ent.owner_module,
             "in_listing": ent.owner_module in listed if ent.owner_module else False,
             "new_vs_baseline": bool(drift)},
            f"{ent.hook_type} hook on {ent.function} "
            f"({'callback in no listed module' if orphan else 'new since baseline'})",
        ))
    return sorted(findings, key=lambda f: f.subject)
```

Change `diff_all`:

```python
def diff_all(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Finding]:
    findings = (diff_processes(snapshot) + diff_modules(snapshot)
                + diff_hooks(snapshot, baseline))
    if baseline is not None:
        from kdetect.analysis import baseline_diff       # Task 8
        findings += baseline_diff.diff(snapshot, baseline)
    return findings
```

- [ ] **Step 5: Run tests, then commit**

Run: `python -m pytest tests/unit/test_diff_hooks.py -v`
Expected: PASS (3 tests). The `baseline_diff` import in `diff_all` is only reached when a baseline is passed, so it does not break until Task 8 — but do not run `diff_all(snap, baseline)` before Task 8.

```bash
git add src/kdetect/analysis/models.py src/kdetect/analysis/crossview.py tests/unit/test_diff_hooks.py
```

Commit message for Angus:
`feat(analysis): orphan-hook differ and UNEXPECTED_HOOK/BASELINE_DRIFT kinds`

---

## Task 8: The signed baseline store

**Files:**
- Create: `src/kdetect/baseline/store.py`
- Modify: `pyproject.toml`
- Test: `tests/unit/test_baseline_store.py`

**Interfaces:**
- Consumes: `Snapshot` (`to_json`, `from_dict`).
- Produces: `BaselineTampered(Exception)`; `load_private_key(path) -> Ed25519PrivateKey`; `load_public_key(path) -> Ed25519PublicKey`; `write_baseline(snapshot: Snapshot, out_path: Path, private_key) -> None` (writes `<out>.json` and `<out>.json.sig`); `load_baseline(json_path: Path, public_key) -> Snapshot` (verifies before parsing, raises `BaselineTampered` on mismatch).

- [ ] **Step 1: Add the dependency**

Edit `pyproject.toml`:

```toml
dependencies = ["cryptography>=42"]
```

Install into the venv: `python -m pip install -e .`

- [ ] **Step 2: Write the failing store tests**

Create `tests/unit/test_baseline_store.py`:

```python
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kdetect.baseline.store import (
    BaselineTampered, write_baseline, load_baseline,
)
from kdetect.models import (
    Snapshot, HostFacts, CaptureMeta, SCHEMA_VERSION,
)

def _snap():
    host = HostFacts("t", "6.1", "x86_64", "b", 1, 100)
    return Snapshot(SCHEMA_VERSION, "id", "t", host, CaptureMeta("0.1.0", 0), [])

def test_write_then_load_roundtrips(tmp_path):
    key = Ed25519PrivateKey.generate()
    out = tmp_path / "clean.json"
    write_baseline(_snap(), out, key)
    assert out.exists() and (tmp_path / "clean.json.sig").exists()
    loaded = load_baseline(out, key.public_key())
    assert loaded.snapshot_id == "id"

def test_tampered_json_is_refused(tmp_path):
    key = Ed25519PrivateKey.generate()
    out = tmp_path / "clean.json"
    write_baseline(_snap(), out, key)
    out.write_text(out.read_text().replace('"id"', '"forged"'))   # edit after signing
    with pytest.raises(BaselineTampered):
        load_baseline(out, key.public_key())

def test_wrong_key_is_refused(tmp_path):
    write_baseline(_snap(), tmp_path / "clean.json", Ed25519PrivateKey.generate())
    other = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(BaselineTampered):
        load_baseline(tmp_path / "clean.json", other)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_baseline_store.py -v`
Expected: FAIL with `ModuleNotFoundError: kdetect.baseline.store`.

- [ ] **Step 4: Write the store**

Create `src/kdetect/baseline/store.py`:

```python
"""The signed baseline store (spec §6).

A baseline is an ordinary snapshot (P6) plus a detached ed25519 signature over
the exact bytes of its .json. Verification precedes trust (P7): load_baseline
checks the signature before json.loads, so a tampered baseline is refused, not
analysed. On-host verification only defeats an attacker without the signing key
(L18); keep the private key off-host.
"""
from __future__ import annotations

import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from kdetect.models import Snapshot


class BaselineTampered(Exception):
    """A baseline's signature did not verify against the given public key."""


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an ed25519 public key")
    return key


def _sig_path(json_path: Path) -> Path:
    return Path(str(json_path) + ".sig")


def write_baseline(snapshot: Snapshot, out_path: Path, private_key) -> None:
    """Write <out_path> (the snapshot) and <out_path>.sig (detached signature).

    The signed bytes are exactly the bytes written, so verification reads the
    same file back and needs no re-serialisation."""
    out_path = Path(out_path)
    data = snapshot.to_json(pretty=False).encode("utf-8")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    _sig_path(out_path).write_bytes(private_key.sign(data))


def load_baseline(json_path: Path, public_key) -> Snapshot:
    """Verify the detached signature, THEN parse (P7)."""
    json_path = Path(json_path)
    data = json_path.read_bytes()
    try:
        signature = _sig_path(json_path).read_bytes()
    except OSError as exc:
        raise BaselineTampered(f"missing signature for {json_path}") from exc
    try:
        public_key.verify(signature, data)
    except InvalidSignature as exc:
        raise BaselineTampered(f"signature mismatch for {json_path}") from exc
    return Snapshot.from_dict(json.loads(data))
```

Create the empty package marker if needed: `src/kdetect/baseline/__init__.py` already exists.

- [ ] **Step 5: Run tests, then commit**

Run: `python -m pytest tests/unit/test_baseline_store.py -v`
Expected: PASS (3 tests).

```bash
git add pyproject.toml src/kdetect/baseline/store.py tests/unit/test_baseline_store.py
```

Commit message for Angus:
`feat(baseline): ed25519-signed baseline store with verify-before-parse`

---

## Task 9: The baseline-diff pass (module-view drift)

**Files:**
- Create: `src/kdetect/analysis/baseline_diff.py`
- Test: `tests/unit/test_baseline_diff.py`

**Interfaces:**
- Consumes: `Snapshot`, `_observations` (import from `crossview`), `Finding`, `FindingKind.BASELINE_DRIFT`, `Confidence`.
- Produces: `diff(current: Snapshot, baseline: Snapshot) -> list[Finding]` — BASELINE_DRIFT for modules present now but absent from the baseline (MEDIUM: a new module is a stronger signal than a removed one), and removed modules at LOW (informational). The `kernel_hooks` view is handled by `diff_hooks` (Task 7), not here, to avoid double-reporting.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_baseline_diff.py`:

```python
from kdetect.analysis import baseline_diff
from kdetect.analysis.models import Confidence, FindingKind
from kdetect.models import (
    ModuleEntity, Observation, Snapshot, Status, TrustLevel,
    CaptureMeta, HostFacts, SCHEMA_VERSION,
)

def _snap(modules):
    obs = Observation(
        collector="procfs.modules", collector_version="1", view="modules",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(modules),
        entities={m: ModuleEntity(m, 1, 0, [], "Live", "0x0", None) for m in modules},
        stats={}, errors=[],
    )
    host = HostFacts("t", "6.1", "x86_64", "b", 1, 100)
    return Snapshot(SCHEMA_VERSION, "id", "t", host, CaptureMeta("0.1.0", 0), [obs])

def test_added_module_is_medium_drift():
    findings = baseline_diff.diff(_snap(["ext4", "evil"]), _snap(["ext4"]))
    added = [f for f in findings if f.evidence["direction"] == "added"]
    assert len(added) == 1
    assert added[0].kind is FindingKind.BASELINE_DRIFT
    assert added[0].confidence is Confidence.MEDIUM
    assert added[0].subject == "module evil"

def test_removed_module_is_low_informational():
    findings = baseline_diff.diff(_snap(["ext4"]), _snap(["ext4", "gone"]))
    removed = [f for f in findings if f.evidence["direction"] == "removed"]
    assert removed[0].confidence is Confidence.LOW

def test_identical_is_no_findings():
    assert baseline_diff.diff(_snap(["ext4"]), _snap(["ext4"])) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_baseline_diff.py -v`
Expected: FAIL with `ModuleNotFoundError: kdetect.analysis.baseline_diff`.

- [ ] **Step 3: Write the pass**

Create `src/kdetect/analysis/baseline_diff.py`:

```python
"""Baseline-diff: current-vs-known-good drift (spec §5.1).

Pure: (current, baseline) -> [Finding]. Compares module-view entity ids only
(the differ compares ids, never entity detail — P2). Additions are the signal;
removals are informational, since a rootkit adds capability far more often than
it removes it. The kernel_hooks view is handled by diff_hooks, not here.
"""
from __future__ import annotations

from kdetect.analysis.crossview import _observations
from kdetect.analysis.models import Confidence, Finding, FindingKind
from kdetect.models import Snapshot


def _module_ids(snapshot: Snapshot) -> set[str]:
    obs = _observations(snapshot, "procfs.modules")
    return set(obs[0].entity_ids) if obs else set()


def diff(current: Snapshot, baseline: Snapshot) -> list[Finding]:
    now = _module_ids(current)
    was = _module_ids(baseline)
    findings: list[Finding] = []

    for name in sorted(now - was):
        findings.append(Finding(
            FindingKind.BASELINE_DRIFT, f"module {name}", Confidence.MEDIUM,
            ["current capture"], ["signed baseline"],
            {"view": "modules", "subject": name, "direction": "added"},
            f"module {name} is loaded now but was absent from the baseline",
        ))
    for name in sorted(was - now):
        findings.append(Finding(
            FindingKind.BASELINE_DRIFT, f"module {name}", Confidence.LOW,
            ["signed baseline"], ["current capture"],
            {"view": "modules", "subject": name, "direction": "removed"},
            f"module {name} was in the baseline but is not loaded now",
        ))
    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_baseline_diff.py tests/unit/test_diff_hooks.py -v`
Expected: PASS (both suites; confirms the `diff_all` baseline import in Task 7 now resolves).

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/analysis/baseline_diff.py tests/unit/test_baseline_diff.py
```

Commit message for Angus:
`feat(analysis): baseline-diff pass for module-view drift`

---

## Task 10: Wire capture and analyze

**Files:**
- Modify: `src/kdetect/cli.py`
- Test: `tests/unit/test_analyze.py` (extend), `tests/integration/test_capture.py` (extend)

**Interfaces:**
- Consumes: `KernelHookCollector`, `LiveKernelHookSource`; `write_baseline`, `load_baseline`, `load_private_key`, `load_public_key`, `BaselineTampered`; `diff_all(snapshot, baseline)`.
- Produces: `capture` emits a sixth observation (`kernel.hooks`); a new `baseline` subcommand (`<snapshot> --out <path> --sign-key <path>`); `analyze` gains `--baseline <path>` and `--verify-key <path>`, runs `diff_all(snapshot, baseline)`, and exits 1 with `BaselineTampered`.

- [ ] **Step 1: Write the failing CLI tests**

Add to `tests/unit/test_analyze.py`:

```python
def test_analyze_with_tampered_baseline_exits_1(tmp_path, capsys, monkeypatch):
    # a baseline whose signature will not verify -> exit 1, no analysis
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from kdetect.baseline.store import write_baseline
    from kdetect.cli import main
    # build a minimal valid snapshot file to analyze (reuse an existing fixture)
    import shutil, pathlib
    fixture = pathlib.Path("tests/fixtures/snapshots/clean-phase2.json")
    snap = tmp_path / "snap.json"; shutil.copy(fixture, snap)
    # a baseline signed by key A, verified with key B -> BaselineTampered
    key_a = Ed25519PrivateKey.generate()
    from kdetect.models import Snapshot
    base = tmp_path / "base.json"
    write_baseline(Snapshot.from_dict(__import__("json").loads(snap.read_text())),
                   base, key_a)
    key_b_pub = tmp_path / "b.pub.pem"
    key_b_pub.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    rc = main(["analyze", str(snap), "--baseline", str(base),
               "--verify-key", str(key_b_pub)])
    assert rc == 1
    assert "baseline" in capsys.readouterr().err.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_analyze.py -k tampered -v`
Expected: FAIL (`--baseline` is an unrecognised argument).

- [ ] **Step 3: Wire the CLI**

In `src/kdetect/cli.py`:

Add the collector to the capture sandwich:

```python
from kdetect.collectors.kernel_hooks import KernelHookCollector
from kdetect.collectors.sources import (
    LiveKernelHookSource, LiveModuleSource, LiveProcSource, LiveSignalSource,
)
# ... inside cmd_capture, after the module collectors:
    hooks = LiveKernelHookSource()
    observations = [
        ProcfsProcessCollector(pass_label="A").collect(procs),
        SweepProcessCollector().collect(signals),
        ProcfsProcessCollector(pass_label="B").collect(procs),
        ProcfsModuleCollector().collect(mods),
        ModuleEvidenceCollector().collect(mods),
        KernelHookCollector().collect(hooks),                 # NEW
    ]
```

Add a `cmd_baseline`:

```python
def cmd_baseline(args) -> int:
    from kdetect.baseline.store import write_baseline, load_private_key
    try:
        raw = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        snapshot = Snapshot.from_dict(raw)
    except (OSError, json.JSONDecodeError, IncompatibleSnapshot) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    write_baseline(snapshot, Path(args.out), load_private_key(Path(args.sign_key)))
    print(f"{args.out}\n{args.out}.sig")
    return EXIT_OK
```

In `cmd_analyze`, load and verify the baseline before diffing:

```python
    baseline = None
    if getattr(args, "baseline", None):
        from kdetect.baseline.store import load_baseline, load_public_key, BaselineTampered
        if not args.verify_key:
            print("error: --baseline requires --verify-key", file=sys.stderr)
            return EXIT_ERROR
        try:
            baseline = load_baseline(Path(args.baseline), load_public_key(Path(args.verify_key)))
        except BaselineTampered as exc:
            print(f"error: baseline verification failed: {exc}", file=sys.stderr)
            return EXIT_ERROR

    findings = diff_all(snapshot, baseline)
```

Register the parsers in `main`:

```python
    base = subparsers.add_parser("baseline", help="Sign a snapshot as a baseline.")
    base.add_argument("snapshot")
    base.add_argument("--out", required=True)
    base.add_argument("--sign-key", required=True)

    analyze.add_argument("--baseline", help="Signed baseline to diff against.")
    analyze.add_argument("--verify-key", help="ed25519 public key (PEM) for --baseline.")
    # ... and dispatch:
    if args.command == "baseline":
        return cmd_baseline(args)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_analyze.py -v`
Expected: PASS, including the tampered-baseline case (exit 1).

- [ ] **Step 5: Commit**

```bash
git add src/kdetect/cli.py tests/unit/test_analyze.py tests/integration/test_capture.py
```

Commit message for Angus:
`feat(cli): kernel.hooks in capture; baseline subcommand; analyze --baseline`

---

## Task 11: Live validation, fixtures, regression guard, and docs

**VM task (Angus), following the snapshot discipline.** Proves the whole chain on real ground truth, adds the zero-findings regression guard, and writes the limitation and detection docs. The implementer prepares the commands and assertions; Angus performs the runs and commits from a reverted clean tree.

**Files:**
- Create: `tests/integration/test_phase3a_live.py`, `tests/fixtures/snapshots/clean-phase3a.json`, `tests/fixtures/snapshots/infected-hooktest.json`, `tests/fixtures/baselines/` set, `tests/fixtures/hook-trees/orphan/`
- Modify: `docs/limitations.md`, `docs/detection-methods.md`, `docs/architecture.md`

**Interfaces:**
- Consumes: everything above.
- Produces: a passing live test (gated `@needs_procfs`), a committed clean baseline + capture that produce **zero findings**, an infected capture whose analysis reports `UNEXPECTED_HOOK`, and updated docs (L18, §10 rewrite).

- [ ] **Step 1: Generate a keypair and a clean baseline (VM, root, clean snapshot)**

```bash
openssl genpkey -algorithm ed25519 -out ~/baseline_ed25519.pem
openssl pkey -in ~/baseline_ed25519.pem -pubout -out ~/baseline_ed25519.pub.pem
sudo kdetect capture --out clean.json
kdetect baseline clean.json --out clean-baseline.json --sign-key ~/baseline_ed25519.pem
kdetect analyze clean.json --baseline clean-baseline.json --verify-key ~/baseline_ed25519.pub.pem
```

Expected: **findings: none**, exit 0. Copy `clean.json` to `tests/fixtures/snapshots/clean-phase3a.json` (redact per L13). Copy the signed baseline + public key into `tests/fixtures/baselines/` (a fixture key only — never a real signing key).

- [ ] **Step 2: Infected run (VM, root, `infected-hooktest` snapshot, Host-only)**

```bash
cd ~/kdetect/kmod && make && sudo insmod kdetect_hooktest.ko
sudo kdetect capture --out infected.json
kdetect analyze infected.json --baseline clean-baseline.json --verify-key ~/baseline_ed25519.pub.pem
```

Expected: an `UNEXPECTED_HOOK` on `__x64_sys_newuname`, at MEDIUM (orphan or drift) or HIGH if both fire. Record the actual confidence and channels. Copy `infected.json` to `tests/fixtures/snapshots/infected-hooktest.json` (redact per L13).

- [ ] **Step 3: Write the live + regression tests**

Create `tests/integration/test_phase3a_live.py`:

```python
import json
from pathlib import Path
import pytest
from tests.conftest import needs_procfs
from kdetect.models import Snapshot
from kdetect.analysis.crossview import diff_all

FIX = Path(__file__).parent.parent / "fixtures" / "snapshots"

def test_clean_phase3a_has_no_findings():
    snap = Snapshot.from_dict(json.loads((FIX / "clean-phase3a.json").read_text()))
    assert diff_all(snap) == []            # the regression guard (no baseline)

def test_infected_hooktest_reports_unexpected_hook():
    snap = Snapshot.from_dict(json.loads((FIX / "infected-hooktest.json").read_text()))
    kinds = {f.kind.value for f in diff_all(snap)}
    assert "unexpected_hook" in kinds

@needs_procfs
def test_live_capture_includes_kernel_hooks():
    from kdetect.collectors.kernel_hooks import KernelHookCollector
    from kdetect.collectors.sources import LiveKernelHookSource
    obs = KernelHookCollector().collect(LiveKernelHookSource())
    assert obs.collector == "kernel.hooks"
```

- [ ] **Step 4: Build the synthetic orphan fixture and its test**

For the orphan-without-baseline path independent of the live hidden run, add `tests/fixtures/hook-trees/orphan/` where `enabled_functions.txt` names a hook whose callback is absent from `kallsyms.txt` (so `owner_module` resolves to `None`). Extend `test_collector_kernel_hooks.py`:

```python
def test_collector_records_none_owner_for_unattributable_callback():
    obs = KernelHookCollector().collect(
        FixtureKernelHookSource(Path(__file__).parent.parent
                                / "fixtures" / "hook-trees" / "orphan"))
    assert any(e.owner_module is None for e in obs.entities.values())
```

- [ ] **Step 5: Write the docs, run the full suite, and commit (from reverted clean tree)**

Add **L18** to `docs/limitations.md` (on-host signing boundary, spec §6.4/§11) and any new limitation the runs surfaced (e.g. if `enabled_functions` did not name the module, or a channel came back empty). Rewrite `docs/detection-methods.md` §10 for hook surfaces (ftrace `enabled_functions`, kprobes, kallsyms attribution) — each with its clean baseline (cite `docs/step0-phase3/clean/`) and its `kdetect_hooktest` result (cite the infected capture), and mark it `[implemented — phase 3a]`. Note the baseline store in `docs/architecture.md`.

Run the whole suite:

Run: `python -m pytest -v`
Expected: all green on Windows (integration tier skipped there); on the VM the `@needs_procfs` test also passes.

```bash
git add tests/integration/test_phase3a_live.py tests/fixtures/ docs/limitations.md docs/detection-methods.md docs/architecture.md tests/unit/test_collector_kernel_hooks.py
```

Commit message for Angus:
`test+docs: phase 3a live ground truth (kdetect_hooktest), L18, §10 rewrite`

---

## Self-Review

**Spec coverage:**
- §3 architecture / CLI surface → Task 10 (capture, `baseline`, `analyze --baseline`).
- §4 kernel_hooks view (source, collector, entity) → Tasks 3–6. Kallsyms as attribution-not-a-view → Task 6 (`extra.kallsyms_modules`, `sym_to_mod` resolution).
- §5.1 BASELINE_DRIFT → Task 9. §5.2 UNEXPECTED_HOOK (orphan + drift) → Task 7. §5.3 corroboration-count confidence → Task 7 (`_confidence(orphan+drift)`).
- §6 baseline store (ed25519, detached sig, verify-before-parse, key loaders) → Task 8.
- §7 benign test LKM (visible + hidden modes) → Task 1. §8 testing tiers + acceptance criteria → Tasks 3–11 (criterion 2 zero-findings guard → Task 11 Step 3; criterion 4 tamper refusal → Task 8 + Task 10).
- §11 L18 + step-0 gate → Task 2 (gate) and Task 11 (L18). The three prospective format questions are resolved in Task 2 Step 3.

**Deviations from the spec, by intent (both more faithful to its own principles):**
1. `attributable` is **derived by the differ**, not stored on `HookEntity` (Tasks 5/7) — P1/P4 say the collector records evidence (`owner_module`) and the differ concludes. The spec's §4.2 field list is adjusted accordingly.
2. Cross-*pass* module composition (a module that is both new-vs-baseline *and* an unexplained region collapsing into one HIGH finding) is **not** implemented; module drift and phase-2 module channels each report independently. Per-module corroboration is the phase-2 parked item explicitly deferred to phase 3b, so folding it in here would pull 3b work forward. Hook corroboration (orphan + drift) *is* implemented within `diff_hooks`, matching `diff_modules`'s existing within-pass count.

**Placeholder scan:** none — every code and test step carries real content. The one deliberately provisional area (the exact `enabled_functions` line format) is gated on Task 2's capture, with sample lines given and the instruction that the capture is authoritative — the same discipline phase 2 used with `docs/step0-phase2/`.

**Type consistency:** `HookRow`/`HookEntity` fields (`function`, `hook_type`, `callback`, `owner_module`) are identical across Tasks 3/5/6/7. `diff_hooks(snapshot, baseline=None)` and `diff_all(snapshot, baseline=None)` signatures match between Task 7 and Task 10. `write_baseline(snapshot, out_path, private_key)` / `load_baseline(json_path, public_key)` match between Tasks 8 and 10. Entity id form `f"{hook_type}:{function}"` is used consistently in Tasks 5/6/7.

---

## Execution Handoff

Plan complete. Save location: `docs/superpowers/plans/2026-08-21-kdetect-phase3a.md`.
