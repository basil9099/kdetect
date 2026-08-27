"""Ground-truth regression tests (spec §9).

Two paired real captures anchor the differ to reality:

- clean-phase2.json  - a full root capture from the clean-baseline VM. It MUST
  produce zero findings. This is the false-positive guard: the ~90-thread
  class, the sysfs-built-in class, and the kallsyms [bpf] class must all stay
  silent on a real machine, and stay silent under future refactoring.
- infected-diamorphine.json - a capture taken with Diamorphine loaded and a PID
  hidden. Added in the infected half of the ground-truth run; asserts the
  differ actually detects a real rootkit.

Both fixtures are redacted of session secrets before commit (limitation L13).
"""

import json
from pathlib import Path

import pytest

from kdetect.analysis.crossview import diff_all
from kdetect.analysis.models import Confidence, FindingKind
from kdetect.models import Snapshot

SNAP = Path(__file__).parent.parent / "fixtures" / "snapshots"

# Phase-3a fixtures are captured on the VM and committed separately (they are
# real root captures, redacted via tools/redact_snapshot.py per L13). Until they
# land, these guards skip; once the JSON is present the assertions run for real.
needs_clean3a = pytest.mark.skipif(
    not (SNAP / "clean-phase3a.json").exists(),
    reason="clean-phase3a.json fixture not captured yet",
)
needs_hooktest = pytest.mark.skipif(
    not (SNAP / "infected-hooktest.json").exists(),
    reason="infected-hooktest.json fixture not captured yet",
)


def _load(name: str) -> Snapshot:
    return Snapshot.from_dict(json.loads((SNAP / name).read_text(encoding="utf-8")))


def test_clean_phase2_has_zero_findings():
    # The single most important behaviour: a detector that fires on a clean
    # machine is worse than none. A root capture with every channel live still
    # yields nothing, because threads fold to their leader, sysfs built-ins are
    # not in /proc/modules, taint is clear, and ftrace is a subset of the
    # listing.
    assert diff_all(_load("clean-phase2.json")) == []


# --- Real ground truth: Diamorphine loaded on kernel 6.1.0-52 ---
#
# Diamorphine hides its own module with a list_del in its init, so /proc/modules
# never lists it - but its taint bits, its vmalloc region and its ftrace records
# all outlive that unlinking. Three independent channels each catch the hidden
# module, and corroborate to HIGH.
#
# Its PROCESS-hiding syscall hooks did NOT engage on this kernel (see limitation
# L16): sending SIGINVIS killed the target with SIGSYS instead of hiding it, so
# no process was actually hidden. The infected capture therefore also proves the
# differ does NOT invent a hidden_process on an infected box - a real negative.


def test_infected_diamorphine_detects_hidden_module():
    findings = diff_all(_load("infected-diamorphine.json"))
    kinds = {f.kind for f in findings}
    assert FindingKind.MODULE_TAINT_MISMATCH in kinds
    assert FindingKind.UNEXPLAINED_MODULE_REGION in kinds
    assert FindingKind.FTRACE_ORPHAN_MODULE in kinds


def test_infected_ftrace_channel_names_diamorphine():
    findings = diff_all(_load("infected-diamorphine.json"))
    orphans = [f for f in findings if f.kind is FindingKind.FTRACE_ORPHAN_MODULE]
    assert len(orphans) == 1
    assert "diamorphine" in orphans[0].subject


def test_infected_module_findings_are_high_confidence():
    # All three independent channels agree, so corroboration is 3 -> HIGH.
    findings = diff_all(_load("infected-diamorphine.json"))
    module_findings = [
        f for f in findings
        if f.kind in {
            FindingKind.MODULE_TAINT_MISMATCH,
            FindingKind.UNEXPLAINED_MODULE_REGION,
            FindingKind.FTRACE_ORPHAN_MODULE,
        }
    ]
    assert module_findings
    assert all(f.confidence is Confidence.HIGH for f in module_findings)


def test_infected_capture_raises_no_false_hidden_process():
    # Nothing was actually hidden (L16), so the sandwich must stay silent on the
    # process view even on an infected machine - the threads still fold away.
    findings = diff_all(_load("infected-diamorphine.json"))
    assert not any(f.kind is FindingKind.HIDDEN_PROCESS for f in findings)


# --- Phase 3a ground truth: kdetect_hooktest (hidden) on kernel 6.1.0-52 ---
#
# The benign test module (kmod/kdetect_hooktest.c) registers an ftrace hook on
# __x64_sys_newuname and list_del's itself, so /proc/modules never lists it - the
# same hiding technique as Diamorphine, now carrying a hook. It was caught live
# with NO baseline: the phase-3a kernel.hooks channel attributes the hook's
# callback to a module absent from the listing, and the phase-2 taint and
# vmalloc-region channels corroborate. See docs/detection-methods.md #10.


@needs_clean3a
def test_clean_phase3a_has_zero_findings():
    # A clean root capture that INCLUDES the kernel.hooks collector must still
    # yield nothing: enabled_functions/kprobes are empty on an idle host, so the
    # orphan-hook check has nothing to attribute (limitation L19). Requires a
    # taint=0 boot (L17), i.e. captured before any out-of-tree module was loaded.
    assert diff_all(_load("clean-phase3a.json")) == []


@needs_hooktest
def test_infected_hooktest_detects_orphan_hook_and_module():
    findings = diff_all(_load("infected-hooktest.json"))
    kinds = {f.kind for f in findings}
    assert FindingKind.UNEXPECTED_HOOK in kinds          # phase-3a hook channel
    assert FindingKind.MODULE_TAINT_MISMATCH in kinds    # phase-2 corroboration
    assert FindingKind.UNEXPLAINED_MODULE_REGION in kinds


@needs_hooktest
def test_infected_hooktest_hook_names_the_unlisted_module():
    findings = diff_all(_load("infected-hooktest.json"))
    hooks = [f for f in findings if f.kind is FindingKind.UNEXPECTED_HOOK]
    assert len(hooks) == 1
    assert "__x64_sys_newuname" in hooks[0].subject
    assert hooks[0].evidence.get("owner_module") == "kdetect_hooktest"


@needs_hooktest
def test_infected_hooktest_no_false_hidden_process():
    # As with Diamorphine, the module hides itself but no PROCESS is hidden, so
    # the process sandwich must not invent a hidden_process on the infected box.
    findings = diff_all(_load("infected-hooktest.json"))
    assert not any(f.kind is FindingKind.HIDDEN_PROCESS for f in findings)
