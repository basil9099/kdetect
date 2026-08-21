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
