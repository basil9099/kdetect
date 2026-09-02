"""The scorer: [Signal] -> [Finding] (spec §5). Pure.

Groups signals by suspect, attributes anonymous module signals to the single
hidden-named module when exactly one exists, counts distinct channels per suspect
for confidence (P9), and emits one composed Finding per suspect. All conclusions
live here (P8); detectors only observe.
"""
from __future__ import annotations

from kdetect.analysis.models import (
    Confidence, Finding, FindingKind, Signal, Suspect,
)
from kdetect.analysis.signals import all_signals
from kdetect.models import Snapshot

#: Channels that indicate concealment. Everything except baseline_drift, which
#: alone means only "new since the baseline", not "hidden".
_HIDING = {"taint", "vmalloc_region", "ftrace_orphan", "unexpected_hook",
           "syscall_kill", "direct_status", "hidden_socket", "socket_visible"}
#: Named hiding channels -- the ones that can make a module "hidden_named" and so
#: attract the anonymous taint/region signals.
_HIDING_NAMED = {"ftrace_orphan", "unexpected_hook"}


def _confidence(n: int) -> Confidence:
    return {1: Confidence.LOW, 2: Confidence.MEDIUM}.get(n, Confidence.HIGH)


def _classify(suspect: Suspect, channels: list[str]) -> tuple[FindingKind, str, str]:
    if suspect.kind == "process":
        return (FindingKind.HIDDEN_PROCESS, f"pid {suspect.name}",
                f"pid {suspect.name} is hidden from the /proc readdir listing but seen by other channels")
    if suspect.kind == "socket":
        return (FindingKind.HIDDEN_CONNECTION, f"socket inode {suspect.name}",
                f"socket inode {suspect.name} is held by a process but appears in "
                f"no /proc/net table")
    if suspect.name is None:
        return (FindingKind.SUSPECTED_HIDDEN_MODULE, "unattributed hidden module",
                "hidden-module indicators fired but no channel can name the module")
    if any(c in _HIDING for c in channels):
        return (FindingKind.HIDDEN_MODULE, f"module {suspect.name}",
                f"module {suspect.name} is concealed from /proc/modules but named "
                f"by {', '.join(channels)}")
    return (FindingKind.BASELINE_DRIFT, f"module {suspect.name}",
            f"module {suspect.name} is loaded now but was absent from the baseline")


def _compose(suspect: Suspect, sigs: list[Signal]) -> Finding:
    ordered = sorted(sigs, key=lambda s: s.channel)
    channels = sorted({s.channel for s in ordered})
    dissent = sorted({s.dissent for s in ordered})
    evidence: dict = {}
    for s in ordered:
        evidence.setdefault(s.channel, []).append(s.evidence)
    kind, subject, summary = _classify(suspect, channels)
    return Finding(kind, subject, _confidence(len(channels)),
                   channels, dissent, evidence, summary)


def score(signals: list[Signal]) -> list[Finding]:
    named = [s for s in signals if s.suspect.name is not None]
    anon = [s for s in signals if s.suspect.name is None]

    groups: dict[Suspect, list[Signal]] = {}
    for s in named:
        groups.setdefault(s.suspect, []).append(s)

    hidden_named = {
        susp.name for susp, sigs in groups.items()
        if susp.kind == "module" and any(s.channel in _HIDING_NAMED for s in sigs)
    }

    # Attribute anonymous module signals only when exactly one module is hidden
    # (spec §5); with 0 or >=2 they cannot be pinned to a name (L15/L21).
    if len(hidden_named) == 1 and anon:
        target = Suspect("module", next(iter(hidden_named)))
        groups.setdefault(target, []).extend(anon)
        anon = []

    findings = [
        _compose(susp, groups[susp])
        for susp in sorted(groups, key=lambda s: (s.kind, s.name or ""))
    ]
    if anon:
        findings.append(_compose(Suspect("module", None), anon))
    return sorted(findings, key=lambda f: f.subject)


def analyze(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Finding]:
    return score(all_signals(snapshot, baseline))
