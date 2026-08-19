"""The cross-view differ (spec §4.2, §5.2). Pure: Snapshot -> [Finding].

Touches no I/O, so it runs identically on a live capture, a committed fixture,
and a hand-built snapshot. Disagreement between channels is the signal.
"""
from __future__ import annotations

from kdetect.analysis.models import Confidence, Finding, FindingKind
from kdetect.models import Snapshot


def _observations(snapshot: Snapshot, collector: str):
    return [o for o in snapshot.observations if o.collector == collector]


def diff_processes(snapshot: Snapshot) -> list[Finding]:
    procfs = _observations(snapshot, "procfs.processes")
    sweeps = _observations(snapshot, "syscall_sweep.processes")
    if not procfs or not sweeps:
        return []                       # nothing to cross-check

    listed = set()
    for obs in procfs:                  # union of every readdir pass
        listed |= set(obs.entity_ids)

    sweep = sweeps[0]
    findings: list[Finding] = []
    reported: set[int] = set()

    for task_id in sweep.entity_ids:
        ent = sweep.entities[task_id]
        if not ent.status_readable:
            continue                    # vanished between sweep and fold
        tgid = ent.tgid
        if tgid in listed:
            continue                    # ordinary thread of a visible process
        # tgid seen by the sweep but in NEITHER readdir pass -> hidden.
        if tgid in reported:
            continue                    # one finding per process, not per thread
        reported.add(tgid)
        findings.append(Finding(
            kind=FindingKind.HIDDEN_PROCESS,
            subject=f"pid {tgid}",
            confidence=Confidence.MEDIUM,
            channels_agree=["syscall_sweep", "direct status"],
            channels_dissent=["procfs readdir (all passes)"],
            evidence={
                "tgid": tgid,
                "seen_by_sweep": True,
                "in_procfs_passes": sorted(o.pass_ or "?" for o in procfs
                                           if tgid in set(o.entity_ids)),
                "status_readable": True,
            },
            summary=f"pid {tgid} answers the syscall sweep but appears in no "
                    f"/proc readdir pass",
        ))
    return sorted(findings, key=lambda f: f.subject)
