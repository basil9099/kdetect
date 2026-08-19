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


def _confidence(n: int) -> Confidence:
    return {1: Confidence.LOW, 2: Confidence.MEDIUM}.get(n, Confidence.HIGH)


def diff_modules(snapshot: Snapshot) -> list[Finding]:
    listings = _observations(snapshot, "procfs.modules")
    evidences = _observations(snapshot, "kernel.module_evidence")
    if not listings or not evidences:
        return []

    listed = set(listings[0].entity_ids)
    ev = evidences[0]
    taint = ev.stats.get("taint", 0)
    markers = (ev.extra or {}).get("listed_taint_markers", 0)
    regions = ev.stats.get("load_module_regions")
    ftrace = (ev.extra or {}).get("ftrace_modules")

    # How many independent channels indicate a hidden module at all? Used to
    # raise the confidence of the channel(s) that can name it.
    taint_hit = bool(taint & ((1 << 12) | (1 << 13))) and markers == 0
    region_hit = regions is not None and regions > len(listed)
    orphans = sorted(set(ftrace) - listed) if ftrace is not None else []
    corroboration = sum([taint_hit, region_hit, bool(orphans)])
    conf = _confidence(corroboration)

    findings: list[Finding] = []
    if taint_hit:
        bit = "12 (out-of-tree)" if taint & (1 << 12) else "13 (unsigned)"
        findings.append(Finding(
            FindingKind.MODULE_TAINT_MISMATCH, f"taint bit {bit}", conf,
            ["kernel.module_evidence taint"], ["procfs.modules listing"],
            {"taint": taint, "listed_taint_markers": markers},
            f"taint bit {bit} set, but no listed module carries an (O)/(E) marker",
        ))
    if region_hit:
        findings.append(Finding(
            FindingKind.UNEXPLAINED_MODULE_REGION,
            f"{regions - len(listed)} unaccounted module region(s)", conf,
            ["kernel.module_evidence vmallocinfo"], ["procfs.modules listing"],
            {"load_module_regions": regions, "listed": len(listed)},
            f"{regions} load_module regions but only {len(listed)} modules listed",
        ))
    for name in orphans:
        findings.append(Finding(
            FindingKind.FTRACE_ORPHAN_MODULE, f"module {name}", conf,
            ["kernel.module_evidence ftrace"], ["procfs.modules listing"],
            {"ftrace_module": name, "in_listing": False},
            f"module {name} has ftrace records but is absent from /proc/modules",
        ))
    return findings


def diff_all(snapshot: Snapshot) -> list[Finding]:
    return diff_processes(snapshot) + diff_modules(snapshot)
