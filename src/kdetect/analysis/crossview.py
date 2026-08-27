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
        parts = []
        if taint & (1 << 12):
            parts.append("12 (out-of-tree)")
        if taint & (1 << 13):
            parts.append("13 (unsigned)")
        bit = " + ".join(parts)
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


def _hook_ids(snapshot: Snapshot) -> set[str]:
    obs = _observations(snapshot, "kernel.hooks")
    return set(obs[0].entity_ids) if obs else set()


def diff_hooks(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Finding]:
    """UNEXPECTED_HOOK: a hooked function whose callback belongs to a module that
    exists but is NOT in /proc/modules (orphan, intra-snapshot), and/or a hook
    absent from the baseline.

    attributable is DERIVED here (P4). The orphan signal fires only when the
    callback attributes to a *named* module that the /proc/modules listing does
    not contain -- the Diamorphine analog: a hidden module's hook still names its
    module (via the ftrace [module] tag or kallsyms), yet the module has unlinked
    itself from the listing. Two cases deliberately do NOT orphan on this basis:
      - owner_module is None. A legitimate core-kernel ftrace op has a callback
        in the core kernel with no module tag; flagging it would false-positive
        on any host with function tracing active (docs/limitations.md). Such a
        hook, if truly malicious, still surfaces via baseline drift.
      - kprobe hooks, which always report callback/owner_module None (the kprobe
        parser captures no callback symbol) -- covered by the same None guard.
    """
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
        orphan = ent.owner_module is not None and ent.owner_module not in listed
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
        # Computed on its own line, not inside the f-string: a multi-line
        # expression inside an f-string replacement field is a Python 3.12+
        # feature (PEP 701) and is a SyntaxError on 3.11, which the lab VM runs.
        if orphan:
            reason = f"callback attributes to unlisted module {ent.owner_module}"
        else:
            reason = "new since baseline"
        findings.append(Finding(
            FindingKind.UNEXPECTED_HOOK, f"{ent.hook_type} hook on {ent.function}",
            _confidence(corroboration), agree, dissent,
            {"function": ent.function, "hook_type": ent.hook_type,
             "callback": ent.callback, "owner_module": ent.owner_module,
             "in_listing": ent.owner_module in listed if ent.owner_module else False,
             "new_vs_baseline": bool(drift)},
            f"{ent.hook_type} hook on {ent.function} ({reason})",
        ))
    return sorted(findings, key=lambda f: f.subject)


def diff_all(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Finding]:
    findings = (diff_processes(snapshot) + diff_modules(snapshot)
                + diff_hooks(snapshot, baseline))
    if baseline is not None:
        from kdetect.analysis import baseline_diff       # Task 8
        findings += baseline_diff.diff(snapshot, baseline)
    return findings
