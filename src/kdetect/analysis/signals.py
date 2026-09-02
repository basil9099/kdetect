"""Detectors: Snapshot -> [Signal] (spec §3, §4).

Pure and I/O-free. Each detector observes one view and records channels; it
draws no confidence and composes nothing (P8). taint and vmalloc_region are
ANONYMOUS (Suspect name None): the taint word and the hash-obfuscated region
addresses (L15) indicate a hidden module exists but cannot name it. ftrace_orphan
and unexpected_hook name their module. The scorer attributes the anonymous ones
(scoring.py).
"""
from __future__ import annotations

from kdetect.analysis.models import Signal, Suspect
from kdetect.models import Snapshot

_MODULE_DISSENT = "procfs.modules listing"
_PROCESS_DISSENT = "procfs readdir (all passes)"
_BASELINE_DISSENT = "signed baseline"


def _observations(snapshot: Snapshot, collector: str):
    return [o for o in snapshot.observations if o.collector == collector]


def _module_ids(snapshot: Snapshot) -> set[str]:
    obs = _observations(snapshot, "procfs.modules")
    return set(obs[0].entity_ids) if obs else set()


def signals_modules(snapshot: Snapshot) -> list[Signal]:
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

    out: list[Signal] = []
    if bool(taint & ((1 << 12) | (1 << 13))) and markers == 0:
        bits = [b for b in (12, 13) if taint & (1 << b)]
        out.append(Signal("taint", Suspect("module", None), _MODULE_DISSENT,
                          {"taint": taint, "listed_taint_markers": markers, "bits": bits}))
    if regions is not None and regions > len(listed):
        out.append(Signal("vmalloc_region", Suspect("module", None), _MODULE_DISSENT,
                          {"load_module_regions": regions, "listed": len(listed),
                           "unaccounted": regions - len(listed)}))
    if ftrace is not None:
        for name in sorted(set(ftrace) - listed):
            out.append(Signal("ftrace_orphan", Suspect("module", name), _MODULE_DISSENT,
                              {"ftrace_module": name, "in_listing": False}))
    return out


def signals_hooks(snapshot: Snapshot) -> list[Signal]:
    hook_obs = _observations(snapshot, "kernel.hooks")
    if not hook_obs:
        return []
    hooks = hook_obs[0]
    listed = _module_ids(snapshot)
    out: list[Signal] = []
    for key in hooks.entity_ids:
        ent = hooks.entities[key]
        # Orphan only: callback attributes to a named module not in the listing
        # (spec §4). owner_module None (core kernel / kprobe) is not orphaned.
        if ent.owner_module is not None and ent.owner_module not in listed:
            out.append(Signal("unexpected_hook", Suspect("module", ent.owner_module),
                              _MODULE_DISSENT,
                              {"function": ent.function, "hook_type": ent.hook_type,
                               "callback": ent.callback, "owner_module": ent.owner_module}))
    return sorted(out, key=lambda s: (s.suspect.name or "", s.evidence["function"]))


def signals_processes(snapshot: Snapshot) -> list[Signal]:
    procfs = _observations(snapshot, "procfs.processes")
    sweeps = _observations(snapshot, "syscall_sweep.processes")
    if not procfs or not sweeps:
        return []
    listed: set[int] = set()
    for obs in procfs:
        listed |= set(obs.entity_ids)
    sweep = sweeps[0]
    out: list[Signal] = []
    reported: set[int] = set()
    for task_id in sweep.entity_ids:
        ent = sweep.entities[task_id]
        if not ent.status_readable:
            continue                       # no reliable tgid; treated as vanished
        tgid = ent.tgid
        if tgid in listed or tgid in reported:
            continue
        reported.add(tgid)
        evidence = {
            "tgid": tgid, "seen_by_sweep": True, "status_readable": True,
            "in_procfs_passes": sorted(o.pass_ or "?" for o in procfs
                                       if tgid in set(o.entity_ids)),
        }
        suspect = Suspect("process", str(tgid))
        # Two independent reads bypassing readdir -> two channels -> MEDIUM.
        out.append(Signal("syscall_kill", suspect, _PROCESS_DISSENT, dict(evidence)))
        out.append(Signal("direct_status", suspect, _PROCESS_DISSENT, dict(evidence)))
    return out


def signals_baseline(current: Snapshot, baseline: Snapshot) -> list[Signal]:
    now = _module_ids(current)
    was = _module_ids(baseline)
    # Additions are the signal; removals are benign (a rootkit adds capability).
    return [Signal("baseline_drift", Suspect("module", name), _BASELINE_DISSENT,
                   {"direction": "added"})
            for name in sorted(now - was)]


def all_signals(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Signal]:
    sigs = signals_processes(snapshot) + signals_modules(snapshot) + signals_hooks(snapshot)
    if baseline is not None:
        sigs += signals_baseline(snapshot, baseline)
    return sigs
