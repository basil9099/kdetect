"""Detectors: Snapshot -> [Signal] (spec §3, §4).

Pure and I/O-free. Each detector observes one view and records channels; it
draws no confidence and composes nothing (P8). taint and vmalloc_region are
ANONYMOUS (Suspect name None): the taint word and the hash-obfuscated region
addresses (L15) indicate a hidden module exists but cannot name it. ftrace_orphan
and unexpected_hook name their module. The scorer attributes the anonymous ones
(scoring.py).
"""
from __future__ import annotations

from kdetect.analysis.models import ChannelNote, Signal, Suspect
from kdetect.analysis.taint import reconcile
from kdetect.models import Snapshot

_MODULE_DISSENT = "procfs.modules listing"
_PROCESS_DISSENT = "procfs readdir (all passes)"
_BASELINE_DISSENT = "signed baseline"
_LISTING_DISSENT = "every corroborating channel"


def _observations(snapshot: Snapshot, collector: str):
    return [o for o in snapshot.observations if o.collector == collector]


def _module_ids(snapshot: Snapshot) -> set[str]:
    obs = _observations(snapshot, "procfs.modules")
    return set(obs[0].entity_ids) if obs else set()


def _listed_markers(snapshot: Snapshot) -> dict[str, str | None]:
    """Each listed module's /proc/modules taint marker, or None.

    The letters are already in every snapshot ever captured -- ModuleEntity.taint
    -- and were being discarded in favour of a count (P12).
    """
    obs = _observations(snapshot, "procfs.modules")
    if not obs:
        return {}
    return {name: ent.taint for name, ent in obs[0].entities.items()}


def signals_modules(snapshot: Snapshot) -> list[Signal]:
    listings = _observations(snapshot, "procfs.modules")
    evidences = _observations(snapshot, "kernel.module_evidence")
    if not listings or not evidences:
        return []
    listed = set(listings[0].entity_ids)
    ev = evidences[0]
    taint = ev.stats.get("taint", 0)
    regions = ev.stats.get("load_module_regions")
    ftrace = (ev.extra or {}).get("ftrace_modules")

    out: list[Signal] = []
    rec = reconcile(taint, _listed_markers(snapshot))
    if rec.unexplained:
        # explained_by keys are stringified: this dict is serialised into the
        # finding's evidence and JSON object keys must be strings.
        out.append(Signal("taint", Suspect("module", None), _MODULE_DISSENT,
                          {"taint": taint, "bits": rec.unexplained,
                           "explained_by": {str(b): v
                                            for b, v in rec.explained_by.items()}}))
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
            "comm": ent.comm,
            "in_procfs_passes": sorted(o.pass_ or "?" for o in procfs
                                       if tgid in set(o.entity_ids)),
        }
        suspect = Suspect("process", str(tgid))
        # Two independent reads bypassing readdir -> two channels -> MEDIUM.
        out.append(Signal("syscall_kill", suspect, _PROCESS_DISSENT, dict(evidence)))
        out.append(Signal("direct_status", suspect, _PROCESS_DISSENT, dict(evidence)))
    return out


def signals_sockets(snapshot: Snapshot) -> list[Signal]:
    sock_obs = _observations(snapshot, "procfs.sockets")
    if not sock_obs:
        return []
    sockets = sock_obs[0]

    listed: set[int] = set()
    for obs in _observations(snapshot, "procfs.processes"):
        listed |= set(obs.entity_ids)

    # Threads share their process's fd table, so a socket's owner_pids can
    # include non-leader task ids (tids). The readdir listing only has TGIDs,
    # so an unfolded tid would false-fire socket_visible for any thread of a
    # perfectly normal multi-threaded process. Fold tid -> tgid via the sweep
    # before comparing against the readdir listing.
    tid_to_tgid: dict[int, int] = {}
    sweeps = _observations(snapshot, "syscall_sweep.processes")
    if sweeps:
        sweep = sweeps[0]
        for task_id in sweep.entity_ids:
            tid_to_tgid[task_id] = sweep.entities[task_id].tgid

    out: list[Signal] = []
    for key in sockets.entity_ids:
        e = sockets.entities[key]
        if e.in_table:
            reported_tgids: set[int] = set()
            for pid in e.owner_pids:
                tgid = tid_to_tgid.get(pid, pid)
                if tgid in listed or tgid in reported_tgids:
                    continue
                reported_tgids.add(tgid)
                out.append(Signal("socket_visible", Suspect("process", str(tgid)),
                                  _PROCESS_DISSENT,
                                  {"inode": e.inode, "local": e.local,
                                   "remote": e.remote, "state": e.state}))
    return sorted(out, key=lambda s: (s.channel, s.suspect.name or ""))


#: Channels consulted for over_listed corroboration, named for ChannelNote detail.
_LISTING_CHANNELS = ["kernel.module_evidence.ftrace_modules", "kernel.hooks.kallsyms_modules"]


def _over_listed_corroboration(snapshot: Snapshot) -> tuple[set[str], set[str]] | None:
    """The listed and corroborated module-name sets for the over_listed channel,
    or None if any corroborating channel is unavailable (spec section 5.2).

    Guarded on channel AVAILABILITY, never on emptiness: a channel that cannot
    be read must be skipped rather than read as dissent, which is the rule
    ModuleSource's own docstring states. Availability is read from the
    ftrace_available/kallsyms_available stats flags, never inferred from
    whether ftrace_modules/kallsyms_modules happens to be empty.
    """
    listings = _observations(snapshot, "procfs.modules")
    evidences = _observations(snapshot, "kernel.module_evidence")
    hooks = _observations(snapshot, "kernel.hooks")
    if not listings or not evidences or not hooks:
        return None
    if not evidences[0].stats.get("ftrace_available"):
        return None
    if not hooks[0].stats.get("kallsyms_available"):
        return None

    ftrace = (evidences[0].extra or {}).get("ftrace_modules")
    kallsyms = (hooks[0].extra or {}).get("kallsyms_modules")
    if ftrace is None or kallsyms is None:
        return None

    return set(listings[0].entity_ids), set(ftrace) | set(kallsyms)


def signals_over_listed(snapshot: Snapshot) -> list[Signal]:
    """A listed module that no other channel corroborates (spec section 5).

    The mirror of ftrace_orphan. An attacker who can unlink a row from
    /proc/modules can equally add one, and each phantom row absorbs exactly one
    unaccounted vmalloc region -- so the region arithmetic is one phantom row
    deep without this.

    When EVERY listed module comes up uncorroborated, that is not N modules
    hiding at once -- it is evidence the channel pair itself said nothing (a
    readable-but-empty /proc/kallsyms still reports available=True with no
    names). Emptiness of the whole corroborating union is channel-level
    evidence (P12), so it is surfaced as a ChannelNote (see channel_notes),
    not as a signal per module, which would flood the report with one
    HIDDEN-reading finding for every legitimate module on such a host.
    """
    corrob = _over_listed_corroboration(snapshot)
    if corrob is None:
        return []
    listed, corroborated = corrob
    uncorroborated = listed - corroborated
    if listed and uncorroborated == listed:
        return []
    return [
        Signal("over_listed", Suspect("module", name), _LISTING_DISSENT,
               {"listed": True, "corroborated_by": []})
        for name in sorted(uncorroborated)
    ]


def signals_baseline(current: Snapshot, baseline: Snapshot) -> list[Signal]:
    now = _module_ids(current)
    was = _module_ids(baseline)
    # Additions are the signal; removals are benign (a rootkit adds capability).
    return [Signal("baseline_drift", Suspect("module", name), _BASELINE_DISSENT,
                   {"direction": "added"})
            for name in sorted(now - was)]


def all_signals(snapshot: Snapshot, baseline: Snapshot | None = None) -> list[Signal]:
    sigs = (signals_processes(snapshot) + signals_modules(snapshot)
            + signals_hooks(snapshot) + signals_sockets(snapshot)
            + signals_over_listed(snapshot))
    if baseline is not None:
        sigs += signals_baseline(snapshot, baseline)
    return sigs


def channel_notes(snapshot: Snapshot) -> list[ChannelNote]:
    """Channels that could not contribute, and why (spec section 4.4).

    A saturated channel and a clean one look identical in the output today, and
    they mean opposite things: "taint is clear" versus "taint is set and fully
    accounted for by a listed module, so it can say nothing about a hidden one".

    Likewise "over_listed is silent" and "over_listed said everything is
    over-listed" look identical as an empty signal list, and mean opposite
    things: a channel with nothing to add versus a channel that came back
    empty and so corroborated nothing at all (spec section 5.2).
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
    corrob = _over_listed_corroboration(snapshot)
    if corrob is not None:
        listed, corroborated = corrob
        if listed and listed - corroborated == listed:
            notes.append(ChannelNote(
                "over_listed", "uncorroborated",
                {"listed": len(listed), "channels_consulted": list(_LISTING_CHANNELS)},
            ))
    return notes
