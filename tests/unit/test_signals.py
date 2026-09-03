import json
from pathlib import Path

from kdetect.analysis.models import Suspect
from kdetect.analysis.signals import (
    signals_modules, signals_hooks, signals_processes, signals_baseline, all_signals,
    signals_sockets,
)
from kdetect.models import (
    CaptureMeta, HostFacts, ModuleEntity, Observation, SCHEMA_VERSION, Snapshot,
    SocketEntity, Status, SweepEntity, TrustLevel,
)

SNAP = Path(__file__).parent.parent / "fixtures" / "snapshots"


def _load(name):
    return Snapshot.from_dict(json.loads((SNAP / name).read_text(encoding="utf-8")))


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


def test_clean_yields_no_signals():
    assert all_signals(_load("clean-phase2.json")) == []
    assert all_signals(_load("clean-phase3a.json")) == []


def test_diamorphine_module_signals_include_named_and_anonymous():
    sigs = signals_modules(_load("infected-diamorphine.json"))
    channels = {s.channel for s in sigs}
    assert "taint" in channels and "vmalloc_region" in channels
    assert "ftrace_orphan" in channels
    # taint/region are anonymous; ftrace_orphan names the module
    anon = {s.channel for s in sigs if s.suspect.name is None}
    named = {s.suspect.name for s in sigs if s.channel == "ftrace_orphan"}
    assert anon == {"taint", "vmalloc_region"}
    assert "diamorphine" in named


def test_hooktest_hook_signal_names_owner_module():
    sigs = signals_hooks(_load("infected-hooktest.json"))
    assert len(sigs) == 1
    s = sigs[0]
    assert s.channel == "unexpected_hook"
    assert s.suspect == Suspect("module", "kdetect_hooktest")
    assert s.evidence["function"] == "__x64_sys_newuname"


def test_baseline_drift_emits_added_modules_only():
    base = _snap(["ext4"])
    cur = _snap(["ext4", "evil_mod"])
    sigs = signals_baseline(cur, base)
    assert len(sigs) == 1
    assert sigs[0].channel == "baseline_drift"
    assert sigs[0].suspect == Suspect("module", "evil_mod")

    # A module present in the baseline but missing now is benign (removal is
    # not the signal) and must not drift.
    assert signals_baseline(_snap(["ext4"]), _snap(["ext4", "gone"])) == []


def test_hidden_module_does_not_show_in_listing_drift():
    # infected-hooktest and clean-phase3a have identical procfs.modules listings;
    # the hidden module is caught by hiding channels, not by listing-based drift.
    assert signals_baseline(_load("infected-hooktest.json"), _load("clean-phase3a.json")) == []


def _sock_snap(sockets, listed_pids):
    socks = Observation(
        collector="procfs.sockets", collector_version="1", view="sockets",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(sockets), entities=sockets, stats={}, errors=[])
    procs = Observation(
        collector="procfs.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(listed_pids),
        entities={}, stats={}, errors=[], pass_="A")
    host = HostFacts("t", "6.1", "x86_64", "b", 1, 100)
    return Snapshot(SCHEMA_VERSION, "id", "t", host, CaptureMeta("0.1.0", 0),
                    [procs, socks])


def test_socket_visible_fires_for_unlisted_owner_of_table_socket():
    socks = {"12345": SocketEntity(12345, "tcp", "LISTEN", "0.0.0.0:22",
                                   "0.0.0.0:0", 0, in_table=True, owner_pids=[31337])}
    sigs = signals_sockets(_sock_snap(socks, listed_pids=[1]))   # 31337 not listed
    assert len(sigs) == 1
    assert sigs[0].channel == "socket_visible"
    assert sigs[0].suspect == Suspect("process", "31337")

def test_normal_owned_table_socket_is_silent():
    socks = {"12345": SocketEntity(12345, "tcp", "ESTABLISHED", "a", "b", 0,
                                   in_table=True, owner_pids=[812])}
    assert signals_sockets(_sock_snap(socks, listed_pids=[1, 812])) == []

def test_unowned_table_socket_emits_nothing():
    socks = {"12345": SocketEntity(12345, "tcp", "TIME_WAIT", "a", "b", 0,
                                   in_table=True, owner_pids=[])}
    assert signals_sockets(_sock_snap(socks, listed_pids=[1])) == []


def test_socket_visible_folds_thread_tid_to_listed_tgid():
    # A clean multi-threaded process (leader tgid 812) owns a table socket
    # via one of its threads (tid 900). The readdir listing only ever shows
    # the leader tgid 812 -- tid 900 is never a top-level /proc entry. Before
    # the tid->tgid fold, this false-fired socket_visible on pid 900, which
    # is not in the readdir listing, producing a false HIDDEN_PROCESS on a
    # perfectly clean host.
    socks = {"12345": SocketEntity(12345, "tcp", "ESTABLISHED", "a", "b", 0,
                                   in_table=True, owner_pids=[812, 900])}
    procs = Observation(
        collector="procfs.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=[812], entities={}, stats={}, errors=[], pass_="A")
    sweep = Observation(
        collector="syscall_sweep.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.MEDIUM, status=Status.OK, duration_ms=1,
        entity_ids=[812, 900],
        entities={
            812: SweepEntity(tgid=812, status_readable=True),
            900: SweepEntity(tgid=812, status_readable=True),
        },
        stats={}, errors=[])
    sockobs = Observation(
        collector="procfs.sockets", collector_version="1", view="sockets",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(socks), entities=socks, stats={}, errors=[])
    host = HostFacts("t", "6.1", "x86_64", "b", 1, 100)
    snap = Snapshot(SCHEMA_VERSION, "id", "t", host, CaptureMeta("0.1.0", 0),
                    [procs, sweep, sockobs])
    assert signals_sockets(snap) == []
