import copy
import json
from pathlib import Path

from kdetect.analysis.models import ChannelNote, Suspect
from kdetect.analysis.signals import (
    signals_modules, signals_hooks, signals_processes, signals_baseline, all_signals,
    signals_sockets, channel_notes, signals_over_listed,
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


def test_signals_processes_carries_comm_in_evidence():
    procs = Observation(
        collector="procfs.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=[1], entities={}, stats={}, errors=[], pass_="A")
    sweep = Observation(
        collector="syscall_sweep.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.MEDIUM, status=Status.OK, duration_ms=1,
        entity_ids=[31337],
        entities={31337: SweepEntity(tgid=31337, status_readable=True, comm="evil")},
        stats={}, errors=[])
    host = HostFacts("t", "6.1", "x86_64", "b", 1, 100)
    snap = Snapshot(SCHEMA_VERSION, "id", "t", host, CaptureMeta("0.1.0", 0),
                    [procs, sweep])
    sigs = signals_processes(snap)
    assert sigs and all(s.evidence.get("comm") == "evil" for s in sigs)


def _mutate(name):
    """Load a committed capture as a raw dict for hostile mutation.

    Fixtures are never modified on disk (spec section 8); every test deep-copies
    the parsed JSON, edits the copy, and rebuilds a Snapshot from it.
    """
    return copy.deepcopy(json.loads((SNAP / name).read_text(encoding="utf-8")))


def _obs(raw, collector):
    return next(o for o in raw["observations"] if o["collector"] == collector)


def _mark(raw, marker):
    """Give the first listed module a /proc/modules taint marker."""
    mods = _obs(raw, "procfs.modules")
    mods["entities"][mods["entity_ids"][0]]["taint"] = marker
    return raw


def _taint_signal(raw):
    sigs = signals_modules(Snapshot.from_dict(raw))
    found = [s for s in sigs if s.channel == "taint"]
    return found[0] if found else None


def test_taint_fires_on_the_unmodified_captures():
    for name in ("infected-hooktest.json", "infected-diamorphine.json"):
        sig = _taint_signal(_mutate(name))
        assert sig is not None, name
        assert sig.evidence["bits"] == [12, 13]
        assert sig.evidence["explained_by"] == {}


def test_proprietary_marker_no_longer_silences_the_out_of_tree_bits():
    # Today a (P) marker sets listed_taint_markers to 1 and kills the channel.
    # It has nothing to do with bits 12 and 13 (spec section 1.2, middle rows).
    sig = _taint_signal(_mark(_mutate("infected-hooktest.json"), "P"))
    assert sig is not None
    assert sig.evidence["bits"] == [12, 13]


def test_signed_out_of_tree_marker_leaves_the_unsigned_bit_unexplained():
    sig = _taint_signal(_mark(_mutate("infected-hooktest.json"), "O"))
    assert sig is not None
    assert sig.evidence["bits"] == [13]
    assert list(sig.evidence["explained_by"]) == ["12"]


def test_oe_marker_still_silences_the_channel():
    # Pinning the LIMIT with a test so it cannot be mistaken for a regression:
    # (OE) honestly explains both bits, and no reconciliation recovers this.
    assert _taint_signal(_mark(_mutate("infected-hooktest.json"), "OE")) is None


def test_non_module_taint_bit_never_fires():
    raw = _mutate("infected-hooktest.json")
    _obs(raw, "kernel.module_evidence")["stats"]["taint"] = 1 << 9   # TAINT_WARN
    assert _taint_signal(raw) is None


def test_no_note_when_taint_is_clean():
    raw = _mutate("infected-hooktest.json")
    _obs(raw, "kernel.module_evidence")["stats"]["taint"] = 0
    assert channel_notes(Snapshot.from_dict(raw)) == []


def test_no_note_when_the_channel_still_speaks():
    # Bits set and unexplained: the channel is contributing, not saturated.
    assert channel_notes(_load("infected-hooktest.json")) == []


def test_saturated_taint_emits_a_note_naming_the_explaining_module():
    raw = _mark(_mutate("infected-hooktest.json"), "OE")
    notes = channel_notes(Snapshot.from_dict(raw))
    assert len(notes) == 1
    note = notes[0]
    assert isinstance(note, ChannelNote)
    assert note.channel == "taint"
    assert note.reason == "saturated"
    explaining = _obs(raw, "procfs.modules")["entity_ids"][0]
    assert note.detail["explained_by"] == {"12": [explaining], "13": [explaining]}


def test_note_round_trips_to_a_json_safe_dict():
    raw = _mark(_mutate("infected-hooktest.json"), "OE")
    d = channel_notes(Snapshot.from_dict(raw))[0].to_dict()
    assert json.loads(json.dumps(d)) == d
    assert set(d) == {"channel", "reason", "detail"}


def _corroborators(raw, ftrace, kallsyms):
    _obs(raw, "kernel.module_evidence")["extra"]["ftrace_modules"] = ftrace
    _obs(raw, "kernel.module_evidence")["stats"]["ftrace_available"] = True
    hooks = _obs(raw, "kernel.hooks")
    hooks["extra"]["kallsyms_modules"] = kallsyms
    hooks["stats"]["kallsyms_available"] = True
    return raw


def test_no_over_listed_signal_on_the_real_captures():
    # Measured in spec section 5.2: zero on hooktest, and diamorphine has no
    # kernel.hooks observation at all so the guard suppresses it there.
    for name in ("infected-hooktest.json", "infected-diamorphine.json"):
        assert signals_over_listed(_load(name)) == [], name


def test_phantom_row_is_caught_when_every_channel_is_available():
    raw = _mutate("infected-hooktest.json")
    mods = _obs(raw, "procfs.modules")
    original = list(mods["entity_ids"])          # before injecting the phantom
    mods["entities"]["phantom_mod"] = {
        "name": "phantom_mod", "size": 1, "refcount": 0, "dependents": [],
        "state": "Live", "base_addr": "0x0", "taint": None,
    }
    mods["entity_ids"] = sorted(original + ["phantom_mod"])
    # Split the real listing across the two corroborating channels so neither
    # one alone covers it -- proving the UNION is what corroborates, not just
    # one channel's reach -- while the injected phantom row sits in neither
    # half. This does not depend on the fixture's own ftrace/kallsyms lists
    # happening to already cover 100% of the listing.
    raw = _corroborators(raw, ftrace=original[:1], kallsyms=original[1:])

    sigs = signals_over_listed(Snapshot.from_dict(raw))
    assert [s.suspect.name for s in sigs] == ["phantom_mod"]
    assert sigs[0].channel == "over_listed"
    assert channel_notes(Snapshot.from_dict(raw)) == []   # partial, not a flood


def test_unavailable_kallsyms_suppresses_the_signal_entirely():
    raw = _mutate("infected-hooktest.json")
    listed = _obs(raw, "procfs.modules")["entity_ids"]
    # Partial corroboration -- neither empty (which would instead trip the
    # "every module uncorroborated" ChannelNote guard) nor full -- so
    # unavailability is the only thing standing between the detector and a
    # real signal for the other 73 modules.
    raw = _corroborators(raw, ftrace=listed[:1], kallsyms=[])
    _obs(raw, "kernel.hooks")["stats"]["kallsyms_available"] = False
    assert signals_over_listed(Snapshot.from_dict(raw)) == []


def test_unavailable_ftrace_also_suppresses_the_signal_entirely():
    raw = _mutate("infected-hooktest.json")
    listed = _obs(raw, "procfs.modules")["entity_ids"]
    raw = _corroborators(raw, ftrace=[], kallsyms=listed[:1])
    _obs(raw, "kernel.module_evidence")["stats"]["ftrace_available"] = False
    assert signals_over_listed(Snapshot.from_dict(raw)) == []


def test_all_modules_uncorroborated_emits_a_note_not_a_flood_of_findings():
    # A readable-but-empty /proc/kallsyms (and an equally silent ftrace) still
    # reports both channels available=True with no names. Every listed module
    # comes up uncorroborated: that is evidence about the channel pair, not
    # that every legitimate module is hiding, so it must not flood the report
    # with one finding per module (spec section 5.2, the P12 behaviour change).
    raw = _corroborators(_mutate("infected-hooktest.json"), ftrace=[], kallsyms=[])
    listed = _obs(raw, "procfs.modules")["entity_ids"]
    assert len(listed) > 0
    assert signals_over_listed(Snapshot.from_dict(raw)) == []

    notes = channel_notes(Snapshot.from_dict(raw))
    over_listed_notes = [n for n in notes if n.channel == "over_listed"]
    assert len(over_listed_notes) == 1
    note = over_listed_notes[0]
    assert isinstance(note, ChannelNote)
    assert note.reason == "uncorroborated"
    assert note.detail["listed"] == len(listed)


def test_partial_uncorroboration_still_emits_signals_not_a_note():
    raw = _mutate("infected-hooktest.json")
    listed = _obs(raw, "procfs.modules")["entity_ids"]
    # Every module but the last is corroborated; the note guard requires ALL
    # of them to be uncorroborated, so this must take the ordinary signal path.
    raw = _corroborators(raw, ftrace=listed[:-1], kallsyms=[])
    sigs = signals_over_listed(Snapshot.from_dict(raw))
    assert [s.suspect.name for s in sigs] == [listed[-1]]
    assert channel_notes(Snapshot.from_dict(raw)) == []
