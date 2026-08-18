import json

from kdetect.models import (
    CaptureMeta,
    CollectionError,
    ErrorKind,
    HostFacts,
    Observation,
    ProcessEntity,
    Snapshot,
    Status,
    TrustLevel,
)


def _entity(pid, comm, flags, exe, partial):
    return ProcessEntity(
        pid=pid, ppid=0, comm=comm, state="S", flags=flags,
        num_threads=1, starttime_ticks=6, cmdline=[], exe=exe,
        uid=[0, 0, 0, 0], gid=[0, 0, 0, 0], partial=partial,
    )


def make_snapshot():
    systemd = _entity(1, "systemd", 4194560, "/usr/lib/systemd/systemd", [])
    kthreadd = _entity(2, "kthreadd", 2129984, None, [])
    denied = _entity(812, "sshd", 4194304, None, ["exe"])
    obs = Observation(
        collector="procfs.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=84,
        entity_ids=[1, 2, 812],
        entities={1: systemd, 2: kthreadd, 812: denied},
        stats={"scanned": 4, "collected": 3, "vanished": 1},
        errors=[CollectionError(entity_id=4171, kind=ErrorKind.VANISHED,
                                detail="ENOENT reading stat")],
    )
    return Snapshot(
        schema_version="1.0",
        snapshot_id="b3f1c8e2-7a4d-4f19-9c2e-1d8a3f5b6c07",
        captured_at="2026-08-18T02:01:08.412Z",
        host=HostFacts(hostname="kdetect-lab", kernel_release="6.1.0-10-amd64",
                       arch="x86_64", boot_id="4fa7045a", btime=1787032782,
                       clock_ticks_per_sec=100),
        capture=CaptureMeta(tool_version="0.1.0", euid=0),
        observations=[obs],
    )


def test_roundtrip_equals_original():
    s = make_snapshot()
    assert Snapshot.from_dict(s.to_dict()) == s


def test_reserialisation_is_byte_identical():
    s = make_snapshot()
    once = s.to_json()
    twice = Snapshot.from_dict(json.loads(once)).to_json()
    assert once == twice


def test_entity_keys_survive_as_integers():
    # JSON object keys are always strings. This is the classic round-trip bug.
    s = make_snapshot()
    raw = json.loads(s.to_json())
    assert set(raw["observations"][0]["entities"]) == {"1", "2", "812"}
    back = Snapshot.from_dict(raw)
    assert set(back.observations[0].entities) == {1, 2, 812}


def test_entities_keys_are_subset_of_entity_ids():
    s = make_snapshot()
    obs = s.observations[0]
    assert set(obs.entities).issubset(set(obs.entity_ids))


def test_exe_three_states_are_distinguishable():
    s = Snapshot.from_dict(make_snapshot().to_dict())
    ents = s.observations[0].entities
    assert ents[1].exe == "/usr/lib/systemd/systemd" and ents[1].partial == []
    assert ents[2].exe is None and ents[2].partial == []      # ENOENT
    assert ents[812].exe is None and ents[812].partial == ["exe"]  # EACCES


def test_entity_ids_are_sorted_ascending():
    raw = json.loads(make_snapshot().to_json())
    ids = raw["observations"][0]["entity_ids"]
    assert ids == sorted(ids)


def test_enums_serialise_as_their_string_values():
    raw = json.loads(make_snapshot().to_json())
    obs = raw["observations"][0]
    assert obs["trust_level"] == "LOW"
    assert obs["status"] == "OK"
    assert obs["errors"][0]["kind"] == "vanished"


def test_pretty_and_compact_carry_the_same_data():
    s = make_snapshot()
    assert json.loads(s.to_json(pretty=True)) == json.loads(s.to_json())
