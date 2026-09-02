from kdetect.analysis.models import Finding, FindingKind, Confidence, Suspect, Signal
from kdetect.models import SocketEntity, Observation, Status, TrustLevel

def test_finding_to_dict_is_deterministic_and_sorted():
    f = Finding(
        kind=FindingKind.HIDDEN_PROCESS, subject="pid 31337",
        confidence=Confidence.HIGH,
        channels_agree=["syscall_sweep", "direct status"],
        channels_dissent=["procfs readdir (both passes)"],
        evidence={"tgid": 31337, "in_procfs_A": False, "in_procfs_B": False},
        summary="pid 31337 seen by sweep, absent from both readdir passes",
    )
    d = f.to_dict()
    assert d["kind"] == "hidden_process"
    assert d["confidence"] == "HIGH"
    assert d["evidence"]["tgid"] == 31337
    # stable ordering: same object serialises identically
    import json
    assert json.dumps(d, sort_keys=True) == json.dumps(f.to_dict(), sort_keys=True)

def test_suspect_and_signal_are_frozen_value_types():
    s = Suspect("module", "diamorphine")
    assert s == Suspect("module", "diamorphine")
    sig = Signal("ftrace_orphan", s, "procfs.modules listing", {"in_listing": False})
    assert sig.channel == "ftrace_orphan"
    assert sig.suspect.name == "diamorphine"
    assert sig.evidence == {"in_listing": False}

def test_anonymous_suspect_has_no_name():
    assert Suspect("module", None).name is None

def test_new_finding_kinds_exist():
    assert FindingKind.HIDDEN_MODULE.value == "hidden_module"
    assert FindingKind.SUSPECTED_HIDDEN_MODULE.value == "suspected_hidden_module"

def test_hidden_connection_kind_exists():
    assert FindingKind.HIDDEN_CONNECTION.value == "hidden_connection"

def test_socket_entity_roundtrips():
    e = SocketEntity(inode=12345, kind="tcp", state="LISTEN",
                     local="0.0.0.0:22", remote="0.0.0.0:0", uid=0,
                     in_table=True, owner_pids=[812])
    assert SocketEntity.from_dict(e.to_dict()) == e

def test_socket_entity_fd_only_has_nulls():
    e = SocketEntity(inode=999, kind="unknown", state=None, local=None,
                     remote=None, uid=None, in_table=False, owner_pids=[4171])
    back = SocketEntity.from_dict(e.to_dict())
    assert back.in_table is False and back.state is None

def test_sockets_observation_uses_string_inode_ids():
    obs = Observation(
        collector="procfs.sockets", collector_version="1", view="sockets",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=["12345"],
        entities={"12345": SocketEntity(12345, "tcp", "LISTEN",
                  "0.0.0.0:22", "0.0.0.0:0", 0, True, [812])},
        stats={}, errors=[],
    )
    back = Observation.from_dict(obs.to_dict())
    assert back == obs
    assert list(back.entities.keys()) == ["12345"]   # stayed str
