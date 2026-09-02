from kdetect.analysis.models import Finding, FindingKind, Confidence, Suspect, Signal

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
