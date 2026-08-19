from kdetect.analysis.models import Finding, FindingKind, Confidence

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
