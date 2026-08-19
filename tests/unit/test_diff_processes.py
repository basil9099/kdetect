from kdetect.analysis.crossview import diff_processes
from kdetect.analysis.models import FindingKind, Confidence
from kdetect.models import (
    Snapshot, Observation, SweepEntity, HostFacts, CaptureMeta,
    Status, TrustLevel, SCHEMA_VERSION,
)

def _host():
    return HostFacts("h", "6.1", "x86_64", "boot", 1, 100)

def _proc_pass(label, pids):
    return Observation(
        collector="procfs.processes", collector_version="1", view="processes",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(pids), entities={}, stats={}, errors=[], pass_=label,
    )

def _sweep(tgid_map):
    # tgid_map: {task_id: (tgid, status_readable)}
    ents = {i: SweepEntity(t, r) for i, (t, r) in tgid_map.items()}
    return Observation(
        collector="syscall_sweep.processes", collector_version="1",
        view="processes", trust_level=TrustLevel.MEDIUM, status=Status.OK,
        duration_ms=1, entity_ids=sorted(tgid_map), entities=ents,
        stats={"pid_max": 4194304, "responded": len(tgid_map)}, errors=[],
    )

def _snap(observations):
    return Snapshot(SCHEMA_VERSION, "id", "t", _host(),
                    CaptureMeta("0.2.0", 0), observations)

def test_threads_are_not_hidden_processes():
    # 501 is listed; 551 is its thread (tgid 501). No finding.
    snap = _snap([_proc_pass("A", [1, 501]), _proc_pass("B", [1, 501]),
                  _sweep({1: (1, True), 501: (501, True), 551: (501, True)})])
    assert diff_processes(snap) == []

def test_hidden_process_detected():
    # 31337 seen by sweep, its own leader, in neither pass -> hidden.
    snap = _snap([_proc_pass("A", [1, 501]), _proc_pass("B", [1, 501]),
                  _sweep({1: (1, True), 501: (501, True), 31337: (31337, True)})])
    findings = diff_processes(snap)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.HIDDEN_PROCESS
    assert f.subject == "pid 31337"
    assert f.evidence["tgid"] == 31337
    assert f.evidence["seen_by_sweep"] is True
    assert f.evidence["in_procfs_passes"] == []
    assert f.evidence["status_readable"] is True
    assert f.confidence is Confidence.MEDIUM     # existence only, no identity

def test_absent_from_one_pass_only_is_timing_not_hiding():
    # 4242 appeared in pass B only (started mid-capture). Not hidden.
    snap = _snap([_proc_pass("A", [1]), _proc_pass("B", [1, 4242]),
                  _sweep({1: (1, True), 4242: (4242, True)})])
    assert diff_processes(snap) == []

def test_unreadable_status_is_vanished_not_hidden():
    snap = _snap([_proc_pass("A", [1]), _proc_pass("B", [1]),
                  _sweep({1: (1, True), 9999: (9999, False)})])
    assert diff_processes(snap) == []

def test_hidden_process_with_threads_yields_one_finding():
    # 31337 is hidden and has two extra threads (31338, 31339) also
    # answering the sweep under the same tgid. Still exactly one finding.
    snap = _snap([_proc_pass("A", [1, 501]), _proc_pass("B", [1, 501]),
                  _sweep({1: (1, True), 501: (501, True),
                          31337: (31337, True), 31338: (31337, True),
                          31339: (31337, True)})])
    findings = diff_processes(snap)
    assert len(findings) == 1
    assert findings[0].subject == "pid 31337"
