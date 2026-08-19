from kdetect.analysis.crossview import diff_modules, diff_all, diff_processes
from kdetect.analysis.models import FindingKind, Confidence
from kdetect.models import (
    Snapshot, Observation, ModuleEntity, SweepEntity, HostFacts, CaptureMeta,
    Status, TrustLevel, SCHEMA_VERSION,
)

def _host(): return HostFacts("h", "6.1", "x86_64", "boot", 1, 100)

def _listing(names):
    ents = {n: ModuleEntity(n, 1, 0, [], "Live", "0x0", None) for n in names}
    return Observation("procfs.modules", "1", "modules", TrustLevel.LOW,
                       Status.OK, 1, sorted(names), ents, {"listed": len(names)}, [])

def _evidence(taint, markers, regions, ftrace):
    return Observation("kernel.module_evidence", "1", "modules",
                       TrustLevel.MEDIUM, Status.OK, 1, [], {},
                       {"taint": taint, "load_module_regions": regions,
                        "ftrace_available": ftrace is not None,
                        "ftrace_module_count": len(ftrace or [])},
                       [], extra={"listed_taint_markers": markers,
                                  "ftrace_modules": ftrace})

def _snap(obs):
    return Snapshot(SCHEMA_VERSION, "id", "t", _host(), CaptureMeta("0.2.0", 0), obs)

def test_clean_baseline_no_findings():
    snap = _snap([_listing(["ext4", "crc16"]),
                  _evidence(0, 0, 2, ["ext4"])])   # ftrace subset of listing
    # region count 2 == listed 2; taint clear; ftrace subset -> nothing
    assert diff_modules(snap) == []

def test_taint_mismatch():
    snap = _snap([_listing(["ext4"]), _evidence(12288, 0, 1, ["ext4"])])
    kinds = [f.kind for f in diff_modules(snap)]
    assert FindingKind.MODULE_TAINT_MISMATCH in kinds

def test_unexplained_region():
    snap = _snap([_listing(["ext4"]), _evidence(0, 0, 2, ["ext4"])])
    kinds = [f.kind for f in diff_modules(snap)]
    assert FindingKind.UNEXPLAINED_MODULE_REGION in kinds

def test_ftrace_orphan_names_module():
    snap = _snap([_listing(["ext4"]), _evidence(0, 0, 1, ["ext4", "diamorphine"])])
    orphans = [f for f in diff_modules(snap)
               if f.kind is FindingKind.FTRACE_ORPHAN_MODULE]
    assert len(orphans) == 1 and orphans[0].subject == "module diamorphine"

def test_corroborated_hidden_module_is_high_confidence():
    # taint mismatch + extra region + ftrace orphan all point at a hidden module
    snap = _snap([_listing(["ext4"]),
                  _evidence(12288, 0, 2, ["ext4", "diamorphine"])])
    orphan = [f for f in diff_modules(snap)
              if f.kind is FindingKind.FTRACE_ORPHAN_MODULE][0]
    assert orphan.confidence is Confidence.HIGH   # 3 channels corroborate

def test_null_channels_are_skipped():
    snap = _snap([_listing(["ext4"]), _evidence(0, 0, None, None)])
    assert diff_modules(snap) == []

def test_taint_hit_with_null_siblings_stays_low():
    # taint fires alone; region and ftrace channels are both None and must
    # not count toward corroboration.
    snap = _snap([_listing(["ext4"]), _evidence(12288, 0, None, None)])
    findings = diff_modules(snap)
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.MODULE_TAINT_MISMATCH
    assert findings[0].confidence is Confidence.LOW

def test_taint_bit_13_alone_fires():
    # 8192 = bit 13 (unsigned) only, bit 12 (out-of-tree) clear.
    snap = _snap([_listing(["ext4"]), _evidence(8192, 0, 1, ["ext4"])])
    kinds = [f.kind for f in diff_modules(snap)]
    assert FindingKind.MODULE_TAINT_MISMATCH in kinds

def test_two_channel_corroboration_is_medium():
    # taint fires + region overhang; ftrace stays a subset of the listing.
    snap = _snap([_listing(["ext4"]), _evidence(12288, 0, 2, ["ext4"])])
    findings = diff_modules(snap)
    kinds = [f.kind for f in findings]
    assert FindingKind.MODULE_TAINT_MISMATCH in kinds
    assert FindingKind.UNEXPLAINED_MODULE_REGION in kinds
    assert all(f.confidence is Confidence.MEDIUM for f in findings)

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

def test_diff_all_merges_process_and_module_findings():
    # Hidden process 31337 (seen by sweep, in neither procfs pass) AND a
    # hidden module (taint bit set, no listed marker) in the same snapshot.
    snap = _snap([
        _proc_pass("A", [1, 501]), _proc_pass("B", [1, 501]),
        _sweep({1: (1, True), 501: (501, True), 31337: (31337, True)}),
        _listing(["ext4"]), _evidence(12288, 0, 1, ["ext4"]),
    ])
    result = diff_all(snap)
    kinds = {f.kind for f in result}
    assert FindingKind.HIDDEN_PROCESS in kinds
    assert FindingKind.MODULE_TAINT_MISMATCH in kinds
    assert len(result) == len(diff_processes(snap)) + len(diff_modules(snap))
