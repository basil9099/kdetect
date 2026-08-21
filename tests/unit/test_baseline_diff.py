from kdetect.analysis import baseline_diff
from kdetect.analysis.models import Confidence, FindingKind
from kdetect.models import (
    ModuleEntity, Observation, Snapshot, Status, TrustLevel,
    CaptureMeta, HostFacts, SCHEMA_VERSION,
)

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

def test_added_module_is_medium_drift():
    findings = baseline_diff.diff(_snap(["ext4", "evil"]), _snap(["ext4"]))
    added = [f for f in findings if f.evidence["direction"] == "added"]
    assert len(added) == 1
    assert added[0].kind is FindingKind.BASELINE_DRIFT
    assert added[0].confidence is Confidence.MEDIUM
    assert added[0].subject == "module evil"

def test_removed_module_is_low_informational():
    findings = baseline_diff.diff(_snap(["ext4"]), _snap(["ext4", "gone"]))
    removed = [f for f in findings if f.evidence["direction"] == "removed"]
    assert removed[0].confidence is Confidence.LOW

def test_identical_is_no_findings():
    assert baseline_diff.diff(_snap(["ext4"]), _snap(["ext4"])) == []
