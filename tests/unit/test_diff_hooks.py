from kdetect.analysis.crossview import diff_hooks
from kdetect.analysis.models import Confidence, FindingKind
from kdetect.models import (
    HookEntity, ModuleEntity, Observation, Snapshot, Status, TrustLevel,
    CaptureMeta, HostFacts, SCHEMA_VERSION,
)

def _host():
    return HostFacts(hostname="t", kernel_release="6.1", arch="x86_64",
                     boot_id="b", btime=1, clock_ticks_per_sec=100)

def _snap(hook_entities, listed_modules):
    hooks = Observation(
        collector="kernel.hooks", collector_version="1", view="kernel_hooks",
        trust_level=TrustLevel.MEDIUM, status=Status.OK, duration_ms=1,
        entity_ids=sorted(hook_entities), entities=hook_entities,
        stats={}, errors=[], extra={"kallsyms_modules": []},
    )
    mods = Observation(
        collector="procfs.modules", collector_version="1", view="modules",
        trust_level=TrustLevel.LOW, status=Status.OK, duration_ms=1,
        entity_ids=sorted(listed_modules),
        entities={m: ModuleEntity(m, 1, 0, [], "Live", "0x0", None)
                  for m in listed_modules},
        stats={}, errors=[],
    )
    return Snapshot(SCHEMA_VERSION, "id", "t", _host(),
                    CaptureMeta("0.1.0", 0), [hooks, mods])

def test_orphan_hook_fires_without_baseline():
    # callback owned by a module NOT in the listing -> orphan
    ents = {"ftrace:sys_x": HookEntity("sys_x", "ftrace", "evil", "hidden_mod")}
    findings = diff_hooks(_snap(ents, listed_modules=["ext4"]))
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.UNEXPECTED_HOOK
    assert f.confidence is Confidence.LOW          # one channel (orphan only)
    assert f.evidence["owner_module"] == "hidden_mod"

def test_attributable_hook_does_not_fire():
    ents = {"ftrace:sys_x": HookEntity("sys_x", "ftrace", "cb", "ext4")}
    assert diff_hooks(_snap(ents, listed_modules=["ext4"])) == []

def test_orphan_plus_baseline_drift_is_medium():
    ents = {"ftrace:sys_x": HookEntity("sys_x", "ftrace", "evil", None)}
    current = _snap(ents, listed_modules=["ext4"])
    baseline = _snap({}, listed_modules=["ext4"])   # hook absent when clean
    findings = diff_hooks(current, baseline)
    assert findings[0].confidence is Confidence.MEDIUM   # orphan + drift

def test_kprobe_without_callback_is_not_orphan():
    # a kprobe (callback=None, owner_module=None), no baseline -> no finding
    ents = {"kprobe:do_stuff": HookEntity("do_stuff", "kprobe", None, None)}
    assert diff_hooks(_snap(ents, listed_modules=["ext4"])) == []
