from pathlib import Path

from kdetect.collectors.kernel_hooks import KernelHookCollector
from kdetect.collectors.sources import FixtureKernelHookSource
from kdetect.models import Observation, TrustLevel

CLEAN = Path(__file__).parent.parent / "fixtures" / "hook-trees" / "clean"
HOOKED = Path(__file__).parent.parent / "fixtures" / "hook-trees" / "hooked"


def test_collector_attributes_hook_to_its_module():
    obs = KernelHookCollector().collect(FixtureKernelHookSource(HOOKED))
    assert obs.trust_level is TrustLevel.MEDIUM
    assert obs.view == "kernel_hooks"
    e = obs.entities["ftrace:__x64_sys_newuname"]
    assert e.callback and "kdetect_callback" in e.callback
    assert e.owner_module == "kdetect_hooktest"


def test_collector_records_absent_channel_as_unavailable(tmp_path):
    # no files at all -> channels unavailable, no entities, still status OK
    obs = KernelHookCollector().collect(FixtureKernelHookSource(tmp_path))
    assert obs.entity_ids == []
    assert obs.stats["enabled_functions_available"] is False


def test_collector_observation_round_trips():
    obs = KernelHookCollector().collect(FixtureKernelHookSource(HOOKED))
    assert Observation.from_dict(obs.to_dict()) == obs
