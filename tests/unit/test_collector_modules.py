from pathlib import Path

from kdetect.collectors.modules import ProcfsModuleCollector, ModuleEvidenceCollector
from kdetect.collectors.sources import FixtureModuleSource
from kdetect.models import Observation, TrustLevel

CLEAN = Path(__file__).parent.parent / "fixtures" / "module-trees" / "clean"


def test_procfs_modules_lists_loaded_modules_by_name():
    obs = ProcfsModuleCollector().collect(FixtureModuleSource(CLEAN))
    assert obs.trust_level is TrustLevel.LOW
    assert obs.entity_ids == ["crc16", "ext4"]           # names, sorted
    assert obs.entities["ext4"].size == 999424
    assert obs.entities["ext4"].taint is None


def test_module_evidence_records_channels():
    obs = ModuleEvidenceCollector().collect(FixtureModuleSource(CLEAN))
    assert obs.trust_level is TrustLevel.MEDIUM
    assert obs.stats["taint"] == 0
    assert obs.stats["load_module_regions"] == 2
    assert obs.stats["ftrace_available"] is True
    assert set(obs.extra["ftrace_modules"]) == {"ext4"}
    assert obs.extra["listed_taint_markers"] == 0


def test_module_evidence_null_channel_when_unreadable(tmp_path):
    # a tree with no vmallocinfo/ftrace file -> those channels read None
    (tmp_path / "proc_modules.txt").write_text("ext4 1 0 - Live 0x0\n")
    (tmp_path / "tainted.txt").write_text("0\n")
    obs = ModuleEvidenceCollector().collect(FixtureModuleSource(tmp_path))
    assert obs.stats["load_module_regions"] is None
    assert obs.stats["ftrace_available"] is False
    assert obs.extra["ftrace_modules"] is None


def test_module_evidence_observation_round_trips():
    obs = ModuleEvidenceCollector().collect(FixtureModuleSource(CLEAN))
    assert Observation.from_dict(obs.to_dict()) == obs
    assert Observation.from_dict(obs.to_dict()).entities == {}   # kernel.module_evidence -> None entity branch
