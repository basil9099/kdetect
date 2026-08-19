import pytest
from tests.conftest import needs_procfs
from kdetect.collectors.sources import (
    LiveSignalSource, LiveModuleSource,
)
from kdetect.collectors.syscall_sweep import SweepProcessCollector
from kdetect.collectors.modules import ProcfsModuleCollector, ModuleEvidenceCollector

@needs_procfs
def test_sweep_finds_at_least_pid_1():
    obs = SweepProcessCollector().collect(LiveSignalSource())
    assert 1 in obs.entity_ids
    assert obs.entities[1].tgid == 1

@needs_procfs
def test_procfs_modules_nonempty_and_evidence_reads():
    listing = ProcfsModuleCollector().collect(LiveModuleSource())
    assert listing.entity_ids                      # some modules are loaded
    ev = ModuleEvidenceCollector().collect(LiveModuleSource())
    assert "taint" in ev.stats
