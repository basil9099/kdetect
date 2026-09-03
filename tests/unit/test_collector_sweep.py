from pathlib import Path
from kdetect.collectors.syscall_sweep import SweepProcessCollector
from kdetect.collectors.sources import FixtureSignalSource
from kdetect.models import Status, TrustLevel

FIX = Path(__file__).parent.parent / "fixtures" / "signal-sets" / "hidden-pid.json"

def test_sweep_collector_records_tgid_evidence():
    obs = SweepProcessCollector().collect(FixtureSignalSource(FIX))
    assert obs.collector == "syscall_sweep.processes"
    assert obs.view == "processes"
    assert obs.trust_level is TrustLevel.MEDIUM
    assert obs.status is Status.OK
    assert obs.entity_ids == [1, 2, 501, 551, 31337]
    assert obs.entities[551].tgid == 501
    assert obs.entities[551].status_readable is True
    assert obs.entities[2].status_readable is False   # unreadable status
    assert obs.stats["responded"] == 5
    assert obs.stats["pid_max"] == 4194304


def test_sweep_records_comm():
    obs = SweepProcessCollector().collect(FixtureSignalSource(FIX))
    # the hidden pid in the fixture carries a comm
    hidden = [e for e in obs.entities.values() if e.comm == "evil"]
    assert hidden, "expected a swept entity with comm 'evil'"
