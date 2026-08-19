from pathlib import Path

from kdetect.collectors.sources import FixtureSignalSource

FIX = Path(__file__).parent.parent / "fixtures" / "signal-sets" / "hidden-pid.json"


def test_sweep_returns_recorded_alive_ids():
    s = FixtureSignalSource(FIX)
    assert s.pid_max() == 4194304
    assert s.sweep(s.pid_max()) == [1, 2, 501, 551, 31337]


def test_read_tgid_folds_thread_to_leader():
    s = FixtureSignalSource(FIX)
    assert s.read_tgid(551) == 501            # thread of 501
    assert s.read_tgid(31337) == 31337        # its own leader


def test_read_tgid_none_when_status_unreadable():
    s = FixtureSignalSource(FIX)
    assert s.read_tgid(2) is None             # kernel thread, status not read
