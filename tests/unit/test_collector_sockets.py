from pathlib import Path

from kdetect.collectors.sockets import SocketCollector
from kdetect.collectors.sources import FixtureSocketSource
from kdetect.models import Observation, TrustLevel

BASIC = Path(__file__).parent.parent / "fixtures" / "socket-trees" / "basic"


def _collect(pids):
    return SocketCollector(set(pids)).collect(FixtureSocketSource(BASIC))


def test_table_socket_attributed_to_owner():
    obs = _collect([812, 900, 4171])
    assert obs.trust_level is TrustLevel.LOW and obs.view == "sockets"
    e = obs.entities["12345"]
    assert e.in_table is True and e.state == "LISTEN" and e.owner_pids == [812]


def test_fd_only_socket_is_not_in_table():
    obs = _collect([812, 900, 4171])
    e = obs.entities["55555"]
    assert e.in_table is False and e.kind == "unknown" and e.owner_pids == [4171]


def test_unwalked_pids_leave_socket_unowned():
    obs = _collect([])                       # walk no fds
    assert obs.entities["12345"].owner_pids == []   # still in_table from the table
    assert "55555" not in obs.entities              # fd-only inode never seen


def test_observation_round_trips():
    obs = _collect([812, 900, 4171])
    assert Observation.from_dict(obs.to_dict()) == obs
