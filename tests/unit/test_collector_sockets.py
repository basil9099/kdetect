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


def test_fd_inode_outside_rich_tables_is_ignored():
    # inode 55555 (owned by pid 4171 in the fixture) is in no tcp/udp table --
    # it stands in for a unix/vsock/etc. socket, which /proc/net cannot classify.
    # Only rich-table sockets become entities (L25), so it is dropped, not flagged.
    obs = _collect([812, 900, 4171])
    assert "55555" not in obs.entities


def test_unwalked_pids_leave_socket_unowned():
    obs = _collect([])                       # walk no fds
    assert obs.entities["12345"].owner_pids == []   # still in_table from the table
    assert "55555" not in obs.entities              # fd inode never recorded


def test_observation_round_trips():
    obs = _collect([812, 900, 4171])
    assert Observation.from_dict(obs.to_dict()) == obs
