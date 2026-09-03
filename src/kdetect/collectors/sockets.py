"""The socket-view collector (spec §4.2, as amended after the phase-4a step-0).

procfs.sockets (LOW) records one SocketEntity per socket in the /proc/net TCP/UDP
tables, and attributes each to the processes that hold it as an fd. It never
concludes: in_table and owner_pids are evidence; the differ (signals_sockets)
decides whether an in_table socket owned by a readdir-hidden pid confirms that
process (socket_visible -> HIGH hidden_process). It walks fds only for the pids
it is given (P10).

Only the four rich families (tcp/tcp6/udp/udp6) are read: the phase-4a step-0
calibration on a clean host showed that the "a held fd in no /proc/net table is
hidden" direction false-positives on legitimate socket families /proc/net does
not expose at all (AF_VSOCK from open-vm-tools, dbus sockets, ...), so that
signal was dropped (docs/limitations.md L25). Sound hidden-connection detection
needs an independent sock_diag channel, which is deferred. Consequently the
collector no longer reads the inode-only families or records fd-only sockets.
"""
from __future__ import annotations

import time

from kdetect.collectors.base import SocketSource
from kdetect.models import Observation, SocketEntity, Status, TrustLevel
from kdetect.parsers.sockets import parse_net_tcp

#: The families whose tables carry the detail socket_visible needs. A network
#: backdoor listens on tcp/udp, so these are the ones that matter for the
#: hidden-process correlation.
_RICH = ("tcp", "tcp6", "udp", "udp6")


class SocketCollector:
    name = "procfs.sockets"
    view = "sockets"
    trust_level = TrustLevel.LOW
    version = "1"

    def __init__(self, pids: set[int]) -> None:
        self._pids = set(pids)

    def collect(self, source: SocketSource) -> Observation:
        started = time.monotonic()
        entities: dict[str, SocketEntity] = {}
        tables_read = 0

        for kind in _RICH:
            text = source.read_net_table(kind)
            if text is None:
                continue
            tables_read += 1
            for r in parse_net_tcp(text, kind):
                entities[str(r.inode)] = SocketEntity(
                    r.inode, r.kind, r.state, r.local, r.remote, r.uid,
                    in_table=True, owner_pids=[])

        # Attribute ownership by walking the given pids' fds. Only inodes that
        # are in a rich table matter; fd inodes of other families (unix, netlink,
        # vsock, ...) are ignored -- they cannot be judged from /proc/net (L25).
        owners: dict[str, set[int]] = {}
        for pid in self._pids:
            for inode in source.list_fds(pid):
                key = str(inode)
                if key in entities:
                    owners.setdefault(key, set()).add(pid)

        for key, pids in owners.items():
            e = entities[key]
            entities[key] = SocketEntity(
                e.inode, e.kind, e.state, e.local, e.remote, e.uid,
                e.in_table, sorted(pids))

        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=sorted(entities), entities=entities,
            stats={"tables_read": tables_read, "sockets": len(entities),
                   "pids_walked": len(self._pids)},
            errors=[],
        )
