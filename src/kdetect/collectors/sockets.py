"""The socket-view collector (spec §4.2).

procfs.sockets (LOW) records one SocketEntity per inode seen in a /proc/net/*
table or a walked /proc/<pid>/fd. It never concludes: in_table and owner_pids
are evidence; the differ decides "hidden connection" and "confirms a hidden
process". It walks fds only for the pids it is given (P10).
"""
from __future__ import annotations

import time

from kdetect.collectors.base import SocketSource
from kdetect.models import Observation, SocketEntity, Status, TrustLevel
from kdetect.parsers.sockets import parse_net_inodes, parse_net_tcp

#: Rich tables (shared tcp/udp layout) and the inode column for the rest.
_RICH = ("tcp", "tcp6", "udp", "udp6")
_INODE_ONLY = {"unix": 6, "netlink": 9, "packet": 8, "raw": 9, "raw6": 9}


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

        # Rich tcp/udp tables: full detail.
        for kind in _RICH:
            text = source.read_net_table(kind)
            if text is None:
                continue
            tables_read += 1
            for r in parse_net_tcp(text, kind):
                entities[str(r.inode)] = SocketEntity(
                    r.inode, r.kind, r.state, r.local, r.remote, r.uid,
                    in_table=True, owner_pids=[])

        # Inode-only families: just mark in_table so their inodes aren't "hidden".
        for name, idx in _INODE_ONLY.items():
            text = source.read_net_table(name)
            if text is None:
                continue
            tables_read += 1
            for inode in parse_net_inodes(text, idx):
                key = str(inode)
                if key not in entities:
                    entities[key] = SocketEntity(
                        inode, name, None, None, None, None,
                        in_table=True, owner_pids=[])

        # Attribute ownership by walking the given pids' fds.
        owners: dict[str, set[int]] = {}
        for pid in self._pids:
            for inode in source.list_fds(pid):
                owners.setdefault(str(inode), set()).add(pid)

        for key, pids in owners.items():
            if key in entities:
                e = entities[key]
                entities[key] = SocketEntity(
                    e.inode, e.kind, e.state, e.local, e.remote, e.uid,
                    e.in_table, sorted(pids))
            else:                            # fd inode in no table -> unknown, hidden
                entities[key] = SocketEntity(
                    int(key), "unknown", None, None, None, None,
                    in_table=False, owner_pids=sorted(pids))

        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=sorted(entities), entities=entities,
            stats={"tables_read": tables_read, "sockets": len(entities),
                   "pids_walked": len(self._pids)},
            errors=[],
        )
