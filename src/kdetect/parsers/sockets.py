"""Pure parsers for the socket-view channels (spec §4).

Text in, typed values out, no I/O. The /proc/net/{tcp,udp}[6] tables share a
column layout; unix/netlink/packet/raw differ, but for those we need only the
inode column (to decide an fd socket is "in some table", not hidden). Each case
mirrors docs/step0-phase4/.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


class SocketParseError(ValueError):
    """A /proc/net socket table could not be parsed."""


@dataclass(frozen=True)
class NetRow:
    inode: int
    kind: str                 # "tcp" | "tcp6" | "udp" | "udp6"
    state: str | None
    local: str | None
    remote: str | None
    uid: int | None


#: TCP state codes (hex) -> name. UDP reuses the column; unknown codes pass
#: through as the raw hex so nothing is silently mislabelled.
_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}


def _decode_addr(hexaddr: str) -> str:
    """'0100007F:0035' -> '127.0.0.1:53'. v4 = 8 hex (little-endian word),
    v6 = 32 hex (four little-endian 32-bit words)."""
    ip_hex, _, port_hex = hexaddr.partition(":")
    port = int(port_hex, 16)
    if len(ip_hex) == 8:
        packed = struct.pack("<I", int(ip_hex, 16))
        ip = socket.inet_ntop(socket.AF_INET, packed)
    elif len(ip_hex) == 32:
        raw = bytes.fromhex(ip_hex)
        packed = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        ip = socket.inet_ntop(socket.AF_INET6, packed)
    else:
        raise SocketParseError(f"bad address field: {hexaddr!r}")
    return f"{ip}:{port}"


def parse_net_tcp(text: str, kind: str) -> list[NetRow]:
    """Parse a /proc/net/{tcp,tcp6,udp,udp6} table into NetRows."""
    rows: list[NetRow] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] == "sl" or not parts[0].endswith(":"):
            continue                       # header or blank
        if len(parts) < 10:
            raise SocketParseError(f"short {kind} row: {line!r}")
        try:
            rows.append(NetRow(
                inode=int(parts[9]), kind=kind,
                state=_STATES.get(parts[3].upper(), parts[3]),
                local=_decode_addr(parts[1]), remote=_decode_addr(parts[2]),
                uid=int(parts[7]),
            ))
        except (ValueError, IndexError) as exc:
            raise SocketParseError(f"bad {kind} row: {line!r}") from exc
    return rows


def parse_net_inodes(text: str, inode_index: int) -> set[int]:
    """The set of inode numbers in a table where inode is a fixed column.
    Non-numeric/short lines (headers) are skipped."""
    out: set[int] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) <= inode_index:
            continue
        try:
            out.add(int(parts[inode_index]))
        except ValueError:
            continue                       # header row
    return out
