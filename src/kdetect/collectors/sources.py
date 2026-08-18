"""Concrete ProcSource implementations.

LiveProcSource reads a real /proc. FixtureProcSource (task 7) replays a
captured tree, including recorded failures.
"""

from __future__ import annotations

import errno
import os

from kdetect.collectors.base import (
    Denied,
    ProcSource,
    ProcSourceError,
    Unreadable,
    Vanished,
)

#: errno values that mean "gone, or never existed".
_VANISHED_ERRNOS = frozenset({errno.ENOENT, errno.ESRCH})

#: errno values that mean "exists, not permitted".
_DENIED_ERRNOS = frozenset({errno.EACCES, errno.EPERM})


def _translate(exc: OSError, what: str) -> ProcSourceError:
    """Map an OSError onto the domain error hierarchy.

    Every read in this module funnels through here. If an OSError ever escapes
    a ProcSource, the seam has leaked and fixtures can no longer reproduce the
    failure paths that matter most.
    """
    detail = f"{what}: {exc.strerror} (errno {exc.errno})"
    if exc.errno in _VANISHED_ERRNOS:
        return Vanished(detail)
    if exc.errno in _DENIED_ERRNOS:
        return Denied(detail)
    return Unreadable(detail)


class LiveProcSource(ProcSource):
    """Reads the running system's /proc."""

    root = "/proc"

    def list_pids(self) -> list[int]:
        """Numeric entries of /proc, sorted.

        /proc also holds non-numeric entries - "self", "meminfo", "modules"
        and so on - which are filtered out. isdigit() is the right filter
        because a pid directory name is always decimal digits only.
        """
        try:
            names = os.listdir(self.root)
        except OSError as exc:
            raise _translate(exc, f"listing {self.root}") from exc
        return sorted(int(n) for n in names if n.isdigit())

    def read_text(self, pid: int, name: str) -> str:
        path = f"{self.root}/{pid}/{name}"
        try:
            # errors="replace" because cmdline is raw bytes and need not be
            # valid UTF-8. Lossy, and recorded as limitation L9.
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError as exc:
            raise _translate(exc, f"reading {path}") from exc

    def read_link(self, pid: int, name: str) -> str:
        path = f"{self.root}/{pid}/{name}"
        try:
            return os.readlink(path)
        except OSError as exc:
            raise _translate(exc, f"resolving {path}") from exc
