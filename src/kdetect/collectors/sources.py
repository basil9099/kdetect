"""Concrete ProcSource implementations.

LiveProcSource reads a real /proc. FixtureProcSource (task 7) replays a
captured tree, including recorded failures.
"""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path

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


class FixtureProcSource(ProcSource):
    """Replays a captured /proc tree, including recorded failures.

    A plain directory of copied files could only reproduce the happy path, but
    every false-positive class in this project lives in the failure paths: the
    kernel thread with no exe, the EACCES read, the process that vanished
    mid-scan. So the tree carries an `_errors.json` sidecar mapping
    "<pid>/<name>" to an errno name, and those reads raise instead of
    returning content.

    Symlinks are stored as <name>.readlink text files - Windows cannot create
    real symlinks without elevated privileges, and this tree is read there.
    """

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self._proc = self.root / "proc"
        errors_path = self.root / "_errors.json"
        self._errors: dict[str, str] = (
            json.loads(errors_path.read_text(encoding="utf-8"))
            if errors_path.exists()
            else {}
        )

    def _recorded_failure(self, pid: int, name: str) -> ProcSourceError | None:
        """The failure recorded for this read, if any.

        Mirrors _translate, but keyed on an errno *name* from the sidecar
        rather than a live OSError. Both funnel into the same three domain
        errors, so the collector cannot tell a replayed failure from a real
        one - which is the point (P3).
        """
        code = self._errors.get(f"{pid}/{name}")
        if code is None:
            return None
        detail = f"replaying recorded {code} for {pid}/{name}"
        if code in ("ENOENT", "ESRCH"):
            return Vanished(detail)
        if code in ("EACCES", "EPERM"):
            return Denied(detail)
        return Unreadable(detail)

    def list_pids(self) -> list[int]:
        """Numeric directories in the tree.

        PID 4171 is an empty directory: it appears here, but every read of it
        fails. That is what a process exiting between the listing and the read
        looks like from outside.
        """
        if not self._proc.is_dir():
            raise Unreadable(f"no proc directory under {self.root}")
        return sorted(int(p.name) for p in self._proc.iterdir() if p.name.isdigit())

    def read_text(self, pid: int, name: str) -> str:
        failure = self._recorded_failure(pid, name)
        if failure is not None:
            raise failure
        path = self._proc / str(pid) / name
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise _translate(exc, f"reading {path}") from exc

    def read_link(self, pid: int, name: str) -> str:
        failure = self._recorded_failure(pid, name)
        if failure is not None:
            raise failure
        path = self._proc / str(pid) / f"{name}.readlink"
        try:
            # rstrip("\n") only, so a trailing " (deleted)" survives intact.
            return path.read_text(encoding="utf-8").rstrip("\n")
        except OSError as exc:
            raise _translate(exc, f"resolving {path}") from exc
