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
    KernelHookSource,
    ModuleSource,
    ProcSource,
    ProcSourceError,
    SignalSource,
    SocketSource,
    Unreadable,
    Vanished,
)
from kdetect.parsers.procfs import ParseError, parse_status

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


class LiveSignalSource(SignalSource):
    """Sweeps the running kernel with os.kill and reads Tgid from /proc."""

    def pid_max(self) -> int:
        with open("/proc/sys/kernel/pid_max", encoding="ascii") as fh:
            return int(fh.read().strip())

    def sweep(self, pid_max: int) -> list[int]:
        alive: list[int] = []
        for task_id in range(1, pid_max + 1):
            try:
                os.kill(task_id, 0)
            except ProcessLookupError:
                continue          # ESRCH: no such id
            except PermissionError:
                alive.append(task_id)   # EPERM: exists, may not signal
            except OSError:
                continue
            else:
                alive.append(task_id)
        return alive

    def read_status(self, task_id: int) -> tuple[int, str | None] | None:
        try:
            with open(f"/proc/{task_id}/status", encoding="utf-8",
                      errors="replace") as fh:
                fields = parse_status(fh.read())
                return (fields.tgid, fields.name)
        except (OSError, ParseError):
            return None


class FixtureSignalSource(SignalSource):
    """Replays a recorded sweep, including a hidden id that never existed (P3)."""

    def __init__(self, path) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self._pid_max = data["pid_max"]
        self._alive = sorted(data["alive"])
        self._tgid = {int(k): v for k, v in data["tgid"].items()}
        self._comm = {int(k): v for k, v in data.get("comm", {}).items()}
        self._unreadable = set(data.get("unreadable_status", []))

    def pid_max(self) -> int:
        return self._pid_max

    def sweep(self, pid_max: int) -> list[int]:
        return [i for i in self._alive if i <= pid_max]

    def read_status(self, task_id: int) -> tuple[int, str | None] | None:
        if task_id in self._unreadable or task_id not in self._tgid:
            return None
        return (self._tgid[task_id], self._comm.get(task_id))


class LiveModuleSource(ModuleSource):
    _TRACING = ("/sys/kernel/tracing/available_filter_functions",
                "/sys/kernel/debug/tracing/available_filter_functions")

    def read_proc_modules(self) -> str:
        with open("/proc/modules", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    def read_tainted(self) -> int:
        with open("/proc/sys/kernel/tainted", encoding="ascii") as fh:
            return int(fh.read().strip())

    def read_vmallocinfo(self) -> str | None:
        try:
            with open("/proc/vmallocinfo", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None        # 0400, root-only; skipped when unreadable

    def read_ftrace_functions(self) -> str | None:
        for path in self._TRACING:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except OSError:
                continue
        return None


class FixtureModuleSource(ModuleSource):
    """Replays a captured module tree; a missing file replays 'unreadable'."""

    def __init__(self, root) -> None:
        self._root = Path(root)

    def _read(self, name: str) -> str | None:
        p = self._root / name
        return p.read_text(encoding="utf-8") if p.exists() else None

    def read_proc_modules(self) -> str:
        return self._read("proc_modules.txt") or ""

    def read_tainted(self) -> int:
        return int((self._read("tainted.txt") or "0").strip())

    def read_vmallocinfo(self) -> str | None:
        return self._read("vmallocinfo.txt")

    def read_ftrace_functions(self) -> str | None:
        return self._read("ftrace.txt")


class LiveKernelHookSource(KernelHookSource):
    _ENABLED = ("/sys/kernel/tracing/enabled_functions",
                "/sys/kernel/debug/tracing/enabled_functions")
    _KPROBES = ("/sys/kernel/debug/kprobes/list",
                "/sys/kernel/tracing/kprobes/list")

    @staticmethod
    def _try(paths) -> str | None:
        for p in paths:
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except OSError:
                continue
        return None

    def read_enabled_functions(self) -> str | None:
        return self._try(self._ENABLED)

    def read_kprobes(self) -> str | None:
        return self._try(self._KPROBES)

    def read_kallsyms_index(self) -> str | None:
        try:
            with open("/proc/kallsyms", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None


class FixtureKernelHookSource(KernelHookSource):
    """Replays a captured hook tree; a missing file replays 'unreadable'."""

    def __init__(self, root) -> None:
        self._root = Path(root)

    def _read(self, name: str) -> str | None:
        p = self._root / name
        return p.read_text(encoding="utf-8") if p.exists() else None

    def read_enabled_functions(self) -> str | None:
        return self._read("enabled_functions.txt")

    def read_kprobes(self) -> str | None:
        return self._read("kprobes.txt")

    def read_kallsyms_index(self) -> str | None:
        return self._read("kallsyms.txt")


class LiveSocketSource(SocketSource):
    def read_net_table(self, name: str) -> str | None:
        try:
            with open(f"/proc/net/{name}", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def list_fds(self, pid: int) -> dict[int, list[str]]:
        out: dict[int, list[str]] = {}
        base = f"/proc/{pid}/fd"
        try:
            names = os.listdir(base)
        except OSError:
            return {}
        for n in names:
            try:
                target = os.readlink(f"{base}/{n}")
            except OSError:
                continue
            if target.startswith("socket:["):
                inode = int(target[len("socket:["):-1])
                out.setdefault(inode, []).append(f"{base}/{n}")
        return out


class FixtureSocketSource(SocketSource):
    """Replays a captured socket tree: net/<name>.txt tables and an fds.json
    mapping {pid: [inode, ...]}."""

    def __init__(self, root) -> None:
        self._root = Path(root)
        fds_path = self._root / "fds.json"
        self._fds = (
            {int(k): v for k, v in json.loads(fds_path.read_text()).items()}
            if fds_path.exists() else {}
        )

    def read_net_table(self, name: str) -> str | None:
        p = self._root / "net" / f"{name}.txt"
        return p.read_text(encoding="utf-8") if p.exists() else None

    def list_fds(self, pid: int) -> dict[int, list[str]]:
        return {int(inode): [f"/proc/{pid}/fd/0"] for inode in self._fds.get(pid, [])}
