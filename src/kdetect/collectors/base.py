"""Abstract interfaces for the collector layer.

Spec section 4.1 splits collection into three layers, and only the Source
touches the operating system:

    Source            ->   Parse             ->   Collector
    (all I/O)              (pure functions)       (assembles Observation)

Collectors receive their source as an argument, so a fixture-driven test runs
the identical code path as a live capture (principle P3). There is no
`if testing:` branch anywhere in this package.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from kdetect.models import Observation, TrustLevel


class ProcSourceError(Exception):
    """Base for every failure a ProcSource can report.

    Implementations translate OSError into one of the subclasses below. No raw
    OSError may escape a ProcSource - that translation is the entire reason
    this layer exists, and it is what lets a fixture replay a failure that
    never actually happened.
    """


class Vanished(ProcSourceError):
    """ESRCH/ENOENT - the entity is gone, or never had this attribute.

    Normal on a live system: processes exit while you are walking /proc. Also
    what a kernel thread's `exe` gives, since it genuinely has no executable.
    Does NOT degrade an Observation's status (spec section 4.2).
    """


class Denied(ProcSourceError):
    """EACCES/EPERM - it exists, we are not permitted to read it.

    Materially different from Vanished. As root this is anomalous rather than
    routine, but the source does not judge that; it records the fact and lets
    analysis weigh it against capture.euid (principle P1).
    """


class Unreadable(ProcSourceError):
    """Any other I/O failure."""


class ProcSource(ABC):
    """Somewhere process information can be read from.

    Deliberately tiny: three operations. Two implementations exist -
    LiveProcSource reads /proc, FixtureProcSource replays a captured tree.
    """

    @abstractmethod
    def list_pids(self) -> list[int]:
        """Every pid this source knows about, unique and sorted ascending."""

    @abstractmethod
    def read_text(self, pid: int, name: str) -> str:
        """Read /proc/<pid>/<name> as text. e.g. "stat", "cmdline", "status"."""

    @abstractmethod
    def read_link(self, pid: int, name: str) -> str:
        """Resolve the symlink /proc/<pid>/<name>. e.g. "exe", "cwd".

        The target is returned verbatim, including any " (deleted)" suffix -
        a running binary unlinked from disk is one of the strongest single
        indicators available, and stripping it would discard the finding.
        """


class SignalSource(ABC):
    """The process-existence channel that does not go through readdir (spec §4).

    kill(id, 0) asks the kernel whether an id exists; /proc/<id>/status is read
    by path lookup, not getdents. Both bypass a directory-listing hook, which
    is why this is a MEDIUM channel independent of procfs.
    """

    @abstractmethod
    def pid_max(self) -> int: ...

    @abstractmethod
    def sweep(self, pid_max: int) -> list[int]:
        """Every id in 1..pid_max that exists, sorted. EPERM counts as exists."""

    @abstractmethod
    def read_tgid(self, task_id: int) -> int | None:
        """The Tgid from /proc/<id>/status, or None if it could not be read."""


class ModuleSource(ABC):
    """The module-view channels (spec §5). /proc/modules is the LOW listing a
    rootkit unlinks itself from; tainted, vmallocinfo and ftrace are channels
    that do NOT share that list's source. A channel that cannot be read returns
    None, and the differ skips it rather than treating absence as agreement."""

    @abstractmethod
    def read_proc_modules(self) -> str: ...
    @abstractmethod
    def read_tainted(self) -> int: ...
    @abstractmethod
    def read_vmallocinfo(self) -> str | None: ...
    @abstractmethod
    def read_ftrace_functions(self) -> str | None: ...


class KernelHookSource(ABC):
    """The hook-surface channels (spec §4). enabled_functions and kprobes are
    what modern LKM rootkits light up; kallsyms attributes a callback symbol to
    a module. A channel that cannot be read returns None, and the collector
    records its absence rather than treating it as agreement."""

    @abstractmethod
    def read_enabled_functions(self) -> str | None: ...
    @abstractmethod
    def read_kprobes(self) -> str | None: ...
    @abstractmethod
    def read_kallsyms_index(self) -> str | None: ...


class Collector(ABC):
    """Produces one Observation - one whole view of one kind of entity."""

    name: str
    view: str
    trust_level: TrustLevel
    version: str

    @abstractmethod
    def collect(self, source: ProcSource) -> Observation:
        """Gather a view from `source`.

        The source is a parameter, not something the collector constructs.
        That is what makes live and fixture runs the same code path (P3).
        """
