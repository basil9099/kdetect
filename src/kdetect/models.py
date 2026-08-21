"""Typed models for kdetect snapshots.

A direct transcription of the schema in section 3 of
docs/superpowers/specs/2026-08-18-kdetect-phase1-design.md.

These types validate nothing beyond type conversion. A snapshot records what
was observed; judging it is the analysis layer's job (principle P1).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from enum import Enum

#: Schema version this build reads and writes. MAJOR.MINOR.
#:   MAJOR - a field was removed, renamed, or changed meaning. Refuse to load.
#:   MINOR - additive only. Load, but warn about keys we do not recognise.
SCHEMA_VERSION = "1.1"

#: Top-level keys a 1.x snapshot is expected to carry.
_KNOWN_TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "snapshot_id", "captured_at", "host", "capture", "observations"}
)


class IncompatibleSnapshot(Exception):
    """The snapshot's schema version cannot be read by this build."""


def _check_schema_version(d: dict) -> None:
    """Gate a snapshot dict on its schema version.

    Runs before anything else is parsed, so a partially-parsed Snapshot can
    never escape into the rest of the program: either the whole object is
    returned, or this raises.
    """
    raw = d.get("schema_version")
    if raw is None:
        raise IncompatibleSnapshot("snapshot has no schema_version field")

    try:
        major, minor = (int(part) for part in str(raw).split("."))
    except ValueError as exc:
        raise IncompatibleSnapshot(
            f"unparseable schema_version {raw!r}, expected MAJOR.MINOR"
        ) from exc

    our_major, our_minor = (int(part) for part in SCHEMA_VERSION.split("."))

    if major != our_major:
        raise IncompatibleSnapshot(
            f"snapshot schema_version {raw} is incompatible with "
            f"{SCHEMA_VERSION}: major versions differ"
        )

    if minor > our_minor:
        unknown = sorted(set(d) - _KNOWN_TOP_LEVEL_KEYS)
        print(
            f"warning: snapshot schema_version {raw} is newer than "
            f"{SCHEMA_VERSION}; ignoring unknown keys: {unknown}",
            file=sys.stderr,
        )


class TrustLevel(str, Enum):
    """How far a collector's view can be relied on.

    Phase 1 emits only LOW. The full set is defined now so that later phases
    add values rather than change meanings.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Status(str, Enum):
    """Outcome of one collector's run. See spec section 4.2."""

    OK = "OK"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ErrorKind(str, Enum):
    """Why a single read failed."""

    VANISHED = "vanished"    # ESRCH/ENOENT - normal, does NOT degrade status
    DENIED = "denied"        # EACCES/EPERM
    MALFORMED = "malformed"  # read succeeded, parse failed
    IO_ERROR = "io_error"    # anything else


@dataclass(frozen=True)
class CollectionError:
    """One failed read, recorded rather than raised.

    entity_id is None when the failure was not about a specific entity - for
    example list_pids() itself failing.
    """

    entity_id: int | None
    kind: ErrorKind
    detail: str

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "kind": self.kind.value,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CollectionError:
        return cls(
            entity_id=d["entity_id"],
            kind=ErrorKind(d["kind"]),
            detail=d["detail"],
        )


@dataclass(frozen=True)
class ProcessEntity:
    """One process as observed by one collector.

    Evidence only (P1). There is deliberately no is_kernel_thread field:
    `flags` is stat field 9 and PF_KTHREAD is bit 0x00200000, so analysis
    derives it rather than the collector asserting it.

    `exe` is three-state, per spec section 3.3:
        "/usr/bin/foo", partial=[]       read successfully
        None,           partial=[]       genuinely has none (ENOENT)
        None,           partial=["exe"]  exists, access denied (EACCES)
    """

    pid: int
    ppid: int
    comm: str
    state: str
    flags: int
    num_threads: int
    starttime_ticks: int
    cmdline: list[str]
    exe: str | None
    uid: list[int] | None
    gid: list[int] | None
    partial: list[str]

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "comm": self.comm,
            "state": self.state,
            "flags": self.flags,
            "num_threads": self.num_threads,
            "starttime_ticks": self.starttime_ticks,
            "cmdline": list(self.cmdline),
            "exe": self.exe,
            "uid": list(self.uid) if self.uid is not None else None,
            "gid": list(self.gid) if self.gid is not None else None,
            "partial": sorted(self.partial),
        }

    @classmethod
    def from_dict(cls, d: dict) -> ProcessEntity:
        return cls(
            pid=d["pid"],
            ppid=d["ppid"],
            comm=d["comm"],
            state=d["state"],
            flags=d["flags"],
            num_threads=d["num_threads"],
            starttime_ticks=d["starttime_ticks"],
            cmdline=list(d["cmdline"]),
            exe=d["exe"],
            uid=list(d["uid"]) if d["uid"] is not None else None,
            gid=list(d["gid"]) if d["gid"] is not None else None,
            partial=list(d["partial"]),
        )


@dataclass(frozen=True)
class SweepEntity:
    """One task id that answered a kill(id, 0) sweep (spec §4.1).

    Evidence only (P4): the tgid we read from /proc/<id>/status, and whether
    that read succeeded. The differ folds threads into leaders using tgid; it
    is not folded here.
    """

    tgid: int
    status_readable: bool

    def to_dict(self) -> dict:
        return {"tgid": self.tgid, "status_readable": self.status_readable}

    @classmethod
    def from_dict(cls, d: dict) -> "SweepEntity":
        return cls(tgid=d["tgid"], status_readable=d["status_readable"])


@dataclass(frozen=True)
class ModuleEntity:
    """One row of /proc/modules (spec §5.1), stored raw (P1).

    `taint` is the trailing parenthesised marker, e.g. "OE", or None when the
    module carries none. `base_addr` is kept as the textual value; on an
    unprivileged capture it reads "0x0" (L4) and analysis must expect that.
    """

    name: str
    size: int
    refcount: int
    dependents: list[str]
    state: str
    base_addr: str
    taint: str | None

    def to_dict(self) -> dict:
        return {
            "name": self.name, "size": self.size, "refcount": self.refcount,
            "dependents": list(self.dependents), "state": self.state,
            "base_addr": self.base_addr, "taint": self.taint,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ModuleEntity":
        return cls(
            name=d["name"], size=d["size"], refcount=d["refcount"],
            dependents=list(d["dependents"]), state=d["state"],
            base_addr=d["base_addr"], taint=d["taint"],
        )


@dataclass(frozen=True)
class HookEntity:
    """One hooked kernel function, as observed on a hook surface (spec §4.2).

    Evidence only (P1): the function, the surface it came from, the callback the
    surface names, and the module that callback attributes to (or None). Whether
    that makes it an ORPHAN hook is a conclusion the differ draws (P4), so there
    is deliberately no `attributable` field here.
    """

    function: str
    hook_type: str                 # "ftrace" | "kprobe"
    callback: str | None
    owner_module: str | None

    def to_dict(self) -> dict:
        return {
            "function": self.function, "hook_type": self.hook_type,
            "callback": self.callback, "owner_module": self.owner_module,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HookEntity":
        return cls(
            function=d["function"], hook_type=d["hook_type"],
            callback=d["callback"], owner_module=d["owner_module"],
        )


#: Which entity type each collector stores. Collectors that record only
#: existence (kernel.module_evidence) have no per-entity detail.
_ENTITY_TYPES = {
    "procfs.processes": ProcessEntity,
    "syscall_sweep.processes": SweepEntity,
    "procfs.modules": ModuleEntity,
    "kernel.module_evidence": None,
    "kernel.hooks": HookEntity,
}

#: Collectors whose entity ids are names, not pids. Their entity_ids and
#: entities keys stay strings; every other collector casts keys back to int.
_STRING_ID_COLLECTORS = frozenset({"procfs.modules", "kernel.hooks"})


@dataclass(frozen=True)
class Observation:
    """One whole view from one collector - not one entity.

    entity_ids and entities are NOT redundant. A collector can prove an entity
    exists without reading any detail about it: phase 2's kill(pid, 0) sweep
    does exactly that. The invariant is:

        set(entities) <= set(entity_ids)

    The differ compares entity_ids only. Per-entity detail lives here, inside
    the observation, and never in a table shared between collectors - two
    collectors disagreeing about the same pid IS the finding (P2).

    Contract: entity_ids is unique and sorted ascending, and each entity's
    `partial` is sorted. to_dict enforces both on the way out.
    """

    collector: str
    collector_version: str
    view: str
    trust_level: TrustLevel
    status: Status
    duration_ms: int
    entity_ids: list[int]
    entities: dict[int | str, ProcessEntity | SweepEntity | ModuleEntity]
    stats: dict[str, object]
    errors: list[CollectionError]
    pass_: str | None = None          # JSON key "pass"; distinguishes A/B walks
    extra: dict | None = None         # channel detail that is not per-entity

    def to_dict(self) -> dict:
        d = {
            "collector": self.collector,
            "collector_version": self.collector_version,
            "view": self.view,
            "trust_level": self.trust_level.value,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "entity_ids": sorted(self.entity_ids),
            "entities": {str(k): e.to_dict() for k, e in self.entities.items()},
            "stats": dict(self.stats),
            "errors": [err.to_dict() for err in self.errors],
        }
        if self.pass_ is not None:
            d["pass"] = self.pass_
        if self.extra is not None:
            d["extra"] = self.extra
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Observation:
        collector = d["collector"]
        entity_cls = _ENTITY_TYPES.get(collector, ProcessEntity)
        cast = str if collector in _STRING_ID_COLLECTORS else int
        entities = (
            {cast(k): entity_cls.from_dict(v) for k, v in d["entities"].items()}
            if entity_cls is not None else {}
        )
        return cls(
            collector=collector,
            collector_version=d["collector_version"],
            view=d["view"],
            trust_level=TrustLevel(d["trust_level"]),
            status=Status(d["status"]),
            duration_ms=d["duration_ms"],
            entity_ids=list(d["entity_ids"]),
            entities=entities,
            stats=dict(d["stats"]),
            errors=[CollectionError.from_dict(e) for e in d["errors"]],
            pass_=d.get("pass"),
            extra=d.get("extra"),
        )


@dataclass(frozen=True)
class HostFacts:
    """Facts about the machine, without which the observations cannot be read.

    btime and clock_ticks_per_sec are mandatory because stat field 22
    (starttime) is expressed in clock ticks since boot. Wall-clock time is
        btime + starttime_ticks / clock_ticks_per_sec
    verified against `ps -o lstart=` in docs/step0/01-stat-fields.txt.

    boot_id is mandatory because pids and start times are only comparable
    within a single boot. Diffing across boots is meaningless, and without
    boot_id nothing detects that mistake.
    """

    hostname: str
    kernel_release: str
    arch: str
    boot_id: str
    btime: int
    clock_ticks_per_sec: int

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "kernel_release": self.kernel_release,
            "arch": self.arch,
            "boot_id": self.boot_id,
            "btime": self.btime,
            "clock_ticks_per_sec": self.clock_ticks_per_sec,
        }

    @classmethod
    def from_dict(cls, d: dict) -> HostFacts:
        return cls(
            hostname=d["hostname"],
            kernel_release=d["kernel_release"],
            arch=d["arch"],
            boot_id=d["boot_id"],
            btime=d["btime"],
            clock_ticks_per_sec=d["clock_ticks_per_sec"],
        )


@dataclass(frozen=True)
class CaptureMeta:
    """How the capture itself was taken.

    euid matters to analysis: docs/step0/09-kallsyms-user-vs-root.txt shows
    kernel addresses reading as zero without CAP_SYSLOG, so a consumer needs
    to know whether the collector could see them at all.
    """

    tool_version: str
    euid: int

    def to_dict(self) -> dict:
        return {"tool_version": self.tool_version, "euid": self.euid}

    @classmethod
    def from_dict(cls, d: dict) -> CaptureMeta:
        return cls(tool_version=d["tool_version"], euid=d["euid"])


@dataclass(frozen=True)
class Snapshot:
    """One capture: host context plus every collector's view."""

    schema_version: str
    snapshot_id: str
    captured_at: str
    host: HostFacts
    capture: CaptureMeta
    observations: list[Observation]

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "captured_at": self.captured_at,
            "host": self.host.to_dict(),
            "capture": self.capture.to_dict(),
            "observations": [o.to_dict() for o in self.observations],
        }

    @classmethod
    def from_dict(cls, d: dict) -> Snapshot:
        _check_schema_version(d)
        return cls(
            schema_version=d["schema_version"],
            snapshot_id=d["snapshot_id"],
            captured_at=d["captured_at"],
            host=HostFacts.from_dict(d["host"]),
            capture=CaptureMeta.from_dict(d["capture"]),
            observations=[Observation.from_dict(o) for o in d["observations"]],
        )

    def to_json(self, pretty: bool = False) -> str:
        """Serialise deterministically.

        sort_keys is what makes byte-identical re-serialisation achievable:
        Python preserves dict insertion order, so without it two runs
        producing the same data could emit different bytes.
        """
        if pretty:
            return json.dumps(self.to_dict(), indent=2, sort_keys=True)
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
