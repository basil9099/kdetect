"""The phase 1 collector: every process visible in /proc."""

from __future__ import annotations

import time

from kdetect.collectors.base import (
    Collector,
    Denied,
    ProcSource,
    ProcSourceError,
    Vanished,
)
from kdetect.models import (
    CollectionError,
    ErrorKind,
    Observation,
    ProcessEntity,
    Status,
    TrustLevel,
)
from kdetect.parsers.procfs import ParseError, parse_cmdline, parse_stat, parse_status


def _kind_of(exc: Exception) -> ErrorKind:
    """Classify a failure for the record. See spec section 4.2."""
    if isinstance(exc, Vanished):
        return ErrorKind.VANISHED
    if isinstance(exc, Denied):
        return ErrorKind.DENIED
    if isinstance(exc, ParseError):
        return ErrorKind.MALFORMED
    return ErrorKind.IO_ERROR


class ProcfsProcessCollector(Collector):
    """Every process visible in /proc.

    Trust level LOW. /proc is the easiest surface for a kernel rootkit to lie
    on: a hooked getdents or a patched proc handler can simply omit an entry.
    This view exists to be *contradicted* by higher-trust collectors in phase
    2 - on its own it proves nothing.
    """

    name = "procfs.processes"
    view = "processes"
    trust_level = TrustLevel.LOW
    version = "1"

    def __init__(self, pass_label: str | None = None) -> None:
        self._pass_label = pass_label

    def collect(self, source: ProcSource) -> Observation:
        started = time.monotonic()
        errors: list[CollectionError] = []

        try:
            pids = source.list_pids()
        except ProcSourceError as exc:
            # We could not enumerate at all. Distinct from "a system with no
            # processes", which is why FAILED exists as a separate status.
            return self._observation(
                started=started,
                status=Status.FAILED,
                entity_ids=[],
                entities={},
                stats={"scanned": 0, "collected": 0, "vanished": 0},
                errors=[CollectionError(None, ErrorKind.IO_ERROR, str(exc))],
            )

        observed: list[int] = []
        entities: dict[int, ProcessEntity] = {}
        vanished = 0
        status = Status.OK

        for pid in pids:
            # stat is mandatory: with no stat there is no entity to record.
            try:
                stat = parse_stat(source.read_text(pid, "stat"))
            except Vanished as exc:
                # Exited between the listing and the read. Normal Linux, NOT
                # an error - it is counted, and status stays OK. Letting this
                # degrade status would cry wolf on every capture ever taken.
                vanished += 1
                errors.append(CollectionError(pid, ErrorKind.VANISHED, str(exc)))
                continue
            except (ProcSourceError, ParseError) as exc:
                # It exists - we saw the dirent - but we cannot describe it.
                # Record the id without detail, so entity_ids stays honest.
                observed.append(pid)
                status = Status.PARTIAL
                errors.append(CollectionError(pid, _kind_of(exc), str(exc)))
                continue

            partial: list[str] = []
            degraded = False

            cmdline, d1 = self._optional(
                lambda: parse_cmdline(source.read_text(pid, "cmdline")),
                pid, "cmdline", partial, errors,
            )
            creds, d2 = self._optional(
                lambda: parse_status(source.read_text(pid, "status")),
                pid, "status", partial, errors,
            )
            exe, d3 = self._optional(
                lambda: source.read_link(pid, "exe"),
                pid, "exe", partial, errors,
            )
            degraded = d1 or d2 or d3

            if degraded:
                status = Status.PARTIAL

            observed.append(pid)
            entities[pid] = ProcessEntity(
                pid=stat.pid,
                ppid=stat.ppid,
                comm=stat.comm,
                state=stat.state,
                flags=stat.flags,
                num_threads=stat.num_threads,
                starttime_ticks=stat.starttime_ticks,
                cmdline=cmdline if cmdline is not None else [],
                exe=exe,
                uid=creds.uid if creds is not None else None,
                gid=creds.gid if creds is not None else None,
                partial=sorted(partial),
            )

        return self._observation(
            started=started,
            status=status,
            entity_ids=sorted(observed),
            entities=entities,
            stats={
                "scanned": len(pids),
                "collected": len(entities),
                "vanished": vanished,
            },
            errors=errors,
        )

    def _optional(self, read, pid, field, partial, errors):
        """Attempt a read that is allowed to be absent.

        Returns (value, degraded).

        Vanished means the attribute genuinely is not there - a kernel thread
        has no exe - so the value is absent and `partial` stays clean.

        Denied or unreadable means it exists and we could not see it, which is
        a different fact: the field name goes into `partial` so a consumer can
        tell the two apart. Collapsing them into a bare None destroys the
        distinction. Spec section 3.3, evidenced by
        docs/step0/06-exe-errno-comparison.txt.
        """
        try:
            return read(), False
        except Vanished:
            return None, False
        except (ProcSourceError, ParseError) as exc:
            partial.append(field)
            errors.append(CollectionError(pid, _kind_of(exc), str(exc)))
            return None, True

    def _observation(self, *, started, status, entity_ids, entities, stats, errors):
        """Assemble the Observation, stamping the elapsed time."""
        return Observation(
            collector=self.name,
            collector_version=self.version,
            view=self.view,
            trust_level=self.trust_level,
            status=status,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=entity_ids,
            entities=entities,
            stats=stats,
            errors=errors,
            pass_=self._pass_label,
        )
