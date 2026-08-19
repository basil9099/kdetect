"""The module-view collectors (spec §5).

procfs.modules (LOW) is the listing a rootkit unlinks itself from.
kernel.module_evidence (MEDIUM) records three channels that do not share that
listing's source. Neither judges (P1/P4); the differ compares them.
"""
from __future__ import annotations

import time

from kdetect.collectors.base import ModuleSource
from kdetect.models import ModuleEntity, Observation, Status, TrustLevel
from kdetect.parsers.modules import (
    count_module_regions, parse_ftrace_modules, parse_proc_modules,
)


class ProcfsModuleCollector:
    name = "procfs.modules"
    view = "modules"
    trust_level = TrustLevel.LOW
    version = "1"

    def collect(self, source: ModuleSource) -> Observation:
        started = time.monotonic()
        rows = parse_proc_modules(source.read_proc_modules())
        entities = {
            r.name: ModuleEntity(r.name, r.size, r.refcount, r.dependents,
                                 r.state, r.base_addr, r.taint)
            for r in rows
        }
        # /proc/modules lists only genuinely loaded modules, so every row is a
        # real module. FP class #2 (built-ins with a /sys/module dir but no
        # initstate) only arises if you enumerate /sys/module, which this
        # collector deliberately does not — the LOW listing is /proc/modules.
        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=sorted(entities), entities=entities,
            stats={"listed": len(entities)}, errors=[],
        )


class ModuleEvidenceCollector:
    name = "kernel.module_evidence"
    view = "modules"
    trust_level = TrustLevel.MEDIUM
    version = "1"

    def collect(self, source: ModuleSource) -> Observation:
        started = time.monotonic()
        taint = source.read_tainted()
        listed = parse_proc_modules(source.read_proc_modules())
        markers = sum(1 for r in listed if r.taint)

        vmalloc = source.read_vmallocinfo()
        regions = count_module_regions(vmalloc) if vmalloc is not None else None

        ftrace = source.read_ftrace_functions()
        ftrace_modules = (
            sorted(parse_ftrace_modules(ftrace)) if ftrace is not None else None
        )

        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=[], entities={},
            stats={
                "taint": taint,
                "load_module_regions": regions,
                "ftrace_available": ftrace is not None,
                "ftrace_module_count": len(ftrace_modules) if ftrace_modules else 0,
            },
            extra={
                "listed_taint_markers": markers,
                "ftrace_modules": ftrace_modules,
            },
            errors=[],
        )
