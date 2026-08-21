"""The hook-surface collector (spec §4.2).

kernel.hooks (MEDIUM) records what is hooked and, where it can, which module a
hook's callback belongs to. It never decides whether a hook is an orphan — that
is the differ's job (P4). A callback whose module cannot be found is recorded
with owner_module=None; the differ reads that as the orphan signal.
"""
from __future__ import annotations

import time

from kdetect.collectors.base import KernelHookSource
from kdetect.models import HookEntity, Observation, Status, TrustLevel
from kdetect.parsers.kernel_hooks import (
    parse_enabled_functions, parse_kprobes, reduce_kallsyms,
)


class KernelHookCollector:
    name = "kernel.hooks"
    view = "kernel_hooks"
    trust_level = TrustLevel.MEDIUM
    version = "1"

    def collect(self, source: KernelHookSource) -> Observation:
        started = time.monotonic()

        kallsyms_text = source.read_kallsyms_index()
        sym_to_mod = reduce_kallsyms(kallsyms_text) if kallsyms_text else {}

        enabled = source.read_enabled_functions()
        kprobes = source.read_kprobes()

        rows = []
        if enabled is not None:
            rows += parse_enabled_functions(enabled)
        if kprobes is not None:
            rows += parse_kprobes(kprobes)

        entities: dict[str, HookEntity] = {}
        for r in rows:
            # Prefer an inline module tag; else attribute the callback symbol
            # via kallsyms. Either may be None -> the orphan signal for the differ.
            owner = r.owner_module
            if owner is None and r.callback:
                owner = sym_to_mod.get(r.callback)
            key = f"{r.hook_type}:{r.function}"
            entities[key] = HookEntity(r.function, r.hook_type, r.callback, owner)

        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=sorted(entities), entities=entities,
            stats={
                "enabled_functions_available": enabled is not None,
                "kprobes_available": kprobes is not None,
                "kallsyms_available": kallsyms_text is not None,
                "hooks": len(entities),
            },
            extra={"kallsyms_modules": sorted(set(sym_to_mod.values()))},
            errors=[],
        )
