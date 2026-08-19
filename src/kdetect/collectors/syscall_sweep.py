"""The MEDIUM process-existence collector: a full pid-space sweep (spec §4.1).

Records evidence, not conclusions (P4): for every id that answered kill(id, 0)
it stores the Tgid it read and whether that read succeeded. The differ folds
threads into leaders and decides what is hidden.
"""
from __future__ import annotations

import time

from kdetect.collectors.base import SignalSource
from kdetect.models import Observation, Status, SweepEntity, TrustLevel


class SweepProcessCollector:
    name = "syscall_sweep.processes"
    view = "processes"
    trust_level = TrustLevel.MEDIUM
    version = "1"

    def collect(self, source: SignalSource) -> Observation:
        started = time.monotonic()
        pid_max = source.pid_max()
        alive = source.sweep(pid_max)

        entities: dict[int, SweepEntity] = {}
        for task_id in alive:
            tgid = source.read_tgid(task_id)
            entities[task_id] = SweepEntity(
                tgid=tgid if tgid is not None else task_id,
                status_readable=tgid is not None,
            )

        return Observation(
            collector=self.name, collector_version=self.version, view=self.view,
            trust_level=self.trust_level, status=Status.OK,
            duration_ms=int((time.monotonic() - started) * 1000),
            entity_ids=sorted(alive), entities=entities,
            stats={"pid_max": pid_max, "responded": len(alive),
                   "sweep_ms": int((time.monotonic() - started) * 1000)},
            errors=[],
        )
