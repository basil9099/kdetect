"""The analysis layer's output type (spec §6).

A Finding is a conclusion, which a snapshot may never hold (P1). It is produced
only by the differ and may be serialised for reporting. Every Finding carries
the evidence it was drawn from so it can be traced back into the snapshot (P5).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FindingKind(str, Enum):
    HIDDEN_PROCESS = "hidden_process"
    HIDDEN_MODULE = "hidden_module"                       # NEW (phase 3b)
    SUSPECTED_HIDDEN_MODULE = "suspected_hidden_module"   # NEW (phase 3b)
    BASELINE_DRIFT = "baseline_drift"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class Suspect:
    """What a Signal is about. name is None for an anonymous hidden-module
    indicator (taint, vmalloc region) that no channel can name (spec §4)."""

    kind: str            # "module" | "process"
    name: str | None


@dataclass(frozen=True)
class Signal:
    """One channel's raw indication that a suspect is anomalous (P8). Carries no
    confidence and no composition -- the scorer draws those (spec §3)."""

    channel: str
    suspect: Suspect
    dissent: str
    evidence: dict


@dataclass(frozen=True)
class Finding:
    kind: FindingKind
    subject: str
    confidence: Confidence
    channels_agree: list[str]
    channels_dissent: list[str]
    evidence: dict
    summary: str

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "subject": self.subject,
            "confidence": self.confidence.value,
            "channels_agree": list(self.channels_agree),
            "channels_dissent": list(self.channels_dissent),
            "evidence": dict(self.evidence),
            "summary": self.summary,
        }
