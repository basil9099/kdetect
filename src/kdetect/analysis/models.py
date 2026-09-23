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
    OVER_LISTED_MODULE = "over_listed_module"              # NEW (phase 4c)


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class Suspect:
    """What a Signal is about. name is None for an anonymous hidden-module
    indicator (taint, vmalloc region) that no channel can name (spec §4)."""

    kind: str            # "module" | "process" | "socket"
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


#: Every `ChannelNote.reason` this branch emits. This tuple is the vocabulary,
#: and it is NOT closed: spec section 4.4 earmarks ChannelNote as the home for
#: phase 4d's "this channel was unreadable", so a renderer must treat an unknown
#: reason as a reason it has not learned yet, not as one that cannot occur.
#:
#: Deliberately not an Enum: ChannelNote is an analysis output only (it is
#: absent from the snapshot schema), and a str field keeps an unknown reason
#: round-trippable through to_dict() rather than raising at the boundary --
#: which is the whole point of the renderers' fallback.
CHANNEL_NOTE_REASONS = (
    # The channel's evidence is fully and honestly explained by legitimate
    # listed state, so it can say nothing about a hidden one.
    "saturated",
    # Every listed module came back uncorroborated, so the corroborating
    # channel pair reported on itself rather than on the modules.
    "uncorroborated",
)


@dataclass(frozen=True)
class ChannelNote:
    """Why a channel did not contribute (spec section 4.4).

    NOT a Finding. A channel being uninformative is not a detection, and exit
    code 3 means findings were produced -- emitting this as a Finding would make
    every host with an out-of-tree driver exit 3 forever. Channel notes are
    carried on their own path, are absent from the IOC extractor, and never
    influence an exit code.

    A note whose reason a renderer does not recognise must still render. Listing
    one reason here while a second shipped is what let both human renderers fall
    silent on `uncorroborated` -- "the renderers handle every reason" was true at
    the type level and false in fact. Every renderer therefore carries a generic
    fallback naming the channel, the raw reason and the detail keys, so the next
    reason added degrades to a visible line rather than to silence.
    """

    channel: str
    #: One of CHANNEL_NOTE_REASONS, or a reason added after this renderer was
    #: written -- see the class docstring; renderers must not assume the set.
    reason: str
    detail: dict

    def to_dict(self) -> dict:
        return {"channel": self.channel, "reason": self.reason,
                "detail": dict(self.detail)}
