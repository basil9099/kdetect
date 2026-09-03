"""IOC extraction (spec §6). Pure: [Finding] -> [IOC].

Pulls the PORTABLE indicators out of findings -- a module name, a hooked
syscall, a C2/backdoor endpoint, the malware's own name -- and leaves host-local
artifacts (pids, inodes, region counts) as report context. Concludes nothing new
(P11); every IOC cites the finding it came from.
"""
from __future__ import annotations

from dataclasses import dataclass

from kdetect.analysis.models import Finding, FindingKind


@dataclass(frozen=True)
class IOC:
    type: str
    value: str
    confidence: str
    source_finding: str

    def to_dict(self) -> dict:
        return {"type": self.type, "value": self.value,
                "confidence": self.confidence, "source_finding": self.source_finding}


def _placeholder_endpoint(ep: str | None) -> bool:
    # 0.0.0.0:0 / :::0 / any :0 port is not a usable endpoint.
    return not ep or ep.rsplit(":", 1)[-1] == "0"


def extract(findings: list[Finding]) -> list[IOC]:
    seen: dict[tuple[str, str], IOC] = {}

    def add(type_: str, value: str, conf: str, source: str) -> None:
        key = (type_, value)
        if value and key not in seen:
            seen[key] = IOC(type_, value, conf, source)

    for f in findings:
        conf = f.confidence.value
        if f.kind is FindingKind.HIDDEN_MODULE:
            name = f.subject.removeprefix("module ")
            add("kernel_module", name, conf, f.subject)
            for ev in f.evidence.get("unexpected_hook", []):
                fn = ev.get("function")
                if fn:
                    add("hooked_function", fn, conf, f.subject)
        elif f.kind is FindingKind.HIDDEN_PROCESS:
            for channel in ("syscall_kill", "direct_status"):
                for ev in f.evidence.get(channel, []):
                    comm = ev.get("comm")
                    if comm:
                        add("process_name", comm, conf, f.subject)
            for ev in f.evidence.get("socket_visible", []):
                endpoint = (ev.get("remote") if ev.get("state") == "ESTABLISHED"
                            else ev.get("local"))
                if not _placeholder_endpoint(endpoint):
                    add("network_endpoint", endpoint, conf, f.subject)

    return sorted(seen.values(), key=lambda i: (i.type, i.value))
