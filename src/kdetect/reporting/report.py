"""Report renderers (spec §5). Pure: (snapshot, findings, iocs) -> str.

Presents analyze()'s findings; concludes nothing (P11). Markdown for a human,
JSON for a pipeline. A hidden process shows its comm and owned socket endpoints;
its exe/cmdline are unavailable because it was hidden from the readdir path that
records them (L26).

baseline_name is a caller contract, not something this module checks: pass it
only once the named baseline's signature has already been verified (the `kdetect
report --baseline` path requires --verify-key and load_baseline() raises
BaselineTampered -- refusing to reach the renderer at all -- on a bad signature).
That is why a non-None baseline_name renders "verified": true unconditionally
here; a caller that has not verified a baseline must pass baseline_name=None.
"""
from __future__ import annotations

import json

from kdetect.analysis.models import Confidence, Finding, FindingKind
from kdetect.models import Snapshot
from kdetect.reporting.iocs import IOC

_ORDER = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


def _ranked(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_ORDER[f.confidence], f.subject))


def _counts(findings: list[Finding]) -> dict:
    return {
        "high": sum(f.confidence is Confidence.HIGH for f in findings),
        "medium": sum(f.confidence is Confidence.MEDIUM for f in findings),
        "low": sum(f.confidence is Confidence.LOW for f in findings),
    }


def _verdict(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    kinds = sorted({f.kind.value for f in findings})
    return f"{len(findings)} finding(s) — {', '.join(kinds)}. Investigate."


def render_json(snapshot: Snapshot, findings: list[Finding], iocs: list[IOC],
                baseline_name: str | None = None) -> str:
    h = snapshot.host
    payload = {
        "host": {"hostname": h.hostname, "kernel_release": h.kernel_release,
                 "arch": h.arch, "boot_id": h.boot_id},
        "captured_at": snapshot.captured_at,
        "euid": snapshot.capture.euid,
        "tool_version": snapshot.capture.tool_version,
        "schema": snapshot.schema_version,
        "baseline": {"name": baseline_name, "verified": True} if baseline_name else None,
        "summary": _counts(findings),
        "verdict": _verdict(findings),
        "findings": [f.to_dict() for f in _ranked(findings)],
        "iocs": [i.to_dict() for i in iocs],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _render_evidence(f: Finding) -> list[str]:
    lines: list[str] = []
    if f.kind is FindingKind.HIDDEN_PROCESS:
        comm = None
        for ch in ("syscall_kill", "direct_status"):
            for ev in f.evidence.get(ch, []):
                comm = comm or ev.get("comm")
        lines.append(f"  - comm: {comm if comm else 'unknown'}")
        lines.append("  - exe: unavailable (hidden from /proc)")
        for ev in f.evidence.get("socket_visible", []):
            lines.append(f"  - socket: {ev.get('local')} -> {ev.get('remote')} "
                         f"({ev.get('state')})")
    else:
        for channel in sorted(f.evidence):
            lines.append(f"  - {channel}: {f.evidence[channel]}")
    return lines


def render_markdown(snapshot: Snapshot, findings: list[Finding], iocs: list[IOC],
                    baseline_name: str | None = None) -> str:
    h = snapshot.host
    c = _counts(findings)
    out = [
        f"# kdetect report — {h.hostname}",
        "",
        f"**Host:** {h.hostname} · {h.kernel_release} · {h.arch}",
        f"**Captured:** {snapshot.captured_at} · boot {h.boot_id[:8]} · "
        f"euid {snapshot.capture.euid}",
        f"**Tool:** kdetect {snapshot.capture.tool_version} · schema "
        f"{snapshot.schema_version}",
        f"**Baseline:** {baseline_name if baseline_name else 'none'}",
        "",
        "## Summary",
        f"- HIGH: {c['high']} · MEDIUM: {c['medium']} · LOW: {c['low']}",
        f"- Verdict: {_verdict(findings)}",
        "",
        "## Findings",
    ]
    if not findings:
        out.append("None.")
    for f in _ranked(findings):
        out.append(f"### [{f.confidence.value}] {f.kind.value} — {f.subject}")
        if f.summary:
            out.append(f.summary)
        if f.channels_agree:
            out.append(f"- Seen by: {', '.join(f.channels_agree)}")
        if f.channels_dissent:
            out.append(f"- Denied by: {', '.join(f.channels_dissent)}")
        out.extend(_render_evidence(f))
        out.append("")
    out.append("## Indicators of Compromise")
    if not iocs:
        out.append("None.")
    for i in iocs:
        out.append(f"- {i.type}: `{i.value}` ({i.confidence})")
    out.append("")
    return "\n".join(out)
