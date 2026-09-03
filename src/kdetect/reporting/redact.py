"""Snapshot redaction for sharing (limitation L13).

/proc/[pid]/cmdline is captured verbatim, so a snapshot can carry credentials a
process was handed as arguments. Cross-view findings never depend on cmdline
(they key on pids/tgids/module/socket data), so replacing every process cmdline
wholesale removes the secrets without changing any conclusion. Reports do not
carry cmdline at all (spec §7); this is for scrubbing a *snapshot* to share.
"""
from __future__ import annotations

_PLACEHOLDER = ["[redacted]"]


def redact_snapshot(snap: dict) -> dict:
    """Replace every process entity's cmdline with a placeholder, in place."""
    for obs in snap.get("observations", []):
        for entity in obs.get("entities", {}).values():
            if isinstance(entity, dict) and "cmdline" in entity:
                entity["cmdline"] = list(_PLACEHOLDER)
    return snap
