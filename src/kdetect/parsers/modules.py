"""Pure parsers for the module-view channels (spec §5).

Text in, typed values out, no I/O. Each mirrors a file in
docs/step0-phase2/clean/ and every case in the tests is drawn from there.
"""
from __future__ import annotations

from dataclasses import dataclass


class ModuleParseError(ValueError):
    """A module-channel file could not be parsed."""


@dataclass(frozen=True)
class ModuleRow:
    name: str
    size: int
    refcount: int
    dependents: list[str]
    state: str
    base_addr: str
    taint: str | None


def parse_proc_modules(text: str) -> list[ModuleRow]:
    """Parse /proc/modules. Columns: name size refcount deps state base [taint]."""
    rows: list[ModuleRow] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 6:
            raise ModuleParseError(f"short /proc/modules line: {line!r}")
        deps = [] if parts[3] == "-" else [d for d in parts[3].split(",") if d]
        taint = None
        if len(parts) >= 7 and parts[6].startswith("(") and parts[6].endswith(")"):
            taint = parts[6][1:-1]
        try:
            rows.append(ModuleRow(
                name=parts[0], size=int(parts[1]), refcount=int(parts[2]),
                dependents=deps, state=parts[4], base_addr=parts[5], taint=taint,
            ))
        except ValueError as exc:
            raise ModuleParseError(f"non-numeric field: {line!r}") from exc
    return rows


def parse_tainted(text: str) -> int:
    """The /proc/sys/kernel/tainted word as an int. Bit 12 = out-of-tree,
    bit 13 = unsigned (spec §3, 08-taint-accounting.txt)."""
    try:
        return int(text.strip())
    except ValueError as exc:
        raise ModuleParseError(f"non-integer tainted value: {text!r}") from exc


def count_module_regions(text: str) -> int:
    """Number of load_module allocations in /proc/vmallocinfo.

    Addresses are hash-obfuscated (L15), so this counts regions and never
    correlates by address (07-vmallocinfo-modules.txt)."""
    return sum(1 for line in text.splitlines() if "load_module" in line)


def parse_ftrace_modules(text: str) -> set[str]:
    """The set of module names tagged in available_filter_functions.

    A record for a module reads 'symbol [modname]'; core-kernel records have
    no bracket. Only bracketed tags name a module (06-ftrace-module-tags.txt)."""
    names: set[str] = set()
    for line in text.splitlines():
        line = line.rstrip()
        if line.endswith("]") and "[" in line:
            names.add(line[line.rindex("[") + 1 : -1])
    return names
