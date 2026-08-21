"""Pure parsers for the hook-surface channels (spec §4).

Text in, typed values out, no I/O. Each mirrors a file in docs/step0-phase3/
and every case in the tests is drawn from there. Addresses are never carried
out of these parsers: under L4 they read as zero unprivileged, and it is the
symbol/module names that later phases diff.
"""
from __future__ import annotations

from dataclasses import dataclass


class KernelHookParseError(ValueError):
    """A hook-surface file could not be parsed."""


@dataclass(frozen=True)
class HookRow:
    function: str
    hook_type: str                 # "ftrace" | "kprobe"
    callback: str | None           # dispatch target as the surface names it
    owner_module: str | None       # only if the surface tags it inline


def parse_enabled_functions(text: str) -> list[HookRow]:
    """Parse /sys/kernel/tracing/enabled_functions.

    A hooked function is a line that starts in column 0: "name (count)".
    Indented lines beneath it describe the ops/callback; we keep the first
    callback symbol we see. Format confirmed in docs/step0-phase3/hooked/.
    """
    rows: list[HookRow] = []
    function: str | None = None
    callback: str | None = None

    def flush() -> None:
        nonlocal function, callback
        if function is not None:
            rows.append(HookRow(function, "ftrace", callback, None))
        function, callback = None, None

    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():          # column-0 line: a new hooked function
            flush()
            function = line.split()[0]
        elif callback is None:             # first indented callback line
            # e.g. "->ftrace_ops_list_func+..." or "tramp: 0x.. (sym+0x../..)"
            if "(" in line and ")" in line:
                callback = line[line.index("(") + 1 : line.rindex(")")].split("+")[0]
            elif "->" in line:
                callback = line.split("->", 1)[1].split("+")[0].strip()
    flush()
    return rows


def parse_kprobes(text: str) -> list[HookRow]:
    """Parse /sys/kernel/debug/kprobes/list.

    Columns: <addr> <type> <symbol>+<offset> [flags...]. We keep the symbol,
    dropping the address (L4). Type letter is 'k'/'r' (kprobe/kretprobe)."""
    rows: list[HookRow] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 3:
            raise KernelHookParseError(f"short kprobes line: {line!r}")
        symbol = parts[2].split("+")[0]
        rows.append(HookRow(symbol, "kprobe", None, None))
    return rows


def reduce_kallsyms(text: str) -> dict[str, str]:
    """Map symbol name -> owning module, for module-tagged symbols only.

    A module symbol reads "<addr> <type> <name>\\t[module]"; core-kernel
    symbols have no bracket. Addresses are discarded (L4). This is the map the
    collector uses to attribute a callback symbol to a module."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.rstrip()
        if not (stripped.endswith("]") and "[" in stripped):
            continue
        module = stripped[stripped.rindex("[") + 1 : -1]
        parts = stripped.split()
        if len(parts) >= 3:
            out[parts[2]] = module
    return out
