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


def _callback_and_module(text: str) -> tuple[str | None, str | None]:
    """Pull the dispatch callback and any owning [module] out of one line of
    enabled_functions detail.

    The callback follows the last '->'; failing that, the symbol inside the
    'tramp: (...)' group. The owning module, when the kernel tags it, is the
    last [bracketed] name on the line. Offsets and addresses are dropped (L4).
    Confirmed against the real single-line format in
    docs/step0-phase3/hooked/01-enabled_functions.txt, e.g.:
        __x64_sys_newuname (1) R I\ttramp: 0x.. (cb+0x0/0x5 [mod]) ->cb+0x0/0x5 [mod]
    """
    module: str | None = None
    lb = text.rfind("[")
    if lb != -1:
        rb = text.find("]", lb)
        if rb != -1:
            module = text[lb + 1:rb]

    callback: str | None = None
    if "->" in text:
        after = text.rsplit("->", 1)[1].split()
        if after:
            callback = after[0].split("+")[0] or None
    elif "tramp:" in text and "(" in text:
        inner = text.split("tramp:", 1)[1]
        inner = inner[inner.index("(") + 1:].split(")")[0].split()
        if inner:
            callback = inner[0].split("+")[0] or None
    return callback, module


def parse_enabled_functions(text: str) -> list[HookRow]:
    """Parse /sys/kernel/tracing/enabled_functions.

    A hooked function begins a column-0 line: "name (count) [flags] [tramp: ...]".
    On the observed 6.1 kernel the callback and its owning [module] sit on that
    SAME line (docs/step0-phase3/hooked/); older/other layouts may continue the
    detail on indented lines, which we still read. The function name is the
    column-0 token; the callback and module come from wherever they appear, and
    the first callback seen for a function wins. If no module is tagged,
    owner_module stays None and the collector attributes via kallsyms instead.
    """
    rows: list[HookRow] = []
    function: str | None = None
    callback: str | None = None
    owner_module: str | None = None

    def flush() -> None:
        nonlocal function, callback, owner_module
        if function is not None:
            rows.append(HookRow(function, "ftrace", callback, owner_module))
        function, callback, owner_module = None, None, None

    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():          # column-0 line: a new hooked function
            flush()
            function = line.split()[0]
            callback, owner_module = _callback_and_module(line)
        else:                              # indented continuation (older layout)
            cb, mod = _callback_and_module(line)
            if callback is None:
                callback = cb
            if owner_module is None:
                owner_module = mod
    flush()
    return rows


def parse_kprobes(text: str) -> list[HookRow]:
    """Parse /sys/kernel/debug/kprobes/list.

    Columns: <addr> <type> <symbol>+<offset> [flags...]. We keep the symbol,
    dropping the address (L4). Type is 'k' for kprobe."""
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
