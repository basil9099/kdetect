"""Neutralise untrusted strings in output meant for a person.

Every string in a snapshot is untrusted: the file may come from a compromised
host, and a rootkit chooses its own module name. Snapshots, JSON output and IOCs
keep exact values; these helpers only change what a terminal or a Markdown
renderer is shown.
"""
from __future__ import annotations

import unicodedata

#: Unicode categories shown as escapes: controls (Cc: ESC, newline, DEL),
#: format characters (Cf: bidi overrides, zero-width spaces), lone surrogates
#: (Cs, which json.loads can produce) and line/paragraph separators (Zl, Zp).
_INVISIBLE = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

#: Backslash is escaped too, so a literal "\x1b" in a name stays distinguishable
#: from an escaped ESC.
_SHORT = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\\": "\\\\"}


def printable(s: str) -> str:
    """Show control and invisible characters as visible escapes such as \\x1b."""
    out = []
    for ch in s:
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif unicodedata.category(ch) in _INVISIBLE:
            cp = ord(ch)
            if cp < 0x100:
                out.append(f"\\x{cp:02x}")
            elif cp < 0x10000:
                out.append(f"\\u{cp:04x}")
            else:
                out.append(f"\\U{cp:08x}")
        else:
            out.append(ch)
    return "".join(out)


def _longest_backtick_run(s: str) -> int:
    longest = run = 0
    for ch in s:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return longest


def md_code(s: str) -> str:
    """An inline code span the value cannot break out of.

    The fence is one backtick longer than any run inside the value. CommonMark
    strips one space from each end of a span, so a value that begins or ends
    with a backtick or a space gets a space of padding on both sides.
    """
    s = printable(s)
    if not s:
        return "(empty)"
    fence = "`" * (_longest_backtick_run(s) + 1)
    if s[0] in "` " or s[-1] in "` ":
        s = f" {s} "
    return f"{fence}{s}{fence}"


def md_block(lines: list[str]) -> list[str]:
    """A fenced text block whose fence outlasts any backtick run inside it."""
    body = [printable(line) for line in lines]
    longest = max((_longest_backtick_run(line) for line in body), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "text", *body, fence]
