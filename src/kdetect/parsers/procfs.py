from dataclasses import dataclass


class ParseError(ValueError):
    """Raised when a /proc file cannot be parsed."""


@dataclass(frozen=True)
class StatFields:
    pid: int
    comm: str
    state: str
    ppid: int
    flags: int
    num_threads: int
    starttime_ticks: int


def parse_stat(text: str) -> StatFields:
    """Parse one line of /proc/[pid]/stat into typed fields.

    Field 2 (comm) is wrapped in parentheses and may itself contain spaces and
    parentheses, so the line cannot be split on whitespace.
    See docs/step0/03-comm-paren-trap.txt for the captured evidence.
    """
    text = text.rstrip()

    # Locate the comm delimiters. rfind scans from the RIGHT, so it finds the
    # last ')' even when comm contains parens of its own.
    open_idx = text.find("(")
    close_idx = text.rfind(")")
    if open_idx == -1 or close_idx == -1 or close_idx < open_idx:
        raise ParseError(f"no parenthesised comm field in stat line: {text!r}")

    # Everything after the closing paren is field 3 onwards, and only that part
    # is safe to split on whitespace.
    rest = text[close_idx + 1:].split()

    # We index rest[19] below, so we need at least 20 entries.
    if len(rest) < 20:
        raise ParseError(
            f"expected at least 20 fields after comm, got {len(rest)}: {text!r}"
        )

    # rest[0] is stat field 3, so stat field N lives at rest[N - 3].
    try:
        return StatFields(
            pid=int(text[:open_idx].strip()),
            comm=text[open_idx + 1:close_idx],
            state=rest[0],                   # field 3
            ppid=int(rest[1]),               # field 4
            flags=int(rest[6]),              # field 9  (PF_KTHREAD = 0x00200000)
            num_threads=int(rest[17]),       # field 20
            starttime_ticks=int(rest[19]),   # field 22, clock ticks since boot
        )
    except ValueError as exc:
        # int() raises ValueError on non-numeric input. Wrapping it means
        # callers only ever need to catch ParseError.
        raise ParseError(f"non-numeric field in stat line: {text!r}") from exc
