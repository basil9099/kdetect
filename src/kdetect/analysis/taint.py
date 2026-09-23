"""Taint-word reconciliation (spec section 4). Pure.

/proc/sys/kernel/tainted is one bitmask for the whole kernel; /proc/modules
marks each listed module with the letters it contributed. A set bit is
*explained* when some listed module carries that bit's letter.

Reconciliation replaces a count. A count cannot say WHICH bit a module
accounts for, which is how one legitimately tainted module came to silence the
entire channel.

The table carries only the two letters this repository has evidence for:
docs/step0-phase2/clean/08-taint-accounting.txt records bit 12 as out-of-tree
with marker (O) and bit 13 as unsigned with marker (E). Those are also the only
bits the taint signal has ever tested. Widening the table needs the evidence
captured first (spec section 4.3).

Note the limit this cannot pass, recorded in spec section 1.2 and L17: taint is
a set of sticky booleans about the whole boot. "At least one out-of-tree module
was loaded" cannot distinguish one from two, so on a host with a listed (O)
module a hidden out-of-tree module adds no observable bit. Reconciliation makes
that state visible (`saturated`); it cannot detect through it.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Taint bit -> the /proc/modules marker letter that accounts for it.
#: Evidence: docs/step0-phase2/clean/08-taint-accounting.txt
TAINT_BIT_LETTER: dict[int, str] = {12: "O", 13: "E"}


@dataclass(frozen=True)
class TaintReconciliation:
    """Which reconcilable taint bits are set, and what accounts for them."""

    unexplained: list[int]
    explained_by: dict[int, list[str]]

    @property
    def saturated(self) -> bool:
        """Every reconcilable set bit is explained by a listed module.

        The channel is answering honestly and has nothing left to say about a
        hidden module. Distinct from a clean taint word, where no bit is set at
        all -- which is why this requires explained_by to be non-empty.
        """
        return not self.unexplained and bool(self.explained_by)


def reconcile(taint: int, listed: dict[str, str | None]) -> TaintReconciliation:
    """Reconcile the global taint word against per-module markers.

    `listed` maps each listed module's name to its /proc/modules marker string
    (e.g. "OE") or None. Bits outside TAINT_BIT_LETTER are ignored: they are set
    by events no module can account for, and reconciling them would fire on any
    host that has ever emitted a kernel warning.
    """
    unexplained: list[int] = []
    explained: dict[int, list[str]] = {}
    for bit, letter in sorted(TAINT_BIT_LETTER.items()):
        if not taint & (1 << bit):
            continue
        owners = sorted(n for n, marker in listed.items() if marker and letter in marker)
        if owners:
            explained[bit] = owners
        else:
            unexplained.append(bit)
    return TaintReconciliation(unexplained=unexplained, explained_by=explained)
