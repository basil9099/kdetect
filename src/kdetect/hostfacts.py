"""Host context, gathered once per capture.

Every field here is mandatory. A snapshot whose starttime values cannot be
interpreted is not a partial snapshot - it is an unusable one - so a missing
value raises rather than becoming None.
"""

from __future__ import annotations

import os
import socket

from kdetect.models import HostFacts

BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
STAT_PATH = "/proc/stat"


def _btime() -> int:
    """Seconds since the epoch at which the system booted.

    Without this, stat field 22 (starttime, expressed in clock ticks since
    boot) cannot be turned into a wall-clock time - it is just an integer.
    Verified against `ps -o lstart=` in docs/step0/01-stat-fields.txt.
    """
    with open(STAT_PATH, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("btime "):
                return int(line.split()[1])
    raise RuntimeError(f"no btime line in {STAT_PATH}")


def gather() -> HostFacts:
    """Collect the host context a snapshot cannot be read without."""
    uname = os.uname()
    with open(BOOT_ID_PATH, encoding="utf-8") as fh:
        boot_id = fh.read().strip()

    return HostFacts(
        hostname=socket.gethostname(),
        kernel_release=uname.release,
        arch=uname.machine,
        boot_id=boot_id,
        btime=_btime(),
        # SC_CLK_TCK is 100 on Debian 12/x86_64, but it is a property of the
        # kernel build, not a constant. Reading it means a capture taken on a
        # differently-configured host still interprets correctly.
        clock_ticks_per_sec=os.sysconf("SC_CLK_TCK"),
    )
