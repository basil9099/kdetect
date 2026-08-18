import os

import pytest

from kdetect.collectors.base import Vanished
from kdetect.collectors.sources import LiveProcSource
from tests.conftest import needs_procfs

pytestmark = needs_procfs


def test_lists_only_numeric_pids():
    pids = LiveProcSource().list_pids()
    assert all(isinstance(p, int) and p > 0 for p in pids)
    assert pids == sorted(pids)
    assert 1 in pids


def test_reads_own_stat():
    text = LiveProcSource().read_text(os.getpid(), "stat")
    assert text.startswith(f"{os.getpid()} (")


def test_kernel_thread_exe_raises_vanished_or_unreadable():
    # PID 2 has no executable: ENOENT. See docs/step0/06-exe-errno-comparison.txt
    with pytest.raises(Exception):
        LiveProcSource().read_link(2, "exe")


def test_nonexistent_pid_raises_vanished():
    with pytest.raises(Vanished):
        LiveProcSource().read_text(999999, "stat")


def test_oserror_never_escapes():
    src = LiveProcSource()
    try:
        src.read_text(999999, "stat")
    except OSError:
        pytest.fail("raw OSError escaped the source layer")
    except Exception:
        pass
