import json
from pathlib import Path

import pytest

from kdetect.collectors.base import Denied, Vanished
from kdetect.collectors.sources import FixtureProcSource

ROOT = Path(__file__).parent.parent / "fixtures" / "proc-trees" / "clean-vm-6.1.0-10"


@pytest.fixture
def src():
    return FixtureProcSource(ROOT)


def test_lists_pids_sorted(src):
    pids = src.list_pids()
    assert pids == sorted(pids)
    assert 1 in pids and 2 in pids


def test_reads_stat(src):
    assert src.read_text(1, "stat").startswith("1 (")


def test_kernel_thread_cmdline_is_empty(src):
    assert src.read_text(2, "cmdline") == ""


def test_recorded_eacces_is_replayed(src):
    with pytest.raises(Denied):
        src.read_link(812, "exe")


def test_recorded_enoent_is_replayed(src):
    with pytest.raises(Vanished):
        src.read_text(4171, "stat")


def test_readlink_returns_target_verbatim(src):
    assert src.read_link(1, "exe") == "/usr/lib/systemd/systemd"


def test_errors_sidecar_is_valid_json():
    assert isinstance(json.loads((ROOT / "_errors.json").read_text()), dict)
