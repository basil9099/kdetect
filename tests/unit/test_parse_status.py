import pytest

from kdetect.parsers.procfs import ParseError, parse_status

STATUS = """Name:\tbash
State:\tS (sleeping)
Tgid:\t6009
Pid:\t6009
PPid:\t6008
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
Threads:\t1
"""


def test_uid_and_gid_are_four_tuples():
    s = parse_status(STATUS)
    assert s.uid == [1000, 1000, 1000, 1000]
    assert s.gid == [1000, 1000, 1000, 1000]


def test_root_process():
    s = parse_status("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
    assert s.uid == [0, 0, 0, 0]


def test_missing_uid_line_raises():
    with pytest.raises(ParseError):
        parse_status("Name:\tbash\n")
