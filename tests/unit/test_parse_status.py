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
    s = parse_status("Tgid:\t1\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
    assert s.uid == [0, 0, 0, 0]


def test_missing_uid_line_raises():
    with pytest.raises(ParseError):
        parse_status("Name:\tbash\n")


def test_parse_status_reads_tgid():
    text = "Name:\tbash\nTgid:\t501\nPid:\t551\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
    assert parse_status(text).tgid == 501


def test_parse_status_extracts_name():
    text = ("Name:\tevil\nTgid:\t1234\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
    fields = parse_status(text)
    assert fields.name == "evil"
    assert fields.tgid == 1234


def test_parse_status_name_absent_is_none():
    text = ("Tgid:\t1\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
    assert parse_status(text).name is None
