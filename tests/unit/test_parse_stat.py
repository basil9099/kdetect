import pytest

from kdetect.parsers.procfs import ParseError, parse_stat

PAREN_COMM = (
    "6041 (ev (il) proc) S 6009 6009 6009 0 -1 4194304 110 0 0 0 0 0 0 0 "
    "20 0 1 0 368731 5603328 226 18446744073709551615 94560358600704"
)

NORMAL = (
    "6009 (bash) S 6008 6009 6009 0 -1 4194304 736 1504 0 1 0 0 1 0 "
    "20 0 1 0 368626 7106560 869 18446744073709551615 94700239310848"
)

KTHREADD = (
    "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 "
    "20 0 1 0 6 0 0 18446744073709551615 0 0"
)


def test_comm_with_spaces_and_parens_does_not_misalign_fields():
    s = parse_stat(PAREN_COMM)
    assert s.pid == 6041
    assert s.comm == "ev (il) proc"
    assert s.state == "S"
    assert s.ppid == 6009


def test_normal_line():
    s = parse_stat(NORMAL)
    assert s.pid == 6009
    assert s.comm == "bash"
    assert s.state == "S"
    assert s.ppid == 6008
    assert s.flags == 4194304
    assert s.num_threads == 1
    assert s.starttime_ticks == 368626


def test_kernel_thread_flags():
    s = parse_stat(KTHREADD)
    assert s.comm == "kthreadd"
    assert s.ppid == 0
    assert s.flags == 2129984
    assert s.flags & 0x00200000  # PF_KTHREAD


def test_comm_at_fifteen_char_limit():
    line = "42 (abcdefghijklmno) S 1 1 1 0 -1 4194304 " + "0 " * 12 + "20 0 1 0 99 0 0"
    assert parse_stat(line).comm == "abcdefghijklmno"


def test_trailing_newline_is_tolerated():
    assert parse_stat(NORMAL + "\n").pid == 6009


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not a stat line at all",
        "123 (noclose S 1 1",
        "123 (bash) S 1",
    ],
)
def test_malformed_raises_parse_error(bad):
    with pytest.raises(ParseError):
        parse_stat(bad)
