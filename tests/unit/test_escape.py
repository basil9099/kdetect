import pytest

from kdetect.reporting.escape import md_block, md_code, printable


@pytest.mark.parametrize(("raw", "want"), [
    ("kdetect_hooktest", "kdetect_hooktest"),
    ("módulo", "módulo"),                       # printable non-ASCII is left alone
    ("evil\x1b[2Kclean", "evil\\x1b[2Kclean"),  # ESC could rewrite the terminal line
    ("a\nb\rc\td", "a\\nb\\rc\\td"),
    ("back\\slash", "back\\\\slash"),           # so a literal "\x1b" stays distinguishable
    ("del\x7f", "del\\x7f"),
    ("c1\x85", "c1\\x85"),
    ("rtl‮txt", "rtl\\u202etxt"),          # bidi override reorders displayed text
    ("zero​width", "zero\\u200bwidth"),
    ("line sep", "line\\u2028sep"),
    ("lone\ud800", "lone\\ud800"),              # json.loads can yield lone surrogates
])
def test_printable(raw, want):
    assert printable(raw) == want


@pytest.mark.parametrize(("raw", "want"), [
    ("kdetect_hooktest", "`kdetect_hooktest`"),
    ("[click](https://evil.example)", "`[click](https://evil.example)`"),
    ("a`b", "``a`b``"),
    ("a``b", "```a``b```"),
    ("`start", "`` `start ``"),
    ("end`", "`` end` ``"),
    (" padded ", "`  padded  `"),
    ("esc\x1b", "`esc\\x1b`"),
    ("", "(empty)"),
])
def test_md_code(raw, want):
    assert md_code(raw) == want


def test_md_block_wraps_lines_in_a_text_fence():
    assert md_block(["one", "two"]) == ["```text", "one", "two", "```"]


def test_md_block_fence_outlasts_backticks_inside():
    # A line of three backticks would otherwise close the block early and let
    # the following line render as Markdown.
    assert md_block(["```", "# not a heading"]) == [
        "````text", "```", "# not a heading", "````"]


def test_md_block_escapes_control_characters_per_line():
    assert md_block(["a\nb"]) == ["```text", "a\\nb", "```"]
