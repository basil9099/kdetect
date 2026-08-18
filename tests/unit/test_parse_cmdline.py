from kdetect.parsers.procfs import parse_cmdline


def test_nul_separated_args():
    assert parse_cmdline("/usr/bin/sleep\x00300\x00") == ["/usr/bin/sleep", "300"]


def test_kernel_thread_has_empty_cmdline():
    # docs/step0/05-kernel-thread-pid2.txt: cmdline is 0 bytes. Not an error.
    assert parse_cmdline("") == []


def test_forged_argv0_is_preserved_verbatim():
    # docs/step0/02-comm-vs-cmdline.txt: argv[0] is attacker-controlled.
    raw = "evil (hidden) proc\x0030\x00"
    assert parse_cmdline(raw) == ["evil (hidden) proc", "30"]


def test_no_trailing_nul():
    assert parse_cmdline("a\x00b") == ["a", "b"]


def test_only_nuls():
    assert parse_cmdline("\x00\x00") == []
