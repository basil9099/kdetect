from kdetect.collectors.sources import FixtureKernelHookSource

def test_fixture_reads_present_files(tmp_path):
    (tmp_path / "enabled_functions.txt").write_text("foo (1)\n")
    (tmp_path / "kprobes.txt").write_text("addr k foo+0x0\n")
    (tmp_path / "kallsyms.txt").write_text("addr t foo\t[bar]\n")
    src = FixtureKernelHookSource(tmp_path)
    assert src.read_enabled_functions() == "foo (1)\n"
    assert "foo" in src.read_kprobes()
    assert "[bar]" in src.read_kallsyms_index()

def test_fixture_missing_file_reads_none(tmp_path):
    src = FixtureKernelHookSource(tmp_path)      # empty dir
    assert src.read_enabled_functions() is None
    assert src.read_kprobes() is None
    assert src.read_kallsyms_index() is None
