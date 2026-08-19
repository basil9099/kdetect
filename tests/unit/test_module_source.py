import json
from pathlib import Path

from kdetect.collectors.sources import FixtureModuleSource

CLEAN = Path(__file__).parent.parent / "fixtures" / "module-trees" / "clean"


def test_reads_channels():
    s = FixtureModuleSource(CLEAN)
    assert "ext4" in s.read_proc_modules()
    assert s.read_tainted() == 0
    assert s.read_vmallocinfo().count("load_module") == 2
    assert "[ext4]" in s.read_ftrace_functions()


def test_sys_module_distinguishes_loaded_from_builtin():
    s = FixtureModuleSource(CLEAN)
    assert s.sys_module_is_loaded("ext4") is True
    assert s.sys_module_is_loaded("acpi") is False     # built-in, no initstate


def test_module_evidence_null_channel_when_unreadable(tmp_path):
    # Only sys_module.json is present - proc_modules.txt, tainted.txt,
    # vmallocinfo.txt and ftrace.txt are all missing. A missing file replays
    # "unreadable": vmallocinfo and ftrace must come back None (SKIPPED by
    # the differ, never treated as agreement), while proc_modules and
    # tainted fall back to their documented defaults.
    (tmp_path / "sys_module.json").write_text(
        json.dumps({"ext4": True}), encoding="utf-8"
    )

    s = FixtureModuleSource(tmp_path)

    assert s.read_proc_modules() == ""
    assert s.read_tainted() == 0
    assert s.read_vmallocinfo() is None
    assert s.read_ftrace_functions() is None
