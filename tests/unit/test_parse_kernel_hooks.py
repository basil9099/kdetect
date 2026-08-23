import pytest
from kdetect.parsers.kernel_hooks import (
    HookRow, KernelHookParseError,
    parse_enabled_functions, parse_kprobes, reduce_kallsyms,
)

# Verbatim from docs/step0-phase3/hooked/01-enabled_functions.txt — the REAL
# single-line format on kernel 6.1.0-52: function, flags, tramp, callback, and
# the owning [module] all on one line. Captured with kdetect_hooktest loaded.
ENABLED = (
    "__x64_sys_newuname (1) R I\ttramp: 0xffffffffc0665000 "
    "(kdetect_callback+0x0/0x5 [kdetect_hooktest]) "
    "->kdetect_callback+0x0/0x5 [kdetect_hooktest]\n"
)

def test_parse_enabled_functions_extracts_function_callback_and_module():
    rows = parse_enabled_functions(ENABLED)
    assert len(rows) == 1
    r = rows[0]
    assert r.function == "__x64_sys_newuname"
    assert r.hook_type == "ftrace"
    assert r.callback == "kdetect_callback"       # offset/address dropped (L4)
    assert r.owner_module == "kdetect_hooktest"   # inline [module] tag read

def test_parse_enabled_functions_empty_is_no_rows():
    assert parse_enabled_functions("") == []

def test_parse_enabled_functions_core_kernel_callback_has_no_module():
    """A callback in the core kernel carries no [module] tag -> owner_module None
    (the collector then leaves it unattributed; the differ decides what that
    means). Uses the same single-line shape without a bracket."""
    core = "some_syscall (1) R I\t->ftrace_ops_list_func+0x0/0x1a0\n"
    rows = parse_enabled_functions(core)
    assert rows[0].function == "some_syscall"
    assert rows[0].callback == "ftrace_ops_list_func"
    assert rows[0].owner_module is None

def test_parse_enabled_functions_multiline_layout_still_read():
    """Defensive: an older/other layout that puts the callback on an indented
    continuation line is still parsed."""
    multiline = (
        "evil_hook (1)\n"
        "\t tramp: 0xffffffffc0451000 (evil_callback+0x0/0x10) [rootkit]\n"
    )
    rows = parse_enabled_functions(multiline)
    assert rows[0].function == "evil_hook"
    assert rows[0].callback == "evil_callback"
    assert rows[0].owner_module == "rootkit"

# Verbatim from docs/step0-phase3/clean/02-kprobes.txt
KPROBES = """\
ffffffff81234560  k  do_int3+0x0    [DISABLED]
ffffffffc0451000  k  __x64_sys_newuname+0x0
"""

def test_parse_kprobes_extracts_symbol():
    rows = parse_kprobes(KPROBES)
    funcs = {r.function for r in rows}
    assert "__x64_sys_newuname" in funcs
    assert all(r.hook_type == "kprobe" for r in rows)

def test_parse_kprobes_raises_on_short_line():
    with pytest.raises(KernelHookParseError):
        parse_kprobes("addr  k")

# Verbatim from docs/step0-phase3/clean/04-kallsyms-module-tags.txt
KALLSYMS = """\
ffffffff81000000 T commit_creds
0000000000000000 t e1000_hook	[e1000]
0000000000000000 t kdetect_callback	[kdetect_hooktest]
"""

def test_reduce_kallsyms_maps_symbol_to_module():
    m = reduce_kallsyms(KALLSYMS)
    assert m["kdetect_callback"] == "kdetect_hooktest"
    assert m["e1000_hook"] == "e1000"
    assert "commit_creds" not in m          # no [module] tag -> core kernel

def test_reduce_kallsyms_ignores_addresses():
    # zeroed addresses (L4) must not appear anywhere in the reduced output
    m = reduce_kallsyms(KALLSYMS)
    # Assert specific address tokens from the fixture don't appear in keys or values
    assert "ffffffff81000000" not in m
    assert "0000000000000000" not in m
    # Assert no address tokens leak into keys or values
    for k, v in m.items():
        assert not k.startswith("0x") and not k.startswith("f"), f"key {k} looks like an address"
        assert not v.startswith("0x") and not v.startswith("f"), f"value {v} looks like an address"
