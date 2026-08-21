import pytest
from kdetect.parsers.kernel_hooks import (
    HookRow, KernelHookParseError,
    parse_enabled_functions, parse_kprobes, reduce_kallsyms,
)

# Verbatim from docs/step0-phase3/hooked/01-enabled_functions.txt
ENABLED = """\
__x64_sys_newuname (1)
	 tramp: 0xffffffffc0451000 (kdetect_callback+0x0/0x10)
	  ->ftrace_ops_list_func+0x0/0x1a0
"""

def test_parse_enabled_functions_extracts_function_and_callback():
    rows = parse_enabled_functions(ENABLED)
    assert len(rows) == 1
    r = rows[0]
    assert r.function == "__x64_sys_newuname"
    assert r.hook_type == "ftrace"
    assert "kdetect_callback" in r.callback

def test_parse_enabled_functions_empty_is_no_rows():
    assert parse_enabled_functions("") == []

def test_parse_enabled_functions_extracts_owner_module_from_bracket_tag():
    """Callback with [module] tag sets owner_module; without tag leaves it None."""
    ENABLED_WITH_TAG = """\
evil_hook (1)
	 tramp: 0xffffffffc0451000 (evil_callback+0x0/0x10) [rootkit]
	  ->ftrace_ops_list_func+0x0/0x1a0
"""
    rows = parse_enabled_functions(ENABLED_WITH_TAG)
    assert len(rows) == 1
    r = rows[0]
    assert r.function == "evil_hook"
    assert r.owner_module == "rootkit"

    # Without bracket tag, owner_module stays None
    rows_no_tag = parse_enabled_functions(ENABLED)
    assert rows_no_tag[0].owner_module is None

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
