from kdetect.parsers.modules import (
    parse_proc_modules, parse_tainted, count_module_regions, parse_ftrace_modules,
)

def test_parse_proc_modules_basic():
    # name size refcount dependents state base [taint]
    text = (
        "ext4 999424 1 - Live 0xffffffffc0591000\n"
        "diamorphine 16384 0 - Live 0x0000000000000000 (OE)\n"
        "crc16 12288 1 ext4,foo Live 0xffffffffc0455000\n"
    )
    rows = {r.name: r for r in parse_proc_modules(text)}
    assert rows["ext4"].size == 999424 and rows["ext4"].taint is None
    assert rows["diamorphine"].taint == "OE"
    assert rows["crc16"].dependents == ["ext4", "foo"]     # "-" means none
    assert rows["ext4"].dependents == []

def test_parse_tainted_bits():
    assert parse_tainted("0\n") == 0
    assert parse_tainted("12288\n") == 12288               # bits 12+13 set

def test_count_module_regions_counts_load_module_lines():
    text = (
        "0x1-0x2 20480 load_module+0xbb7/0x21a0 pages=4 vmalloc N0=4\n"
        "0x3-0x4 8192 some_other_alloc+0x0 pages=2 vmalloc N0=2\n"
        "0x5-0x6 32768 load_module+0xbb7/0x21a0 pages=7 vmalloc N0=7\n"
    )
    assert count_module_regions(text) == 2

def test_parse_ftrace_modules_extracts_bracket_tags():
    text = (
        "vfs_read\n"                       # core kernel, untagged
        "ext4_file_read_iter [ext4]\n"
        "ext4_readpage [ext4]\n"
        "diamorphine_init [diamorphine]\n"
    )
    assert parse_ftrace_modules(text) == {"ext4", "diamorphine"}
