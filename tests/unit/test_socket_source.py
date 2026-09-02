import json
from kdetect.collectors.sources import FixtureSocketSource

def test_fixture_reads_table_and_fds(tmp_path):
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "tcp.txt").write_text("  0: 0100007F:0035 ...\n")
    (tmp_path / "fds.json").write_text(json.dumps({"812": [12345], "4171": [999]}))
    src = FixtureSocketSource(tmp_path)
    assert "0100007F" in src.read_net_table("tcp")
    assert src.read_net_table("udp") is None          # absent -> None
    assert src.list_fds(812) == {12345: ["/proc/812/fd/0"]}
    assert src.list_fds(999999) == {}                  # unknown pid -> {}

def test_fixture_missing_tree_is_none(tmp_path):
    src = FixtureSocketSource(tmp_path)
    assert src.read_net_table("tcp") is None
    assert src.list_fds(1) == {}
