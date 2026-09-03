import pytest
from kdetect.parsers.sockets import (
    NetRow, SocketParseError, parse_net_tcp,
)

TCP = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode\n"
    "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
    "     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
    "   1: 0100007F:1F90 0100007F:C3A2 01 00000000:00000000 00:00000000 00000000"
    "  1000        0 67890 1 0000000000000000 20 4 30 10 -1\n"
)

def test_parse_tcp_decodes_addr_state_inode_uid():
    rows = parse_net_tcp(TCP, "tcp")
    assert rows[0] == NetRow(inode=12345, kind="tcp", state="LISTEN",
                             local="127.0.0.1:53", remote="0.0.0.0:0", uid=0)
    assert rows[1].state == "ESTABLISHED"
    assert rows[1].local == "127.0.0.1:8080" and rows[1].uid == 1000

def test_parse_tcp_skips_header_and_blank():
    assert parse_net_tcp("sl local_address rem_address st\n\n", "tcp") == []

def test_parse_tcp6_decodes_v6():
    # loopback ::1 , port 0x1F90 = 8080
    tcp6 = (
        "  sl  local_address                         remote_address"
        "                      st ... uid ... inode\n"
        "   0: 00000000000000000000000001000000:1F90"
        " 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000"
        " 00000000     0        0 55555 1 0 100 0 0 10 0\n"
    )
    rows = parse_net_tcp(tcp6, "tcp6")
    assert rows[0].inode == 55555
    assert rows[0].local.endswith(":8080")
    assert ":" in rows[0].local           # a v6 address rendered

def test_parse_tcp_raises_on_short_row():
    with pytest.raises(SocketParseError):
        parse_net_tcp("  0: 0100007F:0035\n", "tcp")
