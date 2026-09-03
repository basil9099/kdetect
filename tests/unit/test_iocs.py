from kdetect.analysis.models import Finding, FindingKind, Confidence
from kdetect.reporting.iocs import IOC, extract

def _f(kind, subject, evidence, conf=Confidence.HIGH):
    return Finding(kind, subject, conf, [], [], evidence, "")

def test_hidden_module_yields_module_and_hook_iocs():
    f = _f(FindingKind.HIDDEN_MODULE, "module diamorphine",
           {"unexpected_hook": [{"function": "__x64_sys_kill"}]})
    iocs = extract([f])
    kinds = {(i.type, i.value) for i in iocs}
    assert ("kernel_module", "diamorphine") in kinds
    assert ("hooked_function", "__x64_sys_kill") in kinds

def test_hidden_process_yields_process_name_and_endpoint():
    f = _f(FindingKind.HIDDEN_PROCESS, "pid 1234",
           {"syscall_kill": [{"comm": "evil"}],
            "socket_visible": [{"state": "ESTABLISHED",
                                "remote": "1.2.3.4:4444", "local": "0.0.0.0:0"}]})
    vals = {(i.type, i.value) for i in extract([f])}
    assert ("process_name", "evil") in vals
    assert ("network_endpoint", "1.2.3.4:4444") in vals

def test_listen_socket_uses_local_and_skips_placeholder():
    f = _f(FindingKind.HIDDEN_PROCESS, "pid 1",
           {"socket_visible": [{"state": "LISTEN",
                                "local": "0.0.0.0:4444", "remote": "0.0.0.0:0"}]})
    vals = {(i.type, i.value) for i in extract([f])}
    assert ("network_endpoint", "0.0.0.0:4444") in vals
    assert all(not v.endswith(":0") for t, v in vals if t == "network_endpoint")

def test_established_socket_skips_placeholder_remote():
    # ESTABLISHED reads remote; remote is placeholder -> no endpoint IOC
    f = _f(FindingKind.HIDDEN_PROCESS, "pid 2",
           {"socket_visible": [{"state": "ESTABLISHED",
                                "remote": "0.0.0.0:0", "local": "192.168.1.5:8080"}]})
    vals = {(i.type, i.value) for i in extract([f])}
    assert all(t != "network_endpoint" for t, v in vals)

def test_listen_socket_skips_placeholder_local():
    # LISTEN reads local; local is placeholder -> no endpoint IOC
    f = _f(FindingKind.HIDDEN_PROCESS, "pid 3",
           {"socket_visible": [{"state": "LISTEN",
                                "local": "0.0.0.0:0", "remote": "192.168.1.10:9090"}]})
    vals = {(i.type, i.value) for i in extract([f])}
    assert all(t != "network_endpoint" for t, v in vals)

def test_syn_sent_socket_uses_remote_not_local():
    # Regression test for the bug fixed in review: the old code did
    # `remote if state == "ESTABLISHED" else local`, which for SYN_SENT
    # (the state most likely to catch a C2 beacon mid-connect) published
    # this host's own address and threw the attacker's away. This must
    # fail against that old behaviour: local is a real, non-placeholder
    # address, so the old code would have emitted it as the IOC instead
    # of (or as well as) remote.
    f = _f(FindingKind.HIDDEN_PROCESS, "pid 4",
           {"socket_visible": [{"state": "SYN_SENT",
                                "local": "192.168.1.5:51000",
                                "remote": "203.0.113.9:4444"}]})
    vals = {(i.type, i.value) for i in extract([f])}
    assert ("network_endpoint", "203.0.113.9:4444") in vals
    assert ("network_endpoint", "192.168.1.5:51000") not in vals


def test_udp_close_state_with_placeholder_remote_yields_local_only():
    # UDP rows report CLOSE (from /proc/net/udp's st=07) and normally
    # carry a real local address with a 0.0.0.0:0 remote placeholder.
    f = _f(FindingKind.HIDDEN_PROCESS, "pid 5",
           {"socket_visible": [{"state": "CLOSE",
                                "local": "10.0.0.7:53000",
                                "remote": "0.0.0.0:0"}]})
    vals = {(i.type, i.value) for i in extract([f])}
    assert vals == {("network_endpoint", "10.0.0.7:53000")}


def test_close_state_with_both_real_yields_both():
    f = _f(FindingKind.HIDDEN_PROCESS, "pid 6",
           {"socket_visible": [{"state": "CLOSE",
                                "local": "10.0.0.7:53000",
                                "remote": "198.51.100.2:9999"}]})
    vals = {(i.type, i.value) for i in extract([f])}
    assert vals == {("network_endpoint", "10.0.0.7:53000"),
                    ("network_endpoint", "198.51.100.2:9999")}


def test_iocs_deduped_and_sorted():
    f1 = _f(FindingKind.HIDDEN_MODULE, "module m", {})
    f2 = _f(FindingKind.HIDDEN_MODULE, "module m", {})
    iocs = extract([f1, f2])
    assert [(i.type, i.value) for i in iocs] == [("kernel_module", "m")]

def test_dedup_keeps_first_occurrence_confidence():
    # First finding has LOW confidence, second has HIGH
    # Dedup should keep first occurrence's confidence
    f1 = _f(FindingKind.HIDDEN_MODULE, "module x",
            {"unexpected_hook": [{"function": "hook1"}]},
            conf=Confidence.LOW)
    f2 = _f(FindingKind.HIDDEN_MODULE, "module x",
            {"unexpected_hook": [{"function": "hook1"}]},
            conf=Confidence.HIGH)
    iocs = extract([f1, f2])
    # Should have 2 IOCs (kernel_module and hooked_function), both with LOW confidence
    kernel_ioc = next((i for i in iocs if i.type == "kernel_module" and i.value == "x"), None)
    hook_ioc = next((i for i in iocs if i.type == "hooked_function" and i.value == "hook1"), None)
    assert kernel_ioc is not None and kernel_ioc.confidence == "LOW"
    assert hook_ioc is not None and hook_ioc.confidence == "LOW"
