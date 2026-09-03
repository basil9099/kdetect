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

def test_iocs_deduped_and_sorted():
    f1 = _f(FindingKind.HIDDEN_MODULE, "module m", {})
    f2 = _f(FindingKind.HIDDEN_MODULE, "module m", {})
    iocs = extract([f1, f2])
    assert [(i.type, i.value) for i in iocs] == [("kernel_module", "m")]
