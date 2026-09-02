from kdetect.analysis.models import Signal, Suspect, FindingKind, Confidence
from kdetect.analysis.scoring import score

def _mod(channel, name, **ev):
    return Signal(channel, Suspect("module", name), "procfs.modules listing", ev or {})

def test_empty_signals_no_findings():
    assert score([]) == []

def test_one_hidden_module_folds_anonymous_to_high():
    sigs = [
        _mod("unexpected_hook", "kdetect_hooktest", function="__x64_sys_newuname"),
        _mod("taint", None, bits=[12, 13]),
        _mod("vmalloc_region", None, unaccounted=1),
    ]
    findings = score(sigs)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.HIDDEN_MODULE
    assert f.subject == "module kdetect_hooktest"
    assert f.confidence is Confidence.HIGH          # 3 distinct channels
    assert set(f.channels_agree) == {"unexpected_hook", "taint", "vmalloc_region"}

def test_two_hidden_modules_do_not_absorb_anonymous():
    sigs = [
        _mod("ftrace_orphan", "modA"),
        _mod("unexpected_hook", "modB", function="x"),
        _mod("taint", None, bits=[12]),
    ]
    findings = score(sigs)
    kinds = {f.subject: f for f in findings}
    # each named module scores on its own channel only (LOW), and the anonymous
    # taint becomes a separate SUSPECTED_HIDDEN_MODULE rather than being guessed
    assert kinds["module modA"].confidence is Confidence.LOW
    assert kinds["module modB"].confidence is Confidence.LOW
    susp = [f for f in findings if f.kind is FindingKind.SUSPECTED_HIDDEN_MODULE]
    assert len(susp) == 1 and susp[0].subject == "unattributed hidden module"

def test_baseline_only_module_is_low_drift_not_hidden():
    findings = score([_mod("baseline_drift", "cfg80211", direction="added")])
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.BASELINE_DRIFT
    assert findings[0].confidence is Confidence.LOW

def test_process_two_channels_is_medium():
    p = Suspect("process", "1234")
    sigs = [Signal("syscall_kill", p, "procfs readdir (all passes)", {"tgid": 1234}),
            Signal("direct_status", p, "procfs readdir (all passes)", {"tgid": 1234})]
    findings = score(sigs)
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.HIDDEN_PROCESS
    assert findings[0].confidence is Confidence.MEDIUM
    assert findings[0].subject == "pid 1234"
