import json

from kdetect.analysis.models import Finding, FindingKind, Confidence
from kdetect.reporting.iocs import extract
from kdetect.reporting import report
from kdetect.models import (
    Snapshot, HostFacts, CaptureMeta, SCHEMA_VERSION,
)


def _snap():
    host = HostFacts("kdetect-lab", "6.1.0-52", "x86_64", "b0", 1, 100)
    return Snapshot(SCHEMA_VERSION, "id", "2026-09-03T00:00:00.000Z", host,
                    CaptureMeta("0.1.0", 0), [])


def _hidden_module():
    return Finding(FindingKind.HIDDEN_MODULE, "module diamorphine",
                   Confidence.HIGH, ["ftrace_orphan"], ["procfs.modules listing"],
                   {"unexpected_hook": [{"function": "__x64_sys_kill"}]},
                   "module diamorphine is concealed")


def test_markdown_has_sections_and_verdict():
    f = _hidden_module()
    md = report.render_markdown(_snap(), [f], extract([f]))
    assert "# kdetect report" in md
    assert "diamorphine" in md
    assert "Indicators of Compromise" in md
    assert "__x64_sys_kill" in md
    # Weak "HIGH" in md could match anywhere; pin it to the finding's own
    # heading line, which carries the confidence tag by construction.
    assert "[HIGH] hidden_module — module diamorphine" in md


def test_markdown_hidden_process_shows_comm_and_exe_unavailable():
    f = Finding(FindingKind.HIDDEN_PROCESS, "pid 1234", Confidence.HIGH,
                ["syscall_kill"], [], {"syscall_kill": [{"comm": "evil"}]}, "")
    md = report.render_markdown(_snap(), [f], extract([f]))
    # Weak "comm" in md / "evil" in md could match unrelated lines; pin the
    # comm value to the evidence line that actually names it.
    assert "  - comm: evil" in md
    assert "  - exe: unavailable (hidden from /proc)" in md


def test_markdown_hidden_process_comm_falls_back_to_unknown():
    # A swept task whose /proc/<tid>/status was unreadable has comm=None
    # (spec: real hidden-process findings can legitimately lack a comm).
    f = Finding(FindingKind.HIDDEN_PROCESS, "pid 9999", Confidence.HIGH,
                ["syscall_kill"], [], {"syscall_kill": [{"comm": None}]}, "")
    md = report.render_markdown(_snap(), [f], extract([f]))
    assert "  - comm: unknown" in md


def test_zero_findings_report_is_valid():
    md = report.render_markdown(_snap(), [], [])
    assert "No findings" in md
    # A zero-findings report must not claim a finding exists.
    assert "## Findings\nNone." in md
    assert "## Indicators of Compromise\nNone." in md


def test_findings_render_most_severe_first():
    low = Finding(FindingKind.HIDDEN_PROCESS, "pid 2", Confidence.LOW,
                  [], [], {}, "")
    high = Finding(FindingKind.HIDDEN_PROCESS, "pid 1", Confidence.HIGH,
                   [], [], {}, "")
    md = report.render_markdown(_snap(), [low, high], [])
    assert md.index("[HIGH]") < md.index("[LOW]")


def test_json_report_shape():
    f = _hidden_module()
    payload = json.loads(report.render_json(_snap(), [f], extract([f])))
    assert payload["host"]["hostname"] == "kdetect-lab"
    assert payload["summary"]["high"] == 1
    assert payload["findings"][0]["kind"] == "hidden_module"
    assert any(i["type"] == "kernel_module" for i in payload["iocs"])


def test_json_report_is_deterministic_and_sorted_keys():
    f = _hidden_module()
    a = report.render_json(_snap(), [f], extract([f]))
    b = report.render_json(_snap(), [f], extract([f]))
    assert a == b
    # sort_keys=True: top-level keys must appear in sorted order in the text.
    payload = json.loads(a)
    assert list(json.loads(a).keys()) == sorted(payload.keys())
