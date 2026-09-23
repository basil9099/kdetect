import json

import pytest

from kdetect.analysis.models import (
    CHANNEL_NOTE_REASONS, ChannelNote, Finding, FindingKind, Confidence,
)
from kdetect.reporting.iocs import extract
from kdetect.reporting.iocs import extract as _extract
from kdetect.reporting import report
from kdetect.models import (
    Snapshot, HostFacts, CaptureMeta, SCHEMA_VERSION,
)


def _snap(hostname="kdetect-lab"):
    host = HostFacts(hostname, "6.1.0-52", "x86_64", "b0", 1, 100)
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
    assert "[HIGH] hidden_module — `module diamorphine`" in md
    # Finding.summary (the one-sentence "why it fired") must render too.
    assert "module diamorphine is concealed" in md


def test_markdown_hidden_process_shows_comm_and_exe_unavailable():
    f = Finding(FindingKind.HIDDEN_PROCESS, "pid 1234", Confidence.HIGH,
                ["syscall_kill"], [], {"syscall_kill": [{"comm": "evil"}]}, "")
    md = report.render_markdown(_snap(), [f], extract([f]))
    # Weak "comm" in md / "evil" in md could match unrelated lines; pin the
    # comm value to the evidence line that actually names it.
    assert "\ncomm: evil\n" in md
    assert "\nexe: unavailable (hidden from /proc)\n" in md


def test_markdown_hidden_process_comm_falls_back_to_unknown():
    # A swept task whose /proc/<tid>/status was unreadable has comm=None
    # (spec: real hidden-process findings can legitimately lack a comm).
    f = Finding(FindingKind.HIDDEN_PROCESS, "pid 9999", Confidence.HIGH,
                ["syscall_kill"], [], {"syscall_kill": [{"comm": None}]}, "")
    md = report.render_markdown(_snap(), [f], extract([f]))
    assert "\ncomm: unknown\n" in md


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


def test_findings_tiebreak_by_subject_when_confidence_matches():
    # Same confidence for both -- only the subject tiebreak can order these.
    # Input order is the reverse of the expected (subject-sorted) output
    # order, so this fails on an implementation that does no tiebreak at all.
    b = Finding(FindingKind.HIDDEN_PROCESS, "subject-b", Confidence.MEDIUM,
                [], [], {}, "")
    a = Finding(FindingKind.HIDDEN_PROCESS, "subject-a", Confidence.MEDIUM,
                [], [], {}, "")
    md = report.render_markdown(_snap(), [b, a], [])
    assert md.index("subject-a") < md.index("subject-b")


def test_markdown_baseline_name_appears_in_header():
    f = _hidden_module()
    md = report.render_markdown(_snap(), [f], extract([f]),
                                baseline_name="prod-baseline")
    assert "**Baseline:** `prod-baseline`" in md


def test_markdown_baseline_none_renders_none_in_header():
    md = report.render_markdown(_snap(), [], [], baseline_name=None)
    assert "**Baseline:** none" in md


def test_markdown_module_name_cannot_inject_a_link():
    # A rootkit chooses its own module name. Outside code formatting this one
    # would render as a clickable link in a shared report.
    name = "[click](https://evil.example)"
    f = Finding(FindingKind.HIDDEN_MODULE, "module " + name, Confidence.HIGH,
                ["ftrace_orphan"], ["procfs.modules listing"], {},
                "module " + name + " is concealed")
    md = report.render_markdown(_snap(), [f], extract([f]))
    assert "### [HIGH] hidden_module — `module [click](https://evil.example)`\n" in md
    assert "```text\nmodule [click](https://evil.example) is concealed\n" in md
    assert "- kernel_module: `[click](https://evil.example)` (HIGH)\n" in md
    # Exactly the three formatted places above, and no raw copy anywhere else.
    assert md.count(name) == 3


def test_markdown_comm_with_backtick_and_escape_stays_inert():
    comm = "a`b\x1b[2K"
    f = Finding(FindingKind.HIDDEN_PROCESS, "pid 4242", Confidence.HIGH,
                ["syscall_kill"], [], {"syscall_kill": [{"comm": comm}]}, "")
    md = report.render_markdown(_snap(), [f], extract([f]))
    assert "\x1b" not in md
    assert "\ncomm: a`b\\x1b[2K\n" in md
    assert "- process_name: ``a`b\\x1b[2K`` (HIGH)\n" in md


def test_markdown_hostname_is_code_formatted_and_escaped():
    md = report.render_markdown(_snap(hostname="lab\x1b[31m"), [], [])
    assert "\x1b" not in md
    assert "# kdetect report — `lab\\x1b[31m`\n" in md
    assert "**Host:** `lab\\x1b[31m` · `6.1.0-52` · `x86_64`\n" in md


def test_markdown_evidence_backticks_cannot_close_the_block():
    # repr() already shows the newline as \n; the triple backticks must not end
    # the fenced block, or whatever followed them would render as Markdown.
    f = Finding(FindingKind.HIDDEN_MODULE, "module m", Confidence.HIGH,
                ["unexpected_hook"], ["procfs.modules listing"],
                {"unexpected_hook": [{"callback": "```\n# pwned"}]}, "")
    md = report.render_markdown(_snap(), [f], extract([f]))
    assert "\n````text\n" in md
    assert "\n# pwned" not in md


def test_json_baseline_object_shape_when_verified():
    # baseline_name is only ever passed by a caller that has already
    # verified the baseline's signature (see report.py's module docstring),
    # which is why this object unconditionally reports verified: true.
    f = _hidden_module()
    payload = json.loads(report.render_json(_snap(), [f], extract([f]),
                                             baseline_name="prod-baseline"))
    assert payload["baseline"] == {"name": "prod-baseline", "verified": True}


def test_json_baseline_is_none_when_not_provided():
    f = _hidden_module()
    payload = json.loads(report.render_json(_snap(), [f], extract([f])))
    assert payload["baseline"] is None


def test_json_report_shape():
    f = _hidden_module()
    payload = json.loads(report.render_json(_snap(), [f], extract([f])))
    assert payload["host"]["hostname"] == "kdetect-lab"
    assert payload["summary"]["high"] == 1
    assert payload["findings"][0]["kind"] == "hidden_module"
    assert any(i["type"] == "kernel_module" for i in payload["iocs"])


def test_json_keeps_untrusted_values_verbatim():
    # Escaping is for people. A pipeline reading the JSON report gets the exact
    # captured name back once the JSON is decoded.
    name = "evil\x1b[2K`name`"
    f = Finding(FindingKind.HIDDEN_MODULE, "module " + name, Confidence.HIGH,
                ["ftrace_orphan"], ["procfs.modules listing"], {}, "")
    payload = json.loads(report.render_json(_snap(), [f], extract([f])))
    assert payload["findings"][0]["subject"] == "module " + name
    assert payload["iocs"][0]["value"] == name


def test_json_report_is_deterministic_and_sorted_keys():
    f = _hidden_module()
    a = report.render_json(_snap(), [f], extract([f]))
    b = report.render_json(_snap(), [f], extract([f]))
    assert a == b
    # sort_keys=True: top-level keys must appear in sorted order in the text.
    payload = json.loads(a)
    assert list(json.loads(a).keys()) == sorted(payload.keys())


_NOTE = ChannelNote("taint", "saturated",
                    {"explained_by": {"12": ["vboxdrv"], "13": ["vboxdrv"]}})


def test_markdown_omits_channel_coverage_when_there_are_no_notes():
    md = report.render_markdown(_snap(), [], [])
    assert "Channel coverage" not in md


def test_markdown_renders_channel_coverage_and_escapes_module_names():
    md = report.render_markdown(_snap(), [], [], notes=[_NOTE])
    assert "## Channel coverage" in md
    assert "taint" in md
    # A module name is attacker-chosen, so it must be inline code, not bare text.
    assert "`vboxdrv`" in md


def test_markdown_channel_coverage_neutralises_a_hostile_module_name():
    # "vboxdrv" above is benign: `` f"`{o}`" `` would pass that assertion just
    # as well as md_code(o) would. Use a name carrying both an ESC byte and a
    # backtick, so this only passes if printable() and the fence-widening in
    # md_code() actually ran.
    owner = "evil`mod\x1b[31m"
    note = ChannelNote("taint", "saturated", {"explained_by": {"12": [owner]}})
    md = report.render_markdown(_snap(), [], [], notes=[note])
    assert "\x1b" not in md
    # A bare single-backtick span would end at the owner's own backtick,
    # spilling "mod\x1b[31m``" as loose Markdown; the fence must widen to two
    # backticks to stay closed around the whole escaped value.
    assert "  - bit `12`: ``evil`mod\\x1b[31m``\n" in md


#: Minimal detail for each reason, so every branch has the keys it reads.
_DETAIL_FOR_REASON = {
    "saturated": {"explained_by": {"12": ["vboxdrv"]}},
    "uncorroborated": {"listed": 3, "channels_consulted": ["a", "b"]},
}


@pytest.mark.parametrize("reason", CHANNEL_NOTE_REASONS)
def test_every_declared_reason_has_a_branch_in_both_renderers(reason):
    """CHANNEL_NOTE_REASONS is the declared vocabulary; this makes it binding.

    models.py listed one reason while a second shipped, and that stale comment
    is the proximate cause of both human renderers falling silent on it. Adding
    a reason to the tuple without teaching both renderers now fails here: the
    generic fallback is a safety net for reasons nobody has written yet, not a
    substitute for a branch for one that is declared.
    """
    from kdetect.cli import _note_lines as cli_note_lines

    assert reason in _DETAIL_FOR_REASON, (
        f"{reason!r} was added to CHANNEL_NOTE_REASONS without a sample detail "
        f"dict here -- add one, then check both renderers below still pass."
    )
    note = ChannelNote("some_channel", reason, _DETAIL_FOR_REASON[reason])

    for rendered in ("\n".join(report._note_lines(note)),
                     "\n".join(cli_note_lines(note))):
        assert rendered.strip()
        # The generic fallback's wording. Reaching it means no branch matched.
        assert "did not contribute (reason:" not in rendered


def test_markdown_renders_an_unknown_note_reason_rather_than_nothing():
    """Spec section 4.4 earmarks ChannelNote for phase 4d's "this channel was
    unreadable", so an unrecognised reason is the next thing to arrive, not a
    hypothetical. It must degrade to a visible generic line -- matching one
    literal reason and emitting nothing else is what silenced "uncorroborated"
    on both human paths.
    """
    note = ChannelNote("kallsyms", "unreadable", {"errno": "EACCES"})
    md = report.render_markdown(_snap(), [], [], notes=[note])
    assert "## Channel coverage" in md
    assert "`kallsyms`" in md
    assert "`unreadable`" in md            # the raw reason, verbatim
    assert "`errno`" in md                 # the detail keys, so nothing is lost


def test_markdown_channel_coverage_heading_is_gated_on_content_not_on_notes(
        monkeypatch):
    """The empty-heading defect, pinned at its cause.

    `if notes:` emitted the heading whether or not any note rendered a line;
    `if lines:` cannot. _note_lines always produces something now, so the only
    way to exercise the gate is to make it produce nothing.
    """
    monkeypatch.setattr(report, "_note_lines", lambda note: [])
    md = report.render_markdown(_snap(), [], [], notes=[_NOTE])
    assert "Channel coverage" not in md


def test_cli_renders_an_unknown_note_reason_rather_than_nothing():
    """cli.py's _note_lines is a separate renderer (printable(), not md_code())
    and needs its own guard for the same fallback."""
    from kdetect.cli import _note_lines

    lines = _note_lines(ChannelNote("kallsyms", "unreadable", {"errno": "EACCES"}))
    blob = "\n".join(lines)
    assert lines
    assert "kallsyms" in blob and "unreadable" in blob and "errno" in blob


def test_cli_note_fallback_escapes_a_hostile_reason_and_detail_key():
    """The fallback prints previously-unrendered strings, so it is a new sink
    for attacker-chosen bytes and must escape like every other one."""
    from kdetect.cli import _note_lines

    note = ChannelNote("evil\x1b[31m", "boom\x1b[2K", {"k\x1b[0m": 1})
    blob = "\n".join(_note_lines(note))
    assert "\x1b" not in blob
    assert "\\x1b[31m" in blob and "\\x1b[2K" in blob and "\\x1b[0m" in blob


def test_json_carries_notes_as_a_named_key():
    payload = json.loads(report.render_json(_snap(), [], [], notes=[_NOTE]))
    assert payload["channel_notes"] == [_NOTE.to_dict()]


def test_json_notes_key_is_present_and_empty_when_there_are_none():
    payload = json.loads(report.render_json(_snap(), [], []))
    assert payload["channel_notes"] == []


def test_a_channel_note_never_becomes_an_ioc():
    """Criterion 5: notes are not findings and carry no indicators."""
    assert _extract([]) == []
    md = report.render_markdown(_snap(), [], [], notes=[_NOTE])
    ioc_section = md.split("## Indicators of Compromise", 1)[1]
    assert "vboxdrv" not in ioc_section.split("## Channel coverage")[0]
