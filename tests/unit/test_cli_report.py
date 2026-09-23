import copy
import json
from pathlib import Path
import shutil

import pytest

from kdetect.analysis.signals import channel_notes as _channel_notes
from kdetect.cli import main
from kdetect.models import Snapshot as _Snapshot

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "snapshots"


def test_report_markdown_on_infected(capsys):
    rc = main(["report", str(FIX / "infected-hooktest.json")])
    out = capsys.readouterr().out
    assert rc == 3                          # findings present
    assert "kdetect_hooktest" in out and "# kdetect report" in out


def test_report_json_parses(capsys):
    rc = main(["report", str(FIX / "infected-hooktest.json"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["high"] >= 1
    assert rc == 3


def test_report_clean_is_exit_zero(capsys):
    rc = main(["report", str(FIX / "clean-phase2.json")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No findings" in out


def test_report_writes_out_file(tmp_path):
    out = tmp_path / "r.md"
    rc = main(["report", str(FIX / "clean-phase2.json"), "--out", str(out)])
    assert rc == 0
    assert out.exists()
    assert "kdetect report" in out.read_text(encoding="utf-8")


@pytest.mark.parametrize("fmt", ["md", "json"])
def test_out_file_is_identical_to_stdout(tmp_path, capsys, fmt):
    """--out and stdout must be the same document, byte for byte.

    They came apart once: render_markdown ends in a newline and render_json
    does not, so whichever sink appended its own decided the trailing bytes.
    """
    snapshot = str(FIX / "clean-phase2.json")
    dst = tmp_path / f"r.{fmt}"

    assert main(["report", snapshot, "--format", fmt, "--out", str(dst)]) == 0
    capsys.readouterr()                     # discard the echoed --out path
    assert main(["report", snapshot, "--format", fmt]) == 0
    stdout = capsys.readouterr().out

    assert dst.read_text(encoding="utf-8") == stdout
    assert stdout.endswith("\n")
    assert not stdout.endswith("\n\n")      # exactly one, not doubled


def test_report_unwritable_out_dir_prints_error_not_traceback(tmp_path, capsys):
    out = tmp_path / "does-not-exist" / "r.md"
    rc = main(["report", str(FIX / "clean-phase2.json"), "--out", str(out)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "error:" in captured.err
    assert not out.exists()


def test_redact_scrubs_cmdline(tmp_path):
    src = tmp_path / "in.json"
    shutil.copy(FIX / "clean-phase2.json", src)
    dst = tmp_path / "out.json"
    rc = main(["redact", str(src), str(dst)])
    assert rc == 0
    data = json.loads(dst.read_text())
    cmds = [e.get("cmdline") for o in data["observations"]
            for e in o.get("entities", {}).values() if "cmdline" in e]
    assert cmds and all(c == ["[redacted]"] for c in cmds)
    # non-vacuous: clean-phase2 fixture carries many cmdline entities, so a
    # redactor that never touched anything (or an empty entities dict) must
    # not slip past the above assertions.
    assert len(cmds) > 1


def test_redact_unwritable_out_dir_prints_error_not_traceback(tmp_path, capsys):
    src = tmp_path / "in.json"
    shutil.copy(FIX / "clean-phase2.json", src)
    dst = tmp_path / "does-not-exist" / "out.json"
    rc = main(["redact", str(src), str(dst)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "error:" in captured.err
    assert not dst.exists()


def _saturated_snapshot_raw() -> dict:
    """infected-hooktest.json, mutated so the only module evidence left is a
    saturated taint channel: no findings, but the channel had something to
    say. Shared by every "saturated but no findings" test below so they all
    exercise the exact same fixture state.
    """
    raw = copy.deepcopy(json.loads(
        (FIX / "infected-hooktest.json").read_text(encoding="utf-8")))

    # Saturate taint AND neutralise the other module channels, so the only
    # module evidence left is the saturated one -> no findings at all.
    mods = next(o for o in raw["observations"] if o["collector"] == "procfs.modules")
    mods["entities"][mods["entity_ids"][0]]["taint"] = "OE"
    ev = next(o for o in raw["observations"]
              if o["collector"] == "kernel.module_evidence")
    ev["stats"]["load_module_regions"] = len(mods["entity_ids"])
    ev["extra"]["ftrace_modules"] = []
    raw["observations"] = [o for o in raw["observations"]
                           if o["collector"] != "kernel.hooks"]
    return raw


def test_saturated_channel_does_not_change_the_exit_code(tmp_path, capsys):
    """A channel note is not a finding (spec section 4.4, criterion 5)."""
    raw = _saturated_snapshot_raw()

    # Not "saturated.json": the filename must not be able to contribute to
    # either assertion below (cmd_analyze prints the snapshot path verbatim).
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(raw), encoding="utf-8")

    rc = main(["analyze", str(snap)])
    out = capsys.readouterr().out
    assert rc == 0, out
    # "could not corroborate" appears nowhere else in cmd_analyze's output
    # (unlike "taint", which is also a stats key, or "saturated", which is
    # also in the snapshot's own path) -- only the note-printing block emits
    # it.
    assert "could not corroborate" in out

    # Pin the composed "bit N: owner" detail line itself, derived from the
    # same pure channel_notes() the CLI calls -- not a bare substring of the
    # owner's name, which can be short enough to collide with unrelated
    # output (e.g. "ac" also matches inside "ftrace_available").
    expected_notes = _channel_notes(_Snapshot.from_dict(raw))
    assert len(expected_notes) == 1
    rendered_lines = {ln.strip() for ln in out.splitlines()}
    for bit, owners in expected_notes[0].detail["explained_by"].items():
        assert f"bit {bit}: {', '.join(owners)}" in rendered_lines


def test_analyze_note_output_escapes_hostile_module_name(tmp_path, capsys):
    """A module name is attacker-chosen (P1); an ESC byte in it must not
    reach the terminal via the note-printing path (cli.py's printable()
    calls at the bit/owner lines)."""
    raw = _saturated_snapshot_raw()
    hostile = "evil`mod\x1b[31m"
    mods = next(o for o in raw["observations"] if o["collector"] == "procfs.modules")
    old_id = mods["entity_ids"][0]
    entity = mods["entities"].pop(old_id)
    entity["name"] = hostile
    mods["entities"][hostile] = entity
    mods["entity_ids"][0] = hostile

    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(raw), encoding="utf-8")

    rc = main(["analyze", str(snap)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "\x1b" not in out
    assert "\\x1b[31m" in out


def test_report_shows_channel_coverage_for_saturated_taint(tmp_path, capsys):
    """A report must show the same coverage the terminal does (brief step 4).

    Exercises only the markdown arm of cmd_report's format branch (cli.py's
    render_markdown(..., notes=notes) call). The json arm is a separate call
    site with its own notes=notes argument -- see
    test_report_json_carries_channel_notes_for_saturated_taint below, which
    that arm being correct says nothing about.
    """
    raw = _saturated_snapshot_raw()
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(raw), encoding="utf-8")

    rc = main(["report", str(snap)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "## Channel coverage" in out


def test_report_json_carries_channel_notes_for_saturated_taint(tmp_path, capsys):
    """cmd_report's --format json branch (render_json(..., notes=notes)) is a
    separate call site from the markdown arm above and needs its own guard."""
    raw = _saturated_snapshot_raw()
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(raw), encoding="utf-8")

    rc = main(["report", str(snap), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0, payload

    expected_notes = _channel_notes(_Snapshot.from_dict(raw))
    assert payload["channel_notes"]                    # non-empty
    assert payload["channel_notes"] == [n.to_dict() for n in expected_notes]
