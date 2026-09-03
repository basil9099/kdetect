import json
from pathlib import Path
import shutil
from kdetect.cli import main

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
