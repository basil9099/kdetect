import json
import subprocess
import sys
from pathlib import Path

FIXTURE = Path(__file__).parent.parent / "fixtures" / "snapshots" / "clean-vm.json"


def run(args):
    return subprocess.run([sys.executable, "-m", "kdetect.cli"] + args,
                          capture_output=True, text=True)


def test_analyze_prints_summary():
    r = run(["analyze", str(FIXTURE)])
    assert r.returncode == 0
    for field in ("snapshot:", "schema:", "host:", "captured:", "euid:",
                  "procfs.processes", "trust=LOW"):
        assert field in r.stdout


def test_analyze_reports_entity_count():
    r = run(["analyze", str(FIXTURE)])
    n = len(json.loads(FIXTURE.read_text())["observations"][0]["entity_ids"])
    assert str(n) in r.stdout


def test_analyze_rejects_major_version_mismatch(tmp_path):
    d = json.loads(FIXTURE.read_text())
    d["schema_version"] = "2.0"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(d))
    r = run(["analyze", str(bad)])
    assert r.returncode == 1
    assert "version" in (r.stderr + r.stdout).lower()


def test_analyze_missing_file_exits_1():
    r = run(["analyze", "/nonexistent/nope.json"])
    assert r.returncode == 1


def test_analyze_malformed_json_exits_1(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert run(["analyze", str(bad)]).returncode == 1


def test_fixture_round_trips_byte_identically():
    from kdetect.models import Snapshot
    raw = json.loads(FIXTURE.read_text())
    s = Snapshot.from_dict(raw)
    assert Snapshot.from_dict(json.loads(s.to_json())).to_json() == s.to_json()


def test_fixture_contains_no_session_tokens():
    """The fixture is the only capture that leaves the machine.

    /proc/[pid]/cmdline exposes whatever a process was invoked with, which can
    include credentials. See docs/limitations.md L13.
    """
    text = FIXTURE.read_text()
    assert "b9ecbcb9" not in text
