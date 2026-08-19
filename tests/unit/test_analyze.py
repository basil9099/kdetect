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


def _write_hidden_snapshot(tmp_path):
    import json
    snap = {
      "schema_version": "1.1", "snapshot_id": "x", "captured_at": "t",
      "host": {"hostname": "h", "kernel_release": "6.1", "arch": "x86_64",
               "boot_id": "b", "btime": 1, "clock_ticks_per_sec": 100},
      "capture": {"tool_version": "0.2.0", "euid": 0},
      "observations": [
        {"collector": "procfs.processes", "collector_version": "1",
         "view": "processes", "trust_level": "LOW", "status": "OK",
         "duration_ms": 1, "entity_ids": [1], "entities": {}, "stats": {},
         "errors": [], "pass": "A"},
        {"collector": "procfs.processes", "collector_version": "1",
         "view": "processes", "trust_level": "LOW", "status": "OK",
         "duration_ms": 1, "entity_ids": [1], "entities": {}, "stats": {},
         "errors": [], "pass": "B"},
        {"collector": "syscall_sweep.processes", "collector_version": "1",
         "view": "processes", "trust_level": "MEDIUM", "status": "OK",
         "duration_ms": 1, "entity_ids": [1, 31337],
         "entities": {"1": {"tgid": 1, "status_readable": True},
                      "31337": {"tgid": 31337, "status_readable": True}},
         "stats": {}, "errors": []}
      ]
    }
    p = tmp_path / "hidden.json"
    p.write_text(json.dumps(snap))
    return p


def test_analyze_reports_finding_and_exits_3(tmp_path):
    r = run(["analyze", str(_write_hidden_snapshot(tmp_path))])
    assert r.returncode == 3
    assert "hidden_process" in r.stdout and "31337" in r.stdout


def test_analyze_json_mode(tmp_path):
    r = run(["analyze", "--json", str(_write_hidden_snapshot(tmp_path))])
    assert r.returncode == 3
    import json as _j
    data = _j.loads(r.stdout)
    assert data[0]["kind"] == "hidden_process"


def test_analyze_clean_fixture_still_exits_0():
    r = run(["analyze", str(FIXTURE)])   # phase 1 clean-vm.json, one collector
    assert r.returncode == 0             # no sweep -> no findings
