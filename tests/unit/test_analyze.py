import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

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


#: Token-bearing argument names seen in real captures. A value following one of
#: these is a credential unless it is a placeholder we put there.
_TOKEN_FLAGS = re.compile(
    r"--?(?:connection[-_]?token|access[-_]?token|auth[-_]?token|token)"
    r"(?:[=\s]+)(\S+)", re.IGNORECASE)

#: Values allowed to follow a token flag: our own scrub placeholders, and
#: `remotessh`, the fixed literal VS Code Remote-SSH uses over an already
#: authenticated transport. Anything else must be scrubbed before committing.
_ALLOWED_TOKEN_VALUES = {"redacted", "remotessh"}

#: A committed capture must not carry a high-entropy secret. Kept deliberately
#: narrow: VS Code build ids are 40 hex characters and appear in cmdline *paths*,
#: so entropy alone cannot be the rule -- only values in token position are.
_SECRET_SHAPED = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")


def _fixture_cmdlines(path):
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    return [" ".join(entity["cmdline"])
            for obs in snapshot.get("observations", [])
            for entity in obs.get("entities", {}).values()
            if isinstance(entity, dict) and entity.get("cmdline")]


@pytest.mark.parametrize("path", sorted(FIXTURE.parent.glob("*.json")),
                         ids=lambda p: p.name)
def test_no_committed_fixture_carries_a_live_token(path):
    """Committed captures are the only ones that leave the machine (L13).

    /proc/[pid]/cmdline is recorded verbatim, so a capture can carry whatever a
    process was handed as an argument. Every fixture is checked, not just one:
    the point is to fail if a *future* capture is committed with a live token.
    """
    offenders = []
    for cmdline in _fixture_cmdlines(path):
        for value in _TOKEN_FLAGS.findall(cmdline):
            stripped = value.strip("\"'")
            if stripped.lower().startswith(tuple(_ALLOWED_TOKEN_VALUES)):
                continue
            if _SECRET_SHAPED.match(stripped):
                offenders.append(value)

    assert not offenders, (
        f"{path.name} carries {len(offenders)} unscrubbed token value(s) in a "
        f"process cmdline: {offenders[:3]}. Scrub them before committing "
        f"(docs/limitations.md L13)."
    )


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


def test_analyze_with_tampered_baseline_exits_1(tmp_path, capsys, monkeypatch):
    # a baseline whose signature will not verify -> exit 1, no analysis
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from kdetect.baseline.store import write_baseline
    from kdetect.cli import main
    # build a minimal valid snapshot file to analyze (reuse an existing fixture)
    import shutil, pathlib
    fixture = pathlib.Path("tests/fixtures/snapshots/clean-phase2.json")
    snap = tmp_path / "snap.json"; shutil.copy(fixture, snap)
    # a baseline signed by key A, verified with key B -> BaselineTampered
    key_a = Ed25519PrivateKey.generate()
    from kdetect.models import Snapshot
    base = tmp_path / "base.json"
    write_baseline(Snapshot.from_dict(__import__("json").loads(snap.read_text())),
                   base, key_a)
    key_b_pub = tmp_path / "b.pub.pem"
    key_b_pub.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    rc = main(["analyze", str(snap), "--baseline", str(base),
               "--verify-key", str(key_b_pub)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "baseline" in captured.err.lower()
    assert "findings:" not in captured.out  # analysis never ran
