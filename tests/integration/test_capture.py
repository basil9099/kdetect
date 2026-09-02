import json
import os
import subprocess
import sys

from kdetect.models import SCHEMA_VERSION, Snapshot
from tests.conftest import needs_procfs

pytestmark = needs_procfs


def run(args, cwd):
    return subprocess.run([sys.executable, "-m", "kdetect.cli"] + args,
                          capture_output=True, text=True, cwd=cwd)


def test_capture_writes_a_file_and_prints_its_path(tmp_path):
    r = run(["capture"], tmp_path)
    assert r.returncode == 0
    path = tmp_path / r.stdout.strip()
    assert path.exists()


def test_capture_filename_has_no_colons(tmp_path):
    r = run(["capture"], tmp_path)
    assert ":" not in r.stdout.strip().split("/")[-1]


def test_capture_to_stdout(tmp_path):
    r = run(["capture", "--out", "-"], tmp_path)
    # Assert against the constant, not a literal: a live capture always emits
    # the build's current schema version, so a version bump must not break this.
    assert Snapshot.from_dict(json.loads(r.stdout)).schema_version == SCHEMA_VERSION


def test_capture_contains_its_own_pid(tmp_path):
    # Acceptance criterion 9: the observer is in the observation.
    r = run(["capture", "--out", "-"], tmp_path)
    snap = Snapshot.from_dict(json.loads(r.stdout))
    comms = [e.comm for e in snap.observations[0].entities.values()]
    assert any("python" in c for c in comms)


def test_capture_emits_kernel_hooks_observation(tmp_path):
    r = run(["capture", "--out", "-"], tmp_path)
    snap = Snapshot.from_dict(json.loads(r.stdout))
    assert len(snap.observations) == 7
    assert snap.observations[5].collector == "kernel.hooks"


def test_capture_emits_sockets_observation(tmp_path):
    r = run(["capture", "--out", "-"], tmp_path)
    snap = Snapshot.from_dict(json.loads(r.stdout))
    assert len(snap.observations) == 7
    assert snap.observations[6].collector == "procfs.sockets"


def test_host_facts_are_populated(tmp_path):
    r = run(["capture", "--out", "-"], tmp_path)
    h = Snapshot.from_dict(json.loads(r.stdout)).host
    assert h.btime > 0
    assert h.clock_ticks_per_sec == 100
    assert len(h.boot_id) >= 8
    assert h.kernel_release


def test_non_root_warns_on_stderr(tmp_path):
    if os.geteuid() == 0:
        return
    r = run(["capture", "--out", "-"], tmp_path)
    assert "root" in r.stderr.lower() or "euid" in r.stderr.lower()
    assert r.returncode == 0
