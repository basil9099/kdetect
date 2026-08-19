import json
import shutil
from pathlib import Path

from kdetect.collectors.procfs import ProcfsProcessCollector
from kdetect.collectors.sources import FixtureProcSource
from kdetect.models import ErrorKind, Status, TrustLevel

ROOT = Path(__file__).parent.parent / "fixtures" / "proc-trees" / "clean-vm-6.1.0-10"


def collect():
    return ProcfsProcessCollector().collect(FixtureProcSource(ROOT))


def test_identity_fields():
    obs = collect()
    assert obs.collector == "procfs.processes"
    assert obs.view == "processes"
    assert obs.trust_level is TrustLevel.LOW


def test_entity_ids_sorted_and_superset_of_entities():
    obs = collect()
    assert obs.entity_ids == sorted(obs.entity_ids)
    assert set(obs.entities).issubset(set(obs.entity_ids))


def test_kernel_thread_exe_is_none_and_not_partial():
    # ENOENT: genuinely has no executable.
    e = collect().entities[2]
    assert e.exe is None
    assert "exe" not in e.partial
    assert e.flags & 0x00200000


def test_denied_exe_is_none_and_marked_partial():
    # EACCES: exists, could not be read.
    e = collect().entities[812]
    assert e.exe is None
    assert "exe" in e.partial


def test_vanished_is_recorded_without_being_an_error():
    obs = collect()
    assert obs.stats["vanished"] >= 1
    assert any(err.kind is ErrorKind.VANISHED for err in obs.errors)


def test_denied_read_degrades_status_to_partial():
    # The fixture contains one EACCES (812/exe), so PARTIAL is correct.
    assert collect().status is Status.PARTIAL


def test_vanished_alone_leaves_status_ok(tmp_path):
    """A process exiting mid-scan is normal Linux, not a degradation."""
    tree = tmp_path / "tree"
    shutil.copytree(ROOT, tree)
    errors = json.loads((tree / "_errors.json").read_text())
    del errors["812/exe"]  # leave `vanished` as the only failure
    (tree / "_errors.json").write_text(json.dumps(errors))

    obs = ProcfsProcessCollector().collect(FixtureProcSource(tree))
    assert obs.stats["vanished"] >= 1
    assert obs.status is Status.OK


def test_stats_are_consistent():
    obs = collect()
    assert obs.stats["collected"] == len(obs.entities)
    assert obs.stats["scanned"] >= obs.stats["collected"]


def test_paren_comm_process_parsed_correctly():
    obs = collect()
    assert any("(" in e.comm for e in obs.entities.values())


def test_duration_is_recorded():
    assert collect().duration_ms >= 0


def test_procfs_collector_stamps_pass_label():
    obs = ProcfsProcessCollector(pass_label="A").collect(FixtureProcSource(ROOT))
    assert obs.pass_ == "A"
