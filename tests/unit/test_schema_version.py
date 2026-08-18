import pytest

from kdetect.models import IncompatibleSnapshot, Snapshot
from tests.unit.test_models_roundtrip import make_snapshot


def test_same_version_loads():
    d = make_snapshot().to_dict()
    assert Snapshot.from_dict(d).schema_version == "1.0"


def test_newer_minor_loads_with_warning(capsys):
    d = make_snapshot().to_dict()
    d["schema_version"] = "1.7"
    d["some_future_field"] = 42
    Snapshot.from_dict(d)
    assert "unknown" in capsys.readouterr().err.lower()


def test_newer_major_refuses():
    d = make_snapshot().to_dict()
    d["schema_version"] = "2.0"
    with pytest.raises(IncompatibleSnapshot):
        Snapshot.from_dict(d)


def test_older_major_refuses():
    d = make_snapshot().to_dict()
    d["schema_version"] = "0.9"
    with pytest.raises(IncompatibleSnapshot):
        Snapshot.from_dict(d)


def test_missing_version_refuses():
    d = make_snapshot().to_dict()
    del d["schema_version"]
    with pytest.raises(IncompatibleSnapshot):
        Snapshot.from_dict(d)


def test_malformed_version_refuses():
    d = make_snapshot().to_dict()
    d["schema_version"] = "banana"
    with pytest.raises(IncompatibleSnapshot):
        Snapshot.from_dict(d)
