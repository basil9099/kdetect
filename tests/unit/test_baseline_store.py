import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kdetect.baseline.store import (
    BaselineTampered, write_baseline, load_baseline,
)
from kdetect.models import (
    Snapshot, HostFacts, CaptureMeta, SCHEMA_VERSION,
)

def _snap():
    host = HostFacts("t", "6.1", "x86_64", "b", 1, 100)
    return Snapshot(SCHEMA_VERSION, "id", "t", host, CaptureMeta("0.1.0", 0), [])

def test_write_then_load_roundtrips(tmp_path):
    key = Ed25519PrivateKey.generate()
    out = tmp_path / "clean.json"
    write_baseline(_snap(), out, key)
    assert out.exists() and (tmp_path / "clean.json.sig").exists()
    loaded = load_baseline(out, key.public_key())
    assert loaded.snapshot_id == "id"

def test_tampered_json_is_refused(tmp_path):
    key = Ed25519PrivateKey.generate()
    out = tmp_path / "clean.json"
    write_baseline(_snap(), out, key)
    out.write_text(out.read_text().replace('"id"', '"forged"'))   # edit after signing
    with pytest.raises(BaselineTampered):
        load_baseline(out, key.public_key())

def test_wrong_key_is_refused(tmp_path):
    write_baseline(_snap(), tmp_path / "clean.json", Ed25519PrivateKey.generate())
    other = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(BaselineTampered):
        load_baseline(tmp_path / "clean.json", other)
