"""The signed baseline store (spec §6).

A baseline is an ordinary snapshot (P6) plus a detached ed25519 signature over
the exact bytes of its .json. Verification precedes trust (P7): load_baseline
checks the signature before json.loads, so a tampered baseline is refused, not
analysed. On-host verification only defeats an attacker without the signing key
(L18); keep the private key off-host.
"""
from __future__ import annotations

import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from kdetect.models import Snapshot


class BaselineTampered(Exception):
    """A baseline's signature did not verify against the given public key."""


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an ed25519 public key")
    return key


def _sig_path(json_path: Path) -> Path:
    return Path(str(json_path) + ".sig")


def write_baseline(snapshot: Snapshot, out_path: Path, private_key) -> None:
    """Write <out_path> (the snapshot) and <out_path>.sig (detached signature).

    The signed bytes are exactly the bytes written, so verification reads the
    same file back and needs no re-serialisation."""
    out_path = Path(out_path)
    data = snapshot.to_json(pretty=False).encode("utf-8")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    _sig_path(out_path).write_bytes(private_key.sign(data))


def load_baseline(json_path: Path, public_key) -> Snapshot:
    """Verify the detached signature, THEN parse (P7)."""
    json_path = Path(json_path)
    data = json_path.read_bytes()
    try:
        signature = _sig_path(json_path).read_bytes()
    except OSError as exc:
        raise BaselineTampered(f"missing signature for {json_path}") from exc
    try:
        public_key.verify(signature, data)
    except InvalidSignature as exc:
        raise BaselineTampered(f"signature mismatch for {json_path}") from exc
    return Snapshot.from_dict(json.loads(data))
