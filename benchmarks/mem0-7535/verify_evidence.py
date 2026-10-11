"""Verify closed byte membership, not semantic truth or execution authority."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


def verify(packet):
    packet = packet.resolve()
    manifest = json.loads((packet / "manifest.json").read_text())
    expected = set()
    for entry in manifest["artifacts"]:
        name = entry["path"]
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or name in expected or str(path) != name:
            raise ValueError("invalid or duplicate artifact path")
        expected.add(name)
        target = packet / name
        if target.is_symlink() or any(parent.is_symlink() for parent in target.parents if parent != packet):
            raise ValueError("symlink artifact")
        if not target.resolve().is_relative_to(packet) or not target.is_file():
            raise ValueError("missing or escaping artifact")
        raw = target.read_bytes()
        if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("artifact byte mismatch: " + name)
    actual = {path.relative_to(packet).as_posix() for path in packet.rglob("*") if path.is_file() or path.is_symlink()}
    if actual != expected | {"manifest.json"}:
        raise ValueError("unexpected or missing packet files")
    print("INTEGRITY_WITHIN_BOUND:", len(expected), "artifacts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("packet", nargs="?", type=Path, default=Path(__file__).resolve().parent)
    verify(parser.parse_args().packet)
