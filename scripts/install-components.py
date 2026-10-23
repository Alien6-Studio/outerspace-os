#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Install only allowlisted, hash-locked upstream binaries into the image."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile

ARCHES = {"x86-64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}


def verify(path, expected):
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if digest != expected:
        raise ValueError(f"SHA256 mismatch for {path.name}")


def fetch(cache, architecture, lockfile):
    cache.mkdir(parents=True, exist_ok=True)
    lock = json.loads(lockfile.read_text())
    for component in lock["components"].values():
        artifact = component["artifacts"][ARCHES[architecture]]
        path = cache / artifact["sha256"]
        if path.exists():
            verify(path, artifact["sha256"])
            continue
        temporary = path.with_suffix(".partial")
        try:
            subprocess.run(["curl", "--fail", "--location", "--retry", "3",
                            "--proto", "=https", "--tlsv1.2", "--max-time", "600",
                            "--speed-limit", "1024", "--speed-time", "60",
                            "--silent", "--show-error", "--output", str(temporary), artifact["url"]], check=True)
            verify(temporary, artifact["sha256"])
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def extract_binaries(archive, destination, allowed):
    """Never trust archive paths, symlinks, device nodes or arbitrary modes."""
    installed = set()
    with tarfile.open(archive) as bundle:
        for member in bundle:
            name = str(PurePosixPath(member.name))
            if name not in allowed:
                continue
            if not member.isfile() or member.name != name:
                raise ValueError(f"Unsafe archive member: {member.name}")
            target = destination / PurePosixPath(name).name
            with bundle.extractfile(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755)
            installed.add(name)
    if installed != set(allowed):
        raise ValueError(f"Missing binaries: {set(allowed) - installed}")


def install(root, architecture, lockfile, cache=None):
    arch = ARCHES[architecture]
    lock = json.loads(lockfile.read_text())
    destination = root / "usr/bin"
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="outerspace-download-") as directory:
        for name, component in lock["components"].items():
            artifact = component["artifacts"][arch]
            if cache is None:
                raise ValueError("A verified component cache is required; run the build wrapper")
            path = cache / artifact["sha256"]
            verify(path, artifact["sha256"])
            binaries = artifact.get("binaries", component.get("binaries"))
            if binaries:
                extract_binaries(path, destination, binaries)
            else:
                shutil.copyfile(path, destination / name)
                (destination / name).chmod(0o755)
            if "license" in artifact:
                licenses = root / "usr/share/licenses" / name
                licenses.mkdir(parents=True, exist_ok=True)
                extract_binaries(path, licenses, [artifact["license"]])
                (licenses / "LICENSE").chmod(0o644)
    metadata = root / "usr/share/outerspace"
    metadata.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(lockfile, metadata / "components.lock.json")


if __name__ == "__main__":
    if sys.argv[1] == "fetch":
        fetch(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]))
    else:
        install(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]))
