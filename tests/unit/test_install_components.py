# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("installer", Path(__file__).resolve().parents[2] / "build/tools/install-components.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class ArchiveExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "release.tar"
        self.destination = self.root / "bin"
        self.destination.mkdir()

    def archive_with(self, name="bin/runtime", kind=tarfile.REGTYPE):
        with tarfile.open(self.archive, "w") as bundle:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.linkname = "../../outside"
            if kind == tarfile.REGTYPE:
                member.size = 7
                bundle.addfile(member, io.BytesIO(b"payload"))
            else:
                bundle.addfile(member)

    def test_installs_only_allowlisted_files_with_fixed_mode(self):
        self.archive_with()
        installer.extract_binaries(self.archive, self.destination, ["bin/runtime"])
        self.assertEqual((self.destination / "runtime").read_bytes(), b"payload")
        self.assertEqual((self.destination / "runtime").stat().st_mode & 0o7777, 0o755)

    def test_rejects_allowlisted_symlinks_and_device_nodes(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE]:
            with self.subTest(kind=kind):
                self.archive_with(kind=kind)
                with self.assertRaises(ValueError):
                    installer.extract_binaries(self.archive, self.destination, ["bin/runtime"])
                self.assertEqual(list(self.destination.iterdir()), [])

    def test_path_traversal_cannot_satisfy_allowlist(self):
        self.archive_with("../../bin/runtime")
        with self.assertRaises(ValueError):
            installer.extract_binaries(self.archive, self.destination, ["bin/runtime"])
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_missing_binary_fails_closed(self):
        self.archive_with("bin/other")
        with self.assertRaises(ValueError):
            installer.extract_binaries(self.archive, self.destination, ["bin/runtime"])

    def test_tampered_component_cache_is_rejected_before_installation(self):
        cache = self.root / "cache"
        cache.mkdir()
        expected = "0" * 64
        (cache / expected).write_bytes(b"tampered executable")
        lock = self.root / "lock.json"
        lock.write_text(json.dumps({"components": {"runtime": {
            "artifacts": {"arm64": {"sha256": expected}}
        }}}))
        image = self.root / "image"
        with self.assertRaises(ValueError):
            installer.install(image, "arm64", lock, cache)
        self.assertEqual(list((image / "usr/bin").iterdir()), [])
