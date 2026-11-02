# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from image_fixtures import BUILD_TOOLS
import apt_snapshot

spec = importlib.util.spec_from_file_location('freeze_apt_snapshot', BUILD_TOOLS / 'freeze-apt-snapshot.py')
freeze_apt_snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(freeze_apt_snapshot)


class AptSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.root = BUILD_TOOLS.parent.parent
        self.archive = self.root / 'build/apt-snapshot.tar.gz'
        self.lock = json.loads((self.root / 'build/inputs.lock.json').read_text())

    def test_locked_indexes_match_the_ubuntu_release_records(self):
        self.assertEqual(apt_snapshot.validate(self.archive, self.lock),
                         {'snapshot': '20261027T000000Z', 'indexes': 12})

    def test_release_identity_rejects_another_suite_or_a_newer_release(self):
        release = (b'Origin: Ubuntu\nSuite: noble-updates\nCodename: noble\n'
                   b'Date: Mon, 26 Oct 2026 18:32:36 UTC\n')
        apt_snapshot.release_identity(release, 'noble-updates', '20261027T000000Z')
        for changed in [release.replace(b'Suite: noble-updates', b'Suite: noble-security'),
                        release.replace(b'26 Oct 2026', b'28 Oct 2026'),
                        release + b'Origin: Ubuntu\n']:
            with self.subTest(release=changed), self.assertRaises(ValueError):
                apt_snapshot.release_identity(changed, 'noble-updates', '20261027T000000Z')

    def test_freezing_preserves_exact_index_archive_and_checks_each_signature(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with tarfile.open(self.archive, 'r:gz') as tar:
                tar.extractall(root / 'input', filter='data')
            output = root / 'snapshot.tar.gz'
            with patch.object(freeze_apt_snapshot.subprocess, 'run') as verify:
                result = freeze_apt_snapshot.freeze('20261027T000000Z', root / 'input', output, root / 'keyring')
            self.assertEqual(verify.call_count, 3)
            self.assertEqual(result['snapshot_metadata_sha256'], self.lock['snapshot_metadata_sha256'])
            self.assertEqual(result['snapshot_release_sha256'], self.lock['snapshot_release_sha256'])

    def test_rehashed_archive_cannot_replace_a_signed_index_or_add_a_duplicate(self):
        for change in ('index', 'duplicate'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / 'snapshot.tar.gz'
                with tarfile.open(self.archive, 'r:gz') as original, tarfile.open(output, 'w:gz') as altered:
                    for member in original:
                        data = original.extractfile(member).read() if member.isfile() else None
                        if change == 'index' and member.name.endswith('main/source/Sources.xz'):
                            data = bytes([data[0] ^ 1]) + data[1:]
                            change = 'index-changed'
                        altered.addfile(member, io.BytesIO(data) if data is not None else None)
                        if change == 'duplicate' and member.name == 'dists/noble/InRelease':
                            altered.addfile(copy.copy(member), io.BytesIO(data))
                lock = copy.deepcopy(self.lock)
                lock['snapshot_metadata_sha256'] = hashlib.sha256(output.read_bytes()).hexdigest()
                with self.assertRaisesRegex(ValueError, 'Duplicate APT|differs from the signed release'):
                    apt_snapshot.validate(output, lock)
