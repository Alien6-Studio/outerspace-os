# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch
from image_fixtures import identity, inventory, sbom

spec = importlib.util.spec_from_file_location('install_syft', sbom.ROOT / 'build/tools/install-syft.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class ScannerIntakeTests(unittest.TestCase):
    def install_payload(self, directory, payload, digest):
        lock = directory / 'scanner.lock.json'
        sbom.write_json(lock, {'version': 'test', 'artifacts': {'arm64': {
            'url': 'https://example.invalid/scanner.tar.gz', 'sha256': digest}}})
        def download(command, **kwargs):
            Path(command[-2]).write_bytes(payload)
        with patch.object(installer.platform, 'machine', return_value='aarch64'), \
                patch.object(installer.subprocess, 'run', side_effect=download):
            installer.install(lock, directory / 'syft')

    def test_unapproved_archive_is_rejected_before_installing_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                self.install_payload(directory, b'unapproved download', '0' * 64)
            self.assertFalse((directory / 'syft').exists())

    def test_scanner_symlink_archive_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
                member = tarfile.TarInfo('syft')
                member.type = tarfile.SYMTYPE
                member.linkname = '/etc/passwd'
                tar.addfile(member)
            payload = buffer.getvalue()
            with self.assertRaisesRegex(ValueError, 'Invalid Syft archive member'):
                self.install_payload(directory, payload, hashlib.sha256(payload).hexdigest())
            self.assertFalse((directory / 'syft').exists())


class InventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.subject = identity()
        inventory(self.directory, self.subject)

    def verify(self, subject=None):
        return sbom.verify_inventory(self.directory, subject or self.subject,
                                     self.directory / 'image.manifest', self.directory / 'components.lock.json')

    def edit(self, name, change, rehash=False):
        path = self.directory / name
        value = json.loads(path.read_text())
        change(value)
        sbom.write_json(path, value)
        if rehash:
            self.edit(sbom.REPORT, lambda e: e['files'].update({name: sbom.sha256(path)}))

    def test_each_profile_and_architecture_has_own_subject_and_gaps(self):
        for profile in ['agent', 'inference']:
            for arch in ['amd64', 'arm64']:
                subject = identity(profile, arch)
                inventory(self.directory, subject)
                coverage = self.verify(subject)['coverage']
                self.assertFalse(coverage['complete_dependency_graph'])
                self.assertIn('/usr/bin/dfdaemon', coverage['runtime_dependency_gaps'])
                self.assertEqual(coverage['license_review'], 'pending')

    def test_missing_or_symlink_evidence_is_refused(self):
        report = self.directory / sbom.REPORT
        data = report.read_bytes()
        report.unlink()
        with self.assertRaises(ValueError): self.verify()
        target = self.directory / 'other.json'
        target.write_bytes(data)
        report.symlink_to(target)
        with self.assertRaises(ValueError): self.verify()

    def test_modified_or_symlink_inventory_is_refused(self):
        for name in sbom.FILES:
            inventory(self.directory, self.subject)
            path = self.directory / name
            path.write_text('{}')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'integrity'):
                self.verify()
            path.unlink()
            path.symlink_to(self.directory / sbom.REPORT)
            with self.assertRaises(ValueError): self.verify()
            path.unlink()

    def test_cross_image_profile_source_and_architecture_are_refused(self):
        for field, value in [('profile', 'inference'), ('architecture', 'amd64' if self.subject['architecture'] == 'arm64' else 'arm64'),
                             ('commit', 'c' * 40), ('raw_image_sha256', 'f' * 64), ('hardware_profile', 'cpu-full-firmware')]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'does not match'):
                self.verify({**self.subject, field: value})

    def test_missing_runtime_cannot_be_hidden_by_rehashing(self):
        self.edit(sbom.REPORT, lambda e: e['runtimes'].pop())
        with self.assertRaisesRegex(ValueError, 'locked components'): self.verify()

    def test_changed_runtime_bytes_cannot_be_hidden_by_rehashing(self):
        self.edit(sbom.FILES[0], lambda raw: raw['files'][0]['digests'][0].update(value='f' * 64), rehash=True)
        with self.assertRaisesRegex(ValueError, 'Runtime hash'): self.verify()

    def test_omitted_apt_package_and_forged_license_are_refused(self):
        for edit in [lambda bom: bom.update(components=[c for c in bom['components'] if not c['bom-ref'].startswith('outerspace:apt:')]),
                     lambda bom: bom['components'][0].update(licenses=[{'license': {'id': 'MIT'}}])]:
            inventory(self.directory, self.subject)
            self.edit(sbom.FILES[2], edit, rehash=True)
            with self.assertRaisesRegex(ValueError, 'bound inputs'): self.verify()

    def test_forged_complete_coverage_is_refused(self):
        self.edit(sbom.REPORT, lambda e: e['coverage'].update(complete_dependency_graph=True, license_review='passed'))
        with self.assertRaisesRegex(ValueError, 'coverage'): self.verify()

    def test_unpinned_scanner_is_refused(self):
        self.edit(sbom.REPORT, lambda e: e['scanner'].update(version='latest'))
        with self.assertRaisesRegex(ValueError, 'Scanner differs'): self.verify()

    def test_policy_and_manifest_changes_are_refused(self):
        self.edit(sbom.REPORT, lambda e: e.update(scanner_config_sha256='0' * 64))
        with self.assertRaisesRegex(ValueError, 'scanner policy'): self.verify()
        inventory(self.directory, self.subject)
        self.edit('image.manifest', lambda m: m['packages'].clear())
        with self.assertRaisesRegex(ValueError, 'source inventory'): self.verify()

    def test_runtime_cache_and_installed_binary_must_match(self):
        root = self.directory / 'root'
        (root / 'usr/bin').mkdir(parents=True)
        (root / 'usr/bin/tool').write_bytes(b'changed binary')
        cache = self.directory / 'cache'
        cache.mkdir()
        expected = hashlib.sha256(b'approved binary').hexdigest()
        (cache / expected).write_bytes(b'approved binary')
        lock = {'components': {'tool': {'version': '1', 'artifacts': {'arm64': {'sha256': expected}}}}}
        with self.assertRaisesRegex(ValueError, 'Installed runtime'):
            sbom.verified_runtimes(root, lock, 'arm64', cache)
        (root / 'usr/bin/tool').write_bytes(b'approved binary')
        self.assertEqual(len(sbom.verified_runtimes(root, lock, 'arm64', cache)), 1)
        (cache / expected).write_bytes(b'corrupted cache')
        with self.assertRaisesRegex(ValueError, 'Runtime cache'):
            sbom.verified_runtimes(root, lock, 'arm64', cache)

    def test_unknown_overlap_or_out_of_bounds_partitions_are_refused(self):
        table = {'label': 'gpt', 'unit': 'sectors', 'sectorsize': 512, 'partitions': [
            {'name': n, 'start': 2048 + i * 2048, 'size': 2048, 'type': t} for i, (n, t) in enumerate([
            ('esp', 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'),
            ('OOS_ROOT', 'b921b045-1df0-41c3-af44-4c6f280d3fae'),
            ('OOS_VERITY', 'df3300ce-d69f-4c92-978c-9bfb0f38d820'),
            ('OOS_STATE', '0fc63daf-8483-4772-8e79-3d69d8477de4')])]}
        self.assertEqual(len(sbom.partitions(table, 6 * 1024**2, 'arm64')), 4)
        for change in [lambda t: t['partitions'][1].update(start=2048),
                       lambda t: t['partitions'][1].update(size=999999999),
                       lambda t: t['partitions'][0].update(name='../other'),
                       lambda t: t.update(sectorsize=4096)]:
            altered = copy.deepcopy(table)
            change(altered)
            with self.assertRaises(ValueError): sbom.partitions(altered, 6 * 1024**2, 'arm64')
