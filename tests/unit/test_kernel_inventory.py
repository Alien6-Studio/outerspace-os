# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import io
import tarfile
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from image_fixtures import identity
import kernel_inventory
import kernel_build
import supply_chain


class KernelInventoryTests(unittest.TestCase):
    def test_source_archive_rejects_escape_and_writes_through_links(self):
        cases = [('../escape', None, None), ('linux/escape', '/tmp/outside', None),
                 ('linux/escape', '../../outside', None),
                 ('linux/alias', 'directory', 'linux/alias/write')]
        for name, target, child in cases:
            with self.subTest(name=name, target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); archive = root / 'source.tar'
                with tarfile.open(archive, 'w') as stream:
                    entry = tarfile.TarInfo(name)
                    if target:
                        entry.type = tarfile.SYMTYPE; entry.linkname = target
                    stream.addfile(entry)
                    if child:
                        stream.addfile(tarfile.TarInfo(child), io.BytesIO())
                with self.assertRaises(ValueError):
                    kernel_build.extract_source(archive, root / 'extracted')
                self.assertFalse((root / 'extracted').exists())

    def test_changed_or_additional_module_and_wrong_source_are_rejected(self):
        lock = kernel_build.read_lock()
        name = 'usr/lib/modules/' + lock['release'] + '/vmlinuz'
        report = {'release': lock['release'], 'source': lock['source'], 'files': {name: 'a' * 64, 'boot/vmlinuz-' + lock['release']: 'a' * 64,
                  'boot/config-' + lock['release']: 'b' * 64},
                  'evidence': {'kernel.config': 'b' * 64}}
        index = {'entries': [{'name': 'linux', **lock['source']}]}
        records = {**kernel_inventory.installed_files(report),
                   'usr/lib/modules/' + lock['release'] + '/initrd': 'c' * 64}
        raw = {'files': [{'location': {'path': '/' + path}, 'metadata': {'type': 'RegularFile'},
                         'digests': [{'algorithm': 'sha256', 'value': digest}]} for path, digest in records.items()]}
        with tempfile.TemporaryDirectory() as temporary, patch.object(kernel_build, 'verify_receipt', return_value=report):
            root = Path(temporary); (root / 'kernel-build.json').write_text('synthetic receipt')
            proof = kernel_inventory.correspondence(root, identity(), raw, index)
            self.assertEqual(kernel_inventory.artifact(proof)['version'], lock['version'])
            changed = copy.deepcopy(raw); changed['files'][0]['digests'][0]['value'] = 'c' * 64
            with self.assertRaisesRegex(ValueError, 'Installed kernel'):
                kernel_inventory.correspondence(root, identity(), changed, index)
            changed = copy.deepcopy(raw); changed['files'].append({
                'location': {'path': '/usr/lib/modules/unapproved/extra.ko'}, 'metadata': {'type': 'RegularFile'}})
            with self.assertRaisesRegex(ValueError, 'Unexpected'):
                kernel_inventory.correspondence(root, identity(), changed, index)
            with self.assertRaisesRegex(ValueError, 'source is absent'):
                kernel_inventory.correspondence(root, identity(), raw, {'entries': []})

    def test_kernel_component_scan_keeps_source_bound_paths_without_mutating_full_inventory(self):
        proof = {'release': '6.18.60-outerspace', 'version': '6.18.60', 'source_sha256': 'a' * 64,
                 'config_sha256': 'b' * 64, 'files': {'usr/lib/modules/6.18.60-outerspace/vmlinuz': 'c' * 64}}
        raw = {'artifacts': [{'name': 'original'}], 'artifactRelationships': [], 'files': [
            {'location': {'path': '/usr/bin/bash'}},
            {'location': {'path': '/usr/lib/modules/6.18.60-outerspace/vmlinuz'}}]}
        result = supply_chain.kernel_component_inventory(raw, proof)
        self.assertEqual(len(result['files']), 1)
        self.assertEqual(result['artifacts'][0]['name'], 'linux_kernel')
        self.assertEqual(raw['artifacts'], [{'name': 'original'}])


if __name__ == '__main__':
    unittest.main()
