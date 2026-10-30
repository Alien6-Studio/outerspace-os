# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'build/tools'))
import runtime_build
import zlib


class RuntimeBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.graph = {'format': 1, 'packages': [
            {'name': 'daemon', 'version': '1.0.0', 'source': 'local', 'root': True, 'dependencies': [1]},
            {'name': 'dependency', 'version': '2.0.0', 'source': 'crates.io'}]}

    def binary(self, graph=None, arch='arm64', section_name=b'.dep-v0'):
        data = zlib.compress(json.dumps(graph or self.graph).encode())
        names = b'\0.shstrtab\0' + section_name + b'\0'
        header = bytearray(64)
        header[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<H', header, 18, {'arm64': 183, 'amd64': 62}[arch])
        struct.pack_into('<Q', header, 40, 64)
        struct.pack_into('<HHH', header, 58, 64, 3, 1)
        sections = bytes(64) + struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, 256, len(names), 0, 0, 1, 0)
        sections += struct.pack('<IIQQQQIIQQ', 11, 1, 0, 0, 256 + len(names), len(data), 0, 0, 1, 0)
        path = self.root / 'daemon'
        path.write_bytes(header + sections + names + data)
        return path

    def test_reads_embedded_dependencies_for_each_architecture(self):
        for arch in ['amd64', 'arm64']:
            self.assertEqual(runtime_build.audit_data(self.binary(arch=arch), arch), self.graph)

    def test_wrong_architecture_missing_and_truncated_sections_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'architecture'):
            runtime_build.audit_data(self.binary(arch='amd64'), 'arm64')
        with self.assertRaisesRegex(ValueError, 'Missing'):
            runtime_build.audit_data(self.binary(section_name=b'.other0'), 'arm64')
        path = self.binary()
        path.write_bytes(path.read_bytes()[:-2])
        with self.assertRaisesRegex(ValueError, 'invalid'):
            runtime_build.audit_data(path, 'arm64')

    def test_dependency_graph_rejects_cycles_hidden_nodes_and_duplicate_roots(self):
        mutations = [lambda p: p[1].update(dependencies=[0]),
                     lambda p: p[0].update(dependencies=[]),
                     lambda p: p[1].update(root=True),
                     lambda p: p[0].update(dependencies=[2]),
                     lambda p: p[0].update(dependencies=[True])]
        for change in mutations:
            value = copy.deepcopy(self.graph)
            change(value['packages'])
            with self.subTest(value=value), self.assertRaises(ValueError):
                runtime_build.audit_data(self.binary(value), 'arm64')

    def archive(self, linked):
        path = self.root / 'source.tar'
        with tarfile.open(path, 'w') as tar:
            member = tarfile.TarInfo('project/README')
            member.size = 8
            tar.addfile(member, io.BytesIO(b'original'))
            member = tarfile.TarInfo('project/package/README')
            member.type = tarfile.SYMTYPE
            member.linkname = linked
            tar.addfile(member)
        return path

    def test_vendored_git_package_keeps_original_internal_notice_link_bytes(self):
        destination = self.root / 'package'
        runtime_build.extract(self.archive('../README'), destination, Path('package'))
        self.assertEqual((destination / 'README').read_bytes(), b'original')
        self.assertFalse((destination / 'README').is_symlink())

    def test_vendoring_rejects_links_outside_approved_source(self):
        for number, link in enumerate(['/etc/passwd', '../../../outside']):
            with self.subTest(link=link), self.assertRaisesRegex(ValueError, 'escapes'):
                runtime_build.extract(self.archive(link), self.root / str(number), Path('package'))
