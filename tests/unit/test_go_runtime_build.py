# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'build/tools'))
import go_runtime_build as builder


class GoRuntimeBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lock = builder.read_lock()
        self.info = ('crictl: ' + self.lock['go_version'] + '\n'
                     '\tpath\tsigs.k8s.io/cri-tools/cmd/crictl\n'
                     '\tmod\tsigs.k8s.io/cri-tools\t(devel)\t\n'
                     '\tdep\texample.org/dependency\tv1.0.0\t\n'
                     '\tbuild\tCGO_ENABLED=0\n\tbuild\tGOOS=linux\n'
                     '\tbuild\tGOARCH=arm64\n\tbuild\t-trimpath=true\n')

    def test_embedded_compiler_target_and_dependencies(self):
        parsed = builder.build_info(self.info, 'arm64', self.lock)
        self.assertEqual(parsed['modules']['example.org/dependency'], 'v1.0.0')
        for old, new in [(self.lock['go_version'], 'go1.26.2'), ('CGO_ENABLED=0', 'CGO_ENABLED=1'),
                         ('GOARCH=arm64', 'GOARCH=amd64'), ('GOOS=linux', 'GOOS=darwin')]:
            with self.subTest(change=old), self.assertRaises(ValueError):
                builder.build_info(self.info.replace(old, new), 'arm64', self.lock)

    def test_replacements_and_ambiguous_metadata_are_rejected(self):
        for extra in ['\t=>\t/tmp/modified\t(devel)\n', '\tbuild\tCGO_ENABLED=1\n',
                      '\tdep\texample.org/dependency\tv9.0.0\n']:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                builder.build_info(self.info + extra, 'arm64', self.lock)

    def test_changed_binary_compiler_or_receipt_is_rejected(self):
        (self.root / 'crictl').write_bytes(b'synthetic binary')
        (self.root / 'LICENSE').write_text('Synthetic license fixture')
        report = {'schema': 1, 'architecture': 'arm64', 'source': self.lock['source'],
                  'go_source': self.lock['go_source'], 'compiler_input': self.lock['toolchains']['arm64'],
                  'recipe_sha256': builder.sha256(builder.LOCK),
                  'builder_script_sha256': builder.sha256(Path(builder.__file__)),
                  'extraction_script_sha256': builder.sha256(Path(builder.runtime_build.__file__)),
                  'dependency_script_sha256': builder.sha256(Path(builder.go_dependencies.__file__)),
                  'dependency_lock_sha256': self.lock['dependency_lock_sha256'],
                  'source_inputs': builder.go_dependencies.build_inputs(
                      builder.go_dependencies.read_lock(self.lock['dependency_lock_sha256'])),
                  'builder_image_id': 'sha256:' + 'a' * 64,
                  'binary_sha256': builder.sha256(self.root / 'crictl'),
                  'license_sha256': builder.sha256(self.root / 'LICENSE'),
                  'go_version_m': self.info, 'build_info': builder.build_info(self.info, 'arm64', self.lock)}
        path = self.root / 'runtime-build.json'
        path.write_text(json.dumps(report))
        builder.verify(self.root, 'arm64')
        for key, value in [('compiler_input', {}), ('build_info', {}), ('builder_image_id', 'latest'),
                           ('source_inputs', {}), ('dependency_lock_sha256', 'a' * 64)]:
            changed = copy.deepcopy(report); changed[key] = value
            path.write_text(json.dumps(changed))
            with self.subTest(key=key), self.assertRaises(ValueError):
                builder.verify(self.root, 'arm64')
        path.write_text(json.dumps(report))
        (self.root / 'crictl').write_bytes(b'altered binary')
        with self.assertRaisesRegex(ValueError, 'executable differs'):
            builder.verify(self.root, 'arm64')

    def test_dependency_update_rejects_missing_source_replacement_and_changed_checksum(self):
        dependencies = builder.go_dependencies
        original = dependencies.read_lock(self.lock['dependency_lock_sha256'])
        for change in ['missing-source', 'replacement', 'checksum']:
            config = copy.deepcopy(original)
            if change == 'missing-source':
                name = next(iter(dependencies.vendor_modules(config)))
                config['modules'] = [m for m in config['modules'] if m['path'] != name]
            elif change == 'replacement':
                config['manifests']['vendor/modules.txt'] += '# example.org/local v1.0.0 => ./local\n'
            else:
                config['modules'][0]['sum'] = 'h1:changed'
            with self.subTest(change=change), self.assertRaises(ValueError):
                dependencies.validate(config)

    def test_go_proxy_paths_reject_traversal_and_escape_uppercase(self):
        self.assertEqual(builder.go_dependencies.escape('github.com/Microsoft/go-winio'),
                         'github.com/!microsoft/go-winio')
        for name in ['../module', '/module', 'module/../other', 'module//other', 'module?query']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                builder.go_dependencies.escape(name)

    def test_containerd_requires_all_three_targets_and_pinned_build_tags(self):
        self.lock = builder.read_lock('containerd')
        module = builder.COMPONENTS['containerd']['module']
        report = {'schema': 1, 'architecture': 'arm64', 'source': self.lock['source'],
                  'go_source': self.lock['go_source'], 'compiler_input': self.lock['toolchains']['arm64'],
                  'recipe_sha256': builder.sha256(builder.recipe_path('containerd')),
                  'builder_script_sha256': builder.sha256(Path(builder.__file__)),
                  'extraction_script_sha256': builder.sha256(Path(builder.runtime_build.__file__)),
                  'dependency_script_sha256': builder.sha256(Path(builder.go_dependencies.__file__)),
                  'dependency_lock_sha256': self.lock['dependency_lock_sha256'],
                  'source_inputs': builder.go_dependencies.build_inputs(builder.go_dependencies.read_lock(
                      self.lock['dependency_lock_sha256'], 'containerd')),
                  'builder_image_id': 'sha256:' + 'a' * 64, 'additional_binaries': {}}
        for name in builder.COMPONENTS['containerd']['binaries']:
            (self.root / name).write_bytes(name.encode())
            info = (self.info.replace('sigs.k8s.io/cri-tools', module).replace('cmd/crictl', 'cmd/' + name)
                    + '\tbuild\t-tags=' + ','.join(builder.build_tags('containerd', name)) + '\n')
            record = {'sha256': builder.sha256(self.root / name), 'go_version_m': info,
                      'build_info': builder.build_info(info, 'arm64', self.lock, name)}
            if name == 'containerd':
                report.update(binary_sha256=record['sha256'], go_version_m=info, build_info=record['build_info'])
            else:
                report['additional_binaries'][name] = record
            with self.subTest(name=name), self.assertRaises(ValueError):
                builder.build_info(info.replace('static_build', 'unapproved'), 'arm64', self.lock, name)
        (self.root / 'LICENSE').write_text('Synthetic notice')
        report['license_sha256'] = builder.sha256(self.root / 'LICENSE')
        path = self.root / 'runtime-build.json'
        path.write_text(json.dumps(report))
        builder.verify(self.root, 'arm64', component='containerd')
        for name in ['ctr', 'containerd-shim-runc-v2']:
            changed = copy.deepcopy(report)
            del changed['additional_binaries'][name]
            path.write_text(json.dumps(changed))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'missing an executable'):
                builder.verify(self.root, 'arm64', component='containerd')
        path.write_text(json.dumps(report))
        (self.root / 'ctr').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'executable differs'):
            builder.verify(self.root, 'arm64', component='containerd')

    def test_historical_module_metadata_must_be_pinned_without_conflicting_proxy_bytes(self):
        dependencies = builder.go_dependencies
        lock = builder.read_lock('containerd')
        original = dependencies.read_lock(lock['dependency_lock_sha256'], 'containerd')
        self.assertTrue(original['graph_metadata'])
        for change in ['checksum', 'url', 'duplicate', 'path', 'zip']:
            config = copy.deepcopy(original)
            record = config['graph_metadata'][0]
            if change == 'checksum':
                record['go_mod_sum'] = 'h1:changed'
            elif change == 'url':
                record['files']['mod']['url'] = 'https://example.invalid/go.mod'
            elif change == 'duplicate':
                config['graph_metadata'].append(copy.deepcopy(record))
            elif change == 'path':
                record['path'] = '../escape'
            else:
                record['files']['zip'] = record['files']['mod']
            with self.subTest(change=change), self.assertRaises(ValueError):
                dependencies.validate(config)
        config = copy.deepcopy(original)
        record = copy.deepcopy(config['modules'][0])
        record['files'] = {'mod': record['files']['mod']}
        config['graph_metadata'].append(record)
        before = dependencies.source_entries(config)
        record['files']['mod']['sha256'] = 'a' * 64
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            dependencies.source_entries(config)
        self.assertEqual(len(before), len(dependencies.source_entries(original)))

    def test_kubelet_workspace_rejects_missing_manifests_and_external_replacements(self):
        dependencies = builder.go_dependencies
        lock = builder.read_lock('kubelet')
        original = dependencies.read_lock(lock['dependency_lock_sha256'], 'kubelet')
        self.assertEqual(len(original['workspace_modules']), 33)
        self.assertEqual(dependencies.vendor_modules(original)['k8s.io/api']['workspace_source'],
                         'staging/src/k8s.io/api')
        for change in ['missing', 'escape', 'external', 'version', 'manifest']:
            config = copy.deepcopy(original)
            if change == 'missing':
                del config['manifests']['staging/src/k8s.io/api/go.mod']
            elif change == 'escape':
                config['workspace_modules']['k8s.io/api'] = '../unapproved'
            elif change == 'external':
                config['manifests']['vendor/modules.txt'] += '# example.org/local v0.0.0 => ./staging/src/k8s.io/api\n'
            elif change == 'version':
                config['manifests']['vendor/modules.txt'] = config['manifests']['vendor/modules.txt'].replace(
                    '# k8s.io/api v0.0.0 =>', '# k8s.io/api v9.0.0 =>')
            else:
                config['manifests']['staging/src/k8s.io/api/../../outside'] = 'unapproved'
            with self.subTest(change=change), self.assertRaises(ValueError):
                dependencies.validate(config)

    def test_kubelet_keeps_its_target_tags_and_requires_the_pinned_compiler(self):
        lock = builder.read_lock('kubelet')
        info = (self.info.replace('sigs.k8s.io/cri-tools', 'k8s.io/kubernetes').replace('cmd/crictl', 'cmd/kubelet')
                + '\tdep\tk8s.io/api\t(devel)\t\n\tbuild\t-tags=selinux,notest,grpcnotrace\n')
        parsed = builder.build_info(info, 'arm64', lock)
        self.assertEqual(parsed['modules']['k8s.io/api'], '(devel)')
        for old, new in [('grpcnotrace', 'unapproved'), ('CGO_ENABLED=0', 'CGO_ENABLED=1'),
                         (lock['go_version'], 'go1.26.9')]:
            with self.subTest(change=old), self.assertRaises(ValueError):
                builder.build_info(info.replace(old, new), 'arm64', lock)
