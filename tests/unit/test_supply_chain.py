# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import shutil
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from image_fixtures import identity, BUILD_TOOLS
import attestations
import redistribution
import security
import supply_chain
import reproducibility

spec = importlib.util.spec_from_file_location('apt_inputs', BUILD_TOOLS / 'apt-inputs.py')
apt_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apt_inputs)


class AptSourceTests(unittest.TestCase):
    def test_shared_go_main_module_requires_source_proof_for_every_binary(self):
        paths = ['/usr/bin/containerd', '/usr/bin/ctr']
        raw = {'artifacts': [{'id': 'main', 'type': 'go-module', 'name': 'example.org/runtime',
                'version': 'UNKNOWN', 'locations': [{'path': p} for p in paths], 'metadata': {}}]}
        proofs = [{'main_module': 'example.org/runtime', 'path': p,
                   'source_sha256': 'a' * 64, 'module_version': 'v1.0.0'} for p in paths]
        def compose(selected):
            return supply_chain.compose_native(raw, {'packages': [], 'sources': []}, {'artifacts': []},
                {'packages': []}, {'entries': []}, go_build=selected)
        result = compose(proofs)['artifacts'][0]
        self.assertEqual(result['version'], 'v1.0.0')
        self.assertEqual(result['metadata']['outerspaceSourceBuild'], proofs)
        self.assertEqual(raw['artifacts'][0]['version'], 'UNKNOWN')
        for changed in [proofs[:1], [proofs[0], proofs[0]],
                        [proofs[0], {**proofs[1], 'source_sha256': 'b' * 64}]]:
            with self.subTest(proofs=changed), self.assertRaises(ValueError):
                compose(changed)

    def test_newer_spdx_identifiers_remain_declared_names_in_cyclonedx_16(self):
        original = {'components': [{'licenses': [{'license': {'id': 'MIT'}},
                                  {'license': {'id': 'SMAIL-GPL'}}, {'license': {'id': 'Artistic-dist'}}]}]}
        expected = copy.deepcopy(original)
        expected['components'][0]['licenses'][1] = {'license': {'name': 'SMAIL-GPL'}}
        expected['components'][0]['licenses'][2] = {'license': {'name': 'Artistic-dist'}}
        self.assertEqual(supply_chain.schema_licenses(original), expected)
        self.assertEqual(original['components'][0]['licenses'][1], {'license': {'id': 'SMAIL-GPL'}})

    def test_source_selection_is_version_exact_and_snapshot_bound(self):
        text = 'Package: runc-app\nVersion: 1.3.4\nDirectory: pool/main/r/runc-app\nChecksums-Sha256:\n ' + \
               'a' * 64 + ' 123 runc-app_1.3.4.dsc\n\nPackage: runc-app\nVersion: 1.2.0\n'
        records = apt_inputs.paragraphs(text)
        base = 'https://snapshot.ubuntu.com/ubuntu/20261027T000000Z/'
        source = apt_inputs.source_record(records, 'runc-app', '1.3.4', base)
        self.assertEqual(source['files'][0]['url'], base + 'pool/main/r/runc-app/runc-app_1.3.4.dsc')
        with self.assertRaisesRegex(ValueError, 'absent'):
            apt_inputs.source_record(records, 'runc-app', '1.3.5', base)
        for directory in ['pool/../../etc', '/etc', 'https://example.org']:
            records[0]['Directory'] = directory
            with self.assertRaises(ValueError):
                apt_inputs.source_record(records, 'runc-app', '1.3.4', base)

    def test_binary_source_confusion_and_omitted_packages_are_rejected(self):
        apt = {'packages': [{'name': 'runc', 'version': '1', 'architecture': 'arm64',
                            'source': 'runc-app', 'source_version': '1'}],
               'sources': [{'name': 'runc-app', 'version': '1'}]}
        manifest = {'packages': apt['packages']}
        native = {'artifacts': [{'name': 'runc', 'version': '1', 'type': 'deb',
                   'metadata': {'architecture': 'arm64', 'source': 'runc-app', 'sourceVersion': '1'}}]}
        supply_chain.apt_inventory(apt, manifest, native)
        native['artifacts'][0]['metadata']['source'] = 'runc'
        with self.assertRaisesRegex(ValueError, 'source identity'):
            supply_chain.apt_inventory(apt, manifest, native)
        native['artifacts'] = []
        with self.assertRaisesRegex(ValueError, 'inventory differs'):
            supply_chain.apt_inventory(apt, manifest, native)


class SourceArchiveTests(unittest.TestCase):
    def test_embedded_notice_requires_an_explicit_pinned_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'source.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('example.org/pkg@v1/Readme', b'Original embedded notice')
            self.assertEqual(supply_chain.sources.license_evidence(path)['notices'], [])
            result = supply_chain.sources.license_evidence(path, ['example.org/pkg@v1/Readme'])
            self.assertEqual(result['notices'][0]['sha256'], hashlib.sha256(b'Original embedded notice').hexdigest())
            with self.assertRaisesRegex(ValueError, 'absent'):
                supply_chain.sources.license_evidence(path, ['example.org/pkg@v1/missing'])

    def archive(self, root, entries):
        path = root / 'source.tar.gz'
        with tarfile.open(path, 'w:gz') as tar:
            for name, data in entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        return path

    @unittest.skipUnless(shutil.which('zstd'), 'Source archive integration requires zstd')
    def test_identical_source_bytes_keep_each_pinned_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); cache = root / 'cache'; cache.mkdir()
            cargo = b'version=4\n[[package]]\nname="workspace"\nversion="1.0.0"\n'
            path = self.archive(root, {'project/Cargo.lock': cargo})
            digest = security.sha256(path); shutil.copyfile(path, cache / digest)
            source = {'sha256': digest, 'url': 'https://example.invalid/source', 'size': path.stat().st_size}
            shared = b'one metadata object for two pinned origins'
            digest = hashlib.sha256(shared).hexdigest(); (cache / digest).write_bytes(shared)
            first = {'sha256': digest, 'size': len(shared), 'url': 'https://example.invalid/v1.mod'}
            second = {**first, 'url': 'https://example.invalid/v2.mod'}
            lockfile = root / 'sources.lock.json'
            security.write_json(lockfile, {'sources': {'dfdaemon': source, 'v1': first, 'v2': second}})
            entries = [{**source, 'kind': 'runtime-source', 'name': 'dfdaemon',
                        'cargo_lock_sha256': hashlib.sha256(cargo).hexdigest()},
                       {**first, 'kind': 'go-module-metadata'}, {**second, 'kind': 'go-module-metadata'}]
            index = {'schema': 1, 'source_lock_sha256': security.sha256(lockfile), 'entries': entries}
            security.write_json(root / 'source-index.json', index)
            supply_chain.sources.bundle(cache, root, index)
            self.assertEqual(supply_chain.sources.verify(root, {'sources': []}, lockfile)['objects'], 2)
            entries.pop()
            security.write_json(root / 'source-index.json', index)
            with self.assertRaisesRegex(ValueError, 'incomplete or changed'):
                supply_chain.sources.verify(root, {'sources': []}, lockfile)

    def test_cargo_transitive_input_requires_checksums_and_approved_git_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = ('version=4\n[[package]]\nname="dependency"\nversion="1.2.3"\n'
                    'source="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + 'a'*64 + '"\n')
            path = self.archive(root, {'project/Cargo.lock': lock.encode()})
            packages = supply_chain.sources.cargo_inventory(path, {})
            self.assertEqual(packages[0]['sha256'], 'a'*64)
            self.assertEqual(packages[0]['url'], 'https://static.crates.io/crates/dependency/dependency-1.2.3.crate')
            path = self.archive(root, {'project/Cargo.lock': lock.replace('registry+https://github.com/rust-lang/crates.io-index',
                                                                         'git+https://unapproved.invalid/repository').encode()})
            with self.assertRaisesRegex(ValueError, 'Unapproved Cargo'):
                supply_chain.sources.cargo_inventory(path, {})

    def test_cache_corruption_and_symlinks_are_rejected_without_downloading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = {'sha256': hashlib.sha256(b'approved').hexdigest(), 'url': 'https://example.invalid/source'}
            path = root / entry['sha256']
            path.write_bytes(b'modified')
            with self.assertRaisesRegex(ValueError, 'corruption'):
                supply_chain.sources.fetch(root, entry)
            path.unlink(); path.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                supply_chain.sources.fetch(root, entry)

    def test_source_notices_preserve_original_bytes_and_reject_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.archive(root, {'project/LICENSE': b'original notice'})
            result = supply_chain.sources.license_evidence(path)
            self.assertEqual(result['notices'][0]['sha256'], hashlib.sha256(b'original notice').hexdigest())
            path = self.archive(root, {'project/../../LICENSE': b'unsafe'})
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                supply_chain.sources.license_evidence(path)

    @unittest.skipUnless(shutil.which('zstd'), 'Source archive integration requires zstd')
    def test_source_archive_corruption_and_missing_cargo_closure_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); cache = root / 'cache'; cache.mkdir()
            for dependency in [False, True]:
                lock_text = 'version=4\n[[package]]\nname="workspace"\nversion="1.0.0"\n'
                if dependency:
                    lock_text += ('[[package]]\nname="required"\nversion="1.0.0"\n'
                                  'source="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + 'e'*64 + '"\n')
                path = self.archive(root, {'project/Cargo.lock': lock_text.encode()})
                digest = security.sha256(path); shutil.copyfile(path, cache / digest)
                entry = {'sha256': digest, 'size': path.stat().st_size, 'url': 'https://example.invalid/source'}
                lockfile = root / 'sources.lock.json'
                security.write_json(lockfile, {'sources': {'dfdaemon': entry}})
                index = {'schema': 1, 'source_lock_sha256': security.sha256(lockfile),
                         'entries': [{**entry, 'name': 'dfdaemon', 'kind': 'runtime-source',
                                      'cargo_lock_sha256': hashlib.sha256(lock_text.encode()).hexdigest()}]}
                security.write_json(root / 'source-index.json', index)
                supply_chain.sources.bundle(cache, root, index)
                if dependency:
                    with self.assertRaisesRegex(ValueError, 'transitive Cargo'):
                        supply_chain.sources.verify(root, {'sources': []}, lockfile)
                    continue
                self.assertEqual(supply_chain.sources.verify(root, {'sources': []}, lockfile)['objects'], 1)
                archive = root / 'corresponding-source.tar.zst'
                data = subprocess.check_output(['zstd', '-dc', str(archive)])
                buffer = io.BytesIO()
                with tarfile.open(fileobj=io.BytesIO(data)) as original, tarfile.open(fileobj=buffer, mode='w') as changed:
                    for member in original:
                        content = original.extractfile(member).read()
                        if member.name.startswith('objects/'):
                            content = bytes([content[0] ^ 1]) + content[1:]
                        changed.addfile(member, io.BytesIO(content))
                subprocess.run(['zstd', '-q', '-f', '-o', str(archive)], input=buffer.getvalue(), check=True)
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    supply_chain.sources.verify(root, {'sources': []}, lockfile)

    def test_reproducibility_localizes_changed_disk_regions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); a, b = root / 'a', root / 'b'
            a.write_bytes(b'a' * 256); b.write_bytes(b'a' * 64 + b'b' + b'a' * 191)
            differences = reproducibility.differing_blocks(a, b, block_size=64)
            self.assertEqual([(d['offset'], d['length']) for d in differences], [(64, 64)])

    def test_reproducibility_ignores_only_the_scanner_symlink_prefix(self):
        def scan(root, target):
            return {'source': {'type': 'directory', 'metadata': {'path': root}},
                    'files': [{'location': {'path': '/bin'}, 'metadata': {
                        'type': 'SymbolicLink', 'linkDestination': target}}]}
        a = scan('/tmp/scan-a', '/tmp/scan-a/usr/bin')
        b = scan('/tmp/scan-b', '/tmp/scan-b/usr/bin')
        self.assertEqual(reproducibility.file_inventory(a), reproducibility.file_inventory(b))
        self.assertEqual(a['files'][0]['metadata']['linkDestination'], '/tmp/scan-a/usr/bin')
        for target in ['/tmp/scan-b/usr/sbin', '/tmp/scan-b-other/usr/bin', '../usr/bin']:
            self.assertNotEqual(reproducibility.file_inventory(a),
                                reproducibility.file_inventory(scan('/tmp/scan-b', target)))
        a['files'].append(a['files'][0])
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            reproducibility.file_inventory(a)


class VulnerabilityReviewTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
        self.subject = identity('agent', 'arm64')
        self.policy = security.read_json(security.POLICY)
        # Synthetic October 27 evidence must not inherit real, dated image approvals.
        self.policy['exceptions'] = []
        self.database = {'built': '2026-10-27T06:00:00Z', 'valid': True, 'sha256': 'd'*64,
                         'from': 'https://example.invalid/db', 'schemaVersion': 'v6'}
        self.match = {'artifact': {'name': 'library', 'version': '1.0.0', 'type': 'go-module',
                       'purl': 'pkg:golang/example.org/library@1.0.0', 'locations': [{'path': '/usr/bin/containerd'}]},
                      'vulnerability': {'id': 'TEST-CVE', 'namespace': 'test:go', 'severity': 'High',
                                        'dataSource': 'https://example.invalid/advisory'}}
        self.scan = {'matches': [self.match], 'descriptor': {'name': 'grype',
            'version': security.read_json(security.LOCK)['version'], 'timestamp': '2026-10-27T10:00:00Z',
            'configuration': {'ignore': security.read_json(security.DEFAULT_IGNORE)},
            'db': {'status': self.database.copy()}}}

    def evaluate(self):
        return security.evaluate(self.scan, self.database, self.subject, self.policy, self.now)

    def exception(self):
        self.policy['exceptions'] = [{'finding_sha256': security.finding(self.match)['key'],
            'scope': security.exception_scope(self.subject),
            'reviewed_at': '2026-10-27T11:00:00Z', 'expires_at': '2026-11-03T11:00:00Z',
            'approved_by': 'Coopyrightdmin', 'owner': 'synthetic test owner', 'decision': 'not-affected',
            'rationale': 'Synthetic fixture only: this is not approval of a real vulnerability.',
            'evidence': ['https://example.invalid/synthetic-evidence']}]
        return self.policy['exceptions'][0]

    def test_untriaged_high_and_unknown_block_even_without_a_fix(self):
        for severity in ['High', 'Critical', 'Unknown']:
            self.match['vulnerability']['severity'] = severity
            self.assertEqual(self.evaluate()['status'], 'blocked')
        self.scan['matches'] = []
        self.assertEqual(self.evaluate()['status'], 'passed')

    def test_exception_is_scoped_accountable_and_expires_at_promotion(self):
        e = self.exception()
        self.assertEqual(self.evaluate()['status'], 'passed')
        self.subject['profile'] = 'inference'
        self.assertEqual(self.evaluate()['status'], 'blocked')
        self.subject['profile'] = 'agent'
        for key, value in [('expires_at', '2026-10-27T11:00:00Z'), ('approved_by', 'unapproved'),
                           ('owner', ''), ('rationale', ''), ('expires_at', '2027-01-01T00:00:00Z')]:
            original = e[key]; e[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.evaluate()
            e[key] = original

    def test_changed_dependency_path_or_version_cannot_reuse_exception(self):
        self.exception()
        self.match['artifact']['version'] = '1.0.1'
        with self.assertRaisesRegex(ValueError, 'Unused'): self.evaluate()

    def test_updated_ubuntu_or_source_inputs_invalidate_exception(self):
        e = self.exception()
        for field in ['inputs_lock_sha256', 'sources_lock_sha256']:
            previous = e['scope'][field]
            e['scope'][field] = '0' * 64
            self.assertEqual(self.evaluate()['status'], 'blocked')
            e['scope'][field] = previous

    def test_stale_future_and_different_database_are_rejected(self):
        for value in ['2026-10-01T06:00:00Z', '2026-10-28T06:00:00Z']:
            self.database['built'] = value
            with self.assertRaisesRegex(ValueError, 'stale'): self.evaluate()
        self.database['built'] = '2026-10-27T05:00:00Z'
        with self.assertRaisesRegex(ValueError, 'recorded'): self.evaluate()

    def test_hidden_scanner_ignores_are_rejected(self):
        self.scan['descriptor']['configuration']['ignore'].append({'vulnerability': 'TEST-CVE'})
        with self.assertRaisesRegex(ValueError, 'ignore'): self.evaluate()

    def test_filtering_unfixed_findings_and_unknown_severity_cannot_pass(self):
        self.scan['descriptor']['configuration']['only-fixed'] = True
        with self.assertRaisesRegex(ValueError, 'Filtered'): self.evaluate()
        self.scan['descriptor']['configuration']['only-fixed'] = False
        self.match['vulnerability']['severity'] = 'unexpected'
        with self.assertRaisesRegex(ValueError, 'severity'): self.evaluate()


class ProvenanceTests(unittest.TestCase):
    def test_signature_verifier_constrains_certificate_source_builder_and_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checksums, bundle = root / 'SHA256SUMS', root / 'proof.jsonl'
            checksums.write_text('test'); bundle.write_text('synthetic')
            verified = [{'verificationResult': {'statement': {'predicate': {'runDetails': {'metadata': {
                'invocationId': 'https://github.com/Alien6-Studio/outerspace-os/actions/runs/123/attempts/1'}}}}}}]
            with patch.object(attestations.subprocess, 'check_output', return_value=json.dumps(verified)) as gh:
                attestations.verify(checksums, bundle, 'a'*40, 'v0.1.0-alpha.1', '123')
                command = gh.call_args.args[0]
                for flag in ['--signer-digest', '--source-digest', '--source-ref', '--deny-self-hosted-runners',
                             '--signer-workflow', '--cert-oidc-issuer']:
                    self.assertIn(flag, command)
                with self.assertRaisesRegex(ValueError, 'workflow run'):
                    attestations.verify(checksums, bundle, 'a'*40, 'v0.1.0-alpha.1', '124')
            with patch.object(attestations.subprocess, 'check_output', side_effect=subprocess.CalledProcessError(1, 'gh')):
                with self.assertRaises(subprocess.CalledProcessError):
                    attestations.verify(checksums, bundle, 'a'*40, 'v0.1.0-alpha.1', '123')

    def test_inventory_is_not_redistribution_approval(self):
        apt = {'packages': [{'name': 'example', 'version': '1', 'source': 'example',
                            'source_version': '1', 'notice_sha256': 'a'*64}]}
        index = {'source_lock_sha256': 'b'*64, 'entries': [{'name': 'crate', 'version': '1',
                 'sha256': 'c'*64, 'kind': 'cargo-registry', 'licenses': {'notices': []}}],
                 'cargo_relationship': 'declared source closure'}
        review = redistribution.assess(identity(), apt, index, redistribution.read_json(redistribution.POLICY))
        self.assertEqual(review['status'], 'review-required')
        self.assertEqual(len(review['source_archives_without_notice_files']), 1)
        other = redistribution.assess(identity('inference'), apt, index, redistribution.read_json(redistribution.POLICY))
        self.assertNotEqual(review['subject_sha256'], other['subject_sha256'])

    def test_go_metadata_does_not_hide_missing_module_notice(self):
        index = {'source_lock_sha256': 'b'*64, 'entries': [
            {'name': 'example.org/module', 'version': 'v1.0.0', 'sha256': 'c'*64,
             'kind': 'go-module-source', 'licenses': {'notices': []}},
            {'name': 'example.org/module', 'version': 'v1.0.0', 'sha256': 'd'*64,
             'kind': 'go-module-metadata'}], 'cargo_relationship': 'declared source closure'}
        result = redistribution.assess(identity(), {'packages': []}, index, redistribution.read_json(redistribution.POLICY))
        self.assertEqual([p['sha256'] for p in result['source_archives_without_notice_files']], ['c'*64])
        index['entries'][0]['licenses']['notices'] = [{'path': 'LICENSE', 'sha256': 'e'*64}]
        result = redistribution.assess(identity(), {'packages': []}, index, redistribution.read_json(redistribution.POLICY))
        self.assertEqual(result['source_archives_without_notice_files'], [])
        self.assertEqual(result['status'], 'review-required')
