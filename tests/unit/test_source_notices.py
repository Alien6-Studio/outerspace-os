# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from image_fixtures import BUILD_TOOLS
import supply_chain

sources = supply_chain.sources


class SupplementalNoticeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.manifest = b'[package]\nname="library"\nversion="1.0.0"\nlicense="MIT"\n'
        self.packaging = b'# Cargo-normalized metadata\n' + self.manifest
        self.crate_files = [('library-1.0.0/Cargo.toml', self.packaging),
                            ('library-1.0.0/Cargo.toml.orig', self.manifest),
                            ('library-1.0.0/src/lib.rs', b'pub fn library() {}\n')]
        self.repo_files = [('repo/library/Cargo.toml', self.manifest),
                           ('repo/library/src/lib.rs', b'pub fn library() {}\n'),
                           ('repo/LICENSE', b'Original synthetic notice\n')]
        self.crate = self.object(self.crate_files)
        self.repo = self.object(self.repo_files)
        self.cargo = [{**self.crate, 'name': 'library', 'version': '1.0.0', 'kind': 'cargo-registry'}]
        self.supplement = {**self.repo, 'name': 'example/library', 'commit': 'a' * 40,
                           'for_crates': [self.crate['sha256']], 'content_matches': {
            self.crate['sha256']: {'source_directory': 'library', 'packaging_files': {
                'Cargo.toml': hashlib.sha256(self.packaging).hexdigest()}, 'notice_paths': ['LICENSE']}}}

    def object(self, entries):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
            for name, data in entries:
                member = tarfile.TarInfo(name)
                if data is None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/etc/passwd'
                    tar.addfile(member)
                else:
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
        data = buffer.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        (self.cache / digest).write_bytes(data)
        return {'sha256': digest, 'size': len(data), 'url': 'https://example.invalid/' + digest}

    def prove(self):
        return sources.supplemental_provenance(self.cache, self.supplement, self.cargo)

    def replace_crate(self, entries):
        replacement = self.object(entries)
        config = self.supplement['content_matches'].pop(self.crate['sha256'])
        self.crate = replacement
        self.cargo[0].update(replacement)
        self.supplement['for_crates'] = [replacement['sha256']]
        self.supplement['content_matches'][replacement['sha256']] = config

    def test_complete_content_match_preserves_distinct_evidence_basis(self):
        result = self.prove()[self.crate['sha256']]
        self.assertEqual(result['basis'], 'published-files-match')
        self.assertFalse(result['publication_commit_proven'])
        self.assertEqual(set(result['matched_files']), {'Cargo.toml.orig', 'src/lib.rs'})
        self.assertEqual(set(result['packaging_files']), {'Cargo.toml'})
        self.assertEqual(result['notices']['LICENSE']['sha256'],
                         hashlib.sha256(b'Original synthetic notice\n').hexdigest())

    def test_changed_code_extra_file_and_unmatched_binary_are_refused(self):
        for entries in [self.crate_files[:-1] + [('library-1.0.0/src/lib.rs', b'changed code')],
                        self.crate_files + [('library-1.0.0/build.rs', b'extra code')],
                        self.crate_files + [('library-1.0.0/component.aar', b'generated binary')]]:
            self.replace_crate(entries)
            with self.assertRaisesRegex(ValueError, 'Published crate file differs'):
                self.prove()

    def test_code_cannot_be_exempted_as_packaging_metadata(self):
        config = self.supplement['content_matches'][self.crate['sha256']]
        for path in ['src/lib.rs', '*.rs', 'component.aar']:
            config['packaging_files'][path] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'Only explicit Cargo'):
                self.prove()
            del config['packaging_files'][path]

    def test_changed_packaging_bytes_and_package_identity_are_refused(self):
        self.replace_crate([('library-1.0.0/Cargo.toml', self.packaging + b'\n')] + self.crate_files[1:])
        with self.assertRaisesRegex(ValueError, 'reviewed bytes'):
            self.prove()
        altered = self.packaging.replace(b'license="MIT"', b'license="Apache-2.0"')
        self.replace_crate([('library-1.0.0/Cargo.toml', altered)] + self.crate_files[1:])
        self.supplement['content_matches'][self.crate['sha256']]['packaging_files']['Cargo.toml'] = hashlib.sha256(altered).hexdigest()
        with self.assertRaisesRegex(ValueError, 'license identity'):
            self.prove()

    def test_no_fallback_from_conflicting_publication_metadata(self):
        self.replace_crate(self.crate_files + [('library-1.0.0/.cargo_vcs_info.json',
                                                json.dumps({'git': {'sha1': 'b' * 40}}).encode())])
        with self.assertRaisesRegex(ValueError, 'cannot override'):
            self.prove()
        del self.supplement['content_matches']
        with self.assertRaisesRegex(ValueError, 'publication revision'):
            self.prove()
        self.supplement['commit'] = 'b' * 40
        self.assertEqual(self.prove()[self.crate['sha256']]['basis'], 'cargo-vcs-publication-commit')

    def test_missing_metadata_does_not_implicitly_enable_content_matching(self):
        del self.supplement['content_matches']
        with self.assertRaisesRegex(ValueError, 'Missing or ambiguous'):
            self.prove()

    def test_notice_paths_and_source_directory_are_explicit_and_safe(self):
        config = self.supplement['content_matches'][self.crate['sha256']]
        for paths in [[], ['missing/LICENSE'], ['LICENSE', 'LICENSE'], ['library/src/lib.rs']]:
            config['notice_paths'] = paths
            with self.assertRaisesRegex(ValueError, 'explicit original notice'):
                self.prove()
        config['notice_paths'] = ['LICENSE']
        config['source_directory'] = '../library'
        with self.assertRaisesRegex(ValueError, 'Unsafe crate source directory'):
            self.prove()

    def test_archive_duplicates_links_multiple_roots_and_traversal_are_refused(self):
        for entry in [('repo/LICENSE', b'duplicate'), ('repo/link', None),
                      ('other/LICENSE', b'other root'), ('repo/../LICENSE', b'traversal')]:
            archive = self.object(self.repo_files + [entry])
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                sources.archive_inventory(self.cache / archive['sha256'])

    @unittest.skipUnless(shutil.which('zstd'), 'Source archive integration requires zstd')
    def test_promotion_recomputes_proof_and_notice_bytes_from_bundle(self):
        cargo_lock = ('version=4\n[[package]]\nname="library"\nversion="1.0.0"\n'
                      'source="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + self.crate['sha256'] + '"\n')
        runtime = {**self.object([('project/Cargo.lock', cargo_lock.encode())]), 'commit': 'c' * 40}
        lock = self.root / 'sources.lock.json'
        lock.write_text(json.dumps({'sources': {'dfdaemon': runtime}, 'supplemental_sources': [self.supplement]}))
        with patch.object(sources, 'LOCK', lock):
            index = sources.collect(self.cache)
        def bundle(value):
            (self.root / 'source-index.json').write_text(json.dumps(value, indent=2) + '\n')
            (self.root / 'corresponding-source.tar.zst').unlink(missing_ok=True)
            sources.bundle(self.cache, self.root, value)
        bundle(index)
        self.assertEqual(sources.verify(self.root, {'sources': []}, lock)['objects'], 3)
        for field in ['notice_provenance', 'licenses']:
            altered = copy.deepcopy(index)
            entry = next(e for e in altered['entries'] if e['kind'] == 'supplemental-notice-source')
            entry[field] = {}
            bundle(altered)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'notice (provenance|inventory) differs'):
                sources.verify(self.root, {'sources': []}, lock)


if __name__ == '__main__':
    unittest.main()
