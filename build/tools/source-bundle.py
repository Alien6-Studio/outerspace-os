#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Archive checksum-verified Ubuntu, runtime, vendored and Cargo sources."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from urllib.parse import urlsplit

from profiles import ROOT, sha256
import go_dependencies

LOCK = ROOT / 'build/sbom/sources.lock.json'


def fetch(cache, entry):
    digest = entry['sha256']
    if not re.fullmatch('[a-f0-9]{64}', digest) or urlsplit(entry['url']).scheme != 'https':
        raise ValueError('Sources require an approved SHA256 and HTTPS origin')
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / digest
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Unsafe source cache entry')
    if not path.exists():
        with tempfile.NamedTemporaryFile(dir=cache, prefix='fetch-', delete=False) as stream:
            temporary = Path(stream.name)
        try:
            subprocess.run(['curl', '-fsSL', '--proto', '=https', '--proto-redir', '=https', '--retry', '3',
                '--max-time', '900', '--speed-limit', '1024', '--speed-time', '90',
                '-o', str(temporary), entry['url']], check=True)
            if sha256(temporary) != digest:
                raise ValueError('Corresponding source checksum mismatch: ' + entry['url'])
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    if sha256(path) != digest or ('size' in entry and path.stat().st_size != entry['size']):
        raise ValueError('Corresponding source cache corruption: ' + entry['url'])
    return path


def archive_file(path, suffix):
    with tarfile.open(path) as tar:
        members = [m for m in tar if m.name.endswith('/' + suffix)]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError('Missing or ambiguous source file: ' + suffix)
        return tar.extractfile(members[0]).read()


def cargo_inventory(source, git_sources):
    lock = tomllib.loads(archive_file(source, 'Cargo.lock').decode())
    packages = []
    for p in lock['package']:
        origin = p.get('source')
        if not origin:
            continue  # Workspace source is already in the complete repository archive.
        if origin == 'registry+https://github.com/rust-lang/crates.io-index':
            if not re.fullmatch('[A-Za-z0-9_-]+', p['name']) or not re.fullmatch('[A-Za-z0-9.+_-]+', p['version']):
                raise ValueError('Unsafe Cargo package name/version')
            entry = {'name': p['name'], 'version': p['version'], 'sha256': p['checksum'],
                     'url': f'https://static.crates.io/crates/{p["name"]}/{p["name"]}-{p["version"]}.crate',
                     'kind': 'cargo-registry', 'declared_by': 'dfdaemon/Cargo.lock'}
        elif origin in git_sources:
            entry = {**git_sources[origin], 'name': p['name'], 'version': p['version'],
                     'kind': 'cargo-git', 'declared_by': 'dfdaemon/Cargo.lock'}
        else:
            raise ValueError('Unapproved Cargo source: ' + origin)
        packages.append(entry)
    return packages


def license_evidence(path, extra_paths=()):
    """Keep declarations and exact notice bytes; never invent license decisions."""
    declarations = []
    notices = []
    if zipfile.is_zipfile(path):
        seen = set()
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                name = PurePosixPath(member.filename)
                if (name.is_absolute() or '..' in name.parts or '\\' in member.filename
                        or member.filename in seen):
                    raise ValueError('Unsafe or duplicate Go source archive path')
                seen.add(member.filename)
                if not member.is_dir() and (name.name.upper().startswith(
                        ('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT'))
                        or name.name.upper() == 'AUTHORS' or str(name) in extra_paths):
                    data = archive.read(member)
                    notices.append({'path': str(name), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
        if not set(extra_paths) <= {notice['path'] for notice in notices}:
            raise ValueError('Pinned embedded Go notice is absent from its source archive')
        return {'declared_licenses': [], 'notices': notices}
    if extra_paths:
        raise ValueError('Explicit embedded notice paths require a Go source ZIP')
    with tarfile.open(path) as tar:
        for member in tar:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts:
                raise ValueError('Unsafe source archive path')
            if not member.isfile():
                continue
            leaf = name.name.upper()
            if (leaf.startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT'))
                    or leaf == 'AUTHORS'):
                data = tar.extractfile(member).read()
                notices.append({'path': str(name), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
            if name.name == 'Cargo.toml' and len(name.parts) == 2:
                manifest = tomllib.loads(tar.extractfile(member).read().decode())
                package = manifest.get('package', {})
                if isinstance(package.get('license'), str):
                    declarations.append(package['license'])
    return {'declared_licenses': sorted(set(declarations)), 'notices': notices}


def archive_inventory(path, *, flat=False, allow_internal_links=False):
    """Hash regular files under one archive root without extracting paths."""
    files, seen, roots = {}, set(), set()
    with tarfile.open(path) as tar:
        for member in tar:
            name = PurePosixPath(member.name)
            if flat and str(name) == '.' and member.isdir():
                continue
            if name.is_absolute() or '..' in name.parts or not name.parts:
                raise ValueError('Unsafe notice source archive path')
            roots.add(name.parts[0])
            if str(name) in seen:
                raise ValueError('Duplicate notice source archive path')
            seen.add(str(name))
            if member.isdir():
                continue
            relative = str(name if flat else PurePosixPath(*name.parts[1:]))
            if member.issym() and allow_internal_links and not flat:
                target = posixpath.normpath(str(name.parent / member.linkname))
                if PurePosixPath(member.linkname).is_absolute() or not target.startswith(name.parts[0] + '/'):
                    raise ValueError('Notice source link escapes its archive')
                files[relative] = {'link': target}
                continue
            if not member.isfile() or (not flat and len(name.parts) < 2):
                raise ValueError('Notice content matching requires regular files')
            files[relative] = {'sha256': hashlib.file_digest(tar.extractfile(member), 'sha256').hexdigest(),
                               'bytes': member.size}
    if (not flat and len(roots) != 1) or not files:
        raise ValueError('Notice source archive requires one nonempty root')
    return files


def payload_entries(supplements):
    return [{**config['artifact'], 'kind': 'supplemental-release-payload', 'for_crates': [digest]}
            for supplement in supplements for digest, config in supplement.get('release_payload_matches', {}).items()]


def release_payload_provenance(cache, supplement, config, digest):
    artifact = config['artifact']
    if (not config.get('release_url', '').startswith('https://github.com/' + supplement['name'] + '/releases/tag/')
            or not artifact['url'].startswith('https://github.com/' + supplement['name'] + '/releases/download/')):
        raise ValueError('Release payload must identify its upstream release')
    published = archive_inventory(cache / digest)
    payload = archive_inventory(cache / artifact['sha256'], flat=True)
    if published != payload:
        raise ValueError('Published crate differs from the complete upstream release payload')
    source = archive_inventory(cache / supplement['sha256'], allow_internal_links=True)
    prefix = PurePosixPath(config['source_directory'])
    if prefix.is_absolute() or '..' in prefix.parts or str(prefix) != config['source_directory']:
        raise ValueError('Unsafe release source directory')
    names = {'Cargo.toml.orig'} | {name for name in published if name.startswith('src/')}
    if 'Cargo.toml.orig' not in published or len(names) < 2:
        raise ValueError('Release payload requires its original manifest and Rust sources')
    matched = {}
    for name in sorted(names):
        target = str(prefix / ('Cargo.toml' if name == 'Cargo.toml.orig' else name))
        if source.get(target) != published[name]:
            raise ValueError('Release manifest or Rust source differs from its source revision')
        matched[name] = {'source_path': target, **published[name]}
    notices = config['notice_paths']
    recognized = {str(PurePosixPath(n['path']).relative_to(PurePosixPath(n['path']).parts[0]))
                  for n in license_evidence(cache / supplement['sha256'])['notices']}
    if not notices or len(notices) != len(set(notices)) or not set(notices) <= recognized:
        raise ValueError('Release payload requires explicit original notice files')
    return {'basis': 'complete-upstream-release-payload-match', 'commit': supplement['commit'],
            'release_url': config['release_url'], 'payload_sha256': artifact['sha256'],
            'published_files': published, 'matched_source_files': matched,
            'generated_payload_build_proven': False,
            'notices': {name: source[name] for name in notices}}


def notice_metadata_differences(cache, supplement, digest, config, files, source_files, prefix):
    """Account for pinned CI/dev metadata changes without exempting source code."""
    result = {}
    for name, pins in config.get('metadata_changes', {}).items():
        if name != 'Cargo.toml.orig' and not re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.ya?ml', name):
            raise ValueError('Only an original Cargo manifest or explicit CI workflow may differ')
        target = str(prefix / ('Cargo.toml' if name == 'Cargo.toml.orig' else name))
        before, after = files.get(name), source_files.get(target)
        if (not before or not after or before == after
                or set(pins) != {'published_sha256', 'upstream_sha256'}
                or before.get('sha256') != pins['published_sha256']
                or after.get('sha256') != pins['upstream_sha256']):
            raise ValueError('Notice metadata differs from its reviewed byte identities')
        if name == 'Cargo.toml.orig':
            manifests = [tomllib.loads(archive_file(cache / digest, name).decode()),
                         tomllib.loads(archive_file(cache / supplement['sha256'], target).decode())]
            for manifest in manifests:
                manifest.pop('dev-dependencies', None)
                # Cargo historically accepted this dual-license spelling. Only
                # these explicit equivalent spellings are normalized, not SPDX
                # expressions generally or a different license grant.
                if manifest['package'].get('license') in ('Apache-2.0/MIT', 'Apache-2.0 OR MIT', 'MIT OR Apache-2.0'):
                    manifest['package']['license'] = 'Apache-2.0 OR MIT'
            if manifests[0] != manifests[1]:
                raise ValueError('Later notice changed runtime/build metadata or package identity')
        result[name] = {'source_path': target, 'published': before, 'upstream': after}
    return result


def supplemental_provenance(cache, supplement, cargo):
    """Distinguish publication metadata from complete published-file matching."""
    crates = {e['sha256']: e for e in cargo}
    content_matches = supplement.get('content_matches', {})
    backfills = supplement.get('notice_backfills', {})
    payloads = supplement.get('release_payload_matches', {})
    configured = list(content_matches) + list(backfills) + list(payloads)
    if (not set(configured) <= set(supplement['for_crates']) or len(set(configured)) != len(configured)):
        raise ValueError('Content match refers to an unknown supplemental crate')
    result = {}
    source_files = None
    for digest in supplement['for_crates']:
        if digest not in crates:
            raise ValueError('Supplemental notice refers to an unknown crate')
        if digest in payloads:
            manifest = tomllib.loads(archive_file(cache / digest, 'Cargo.toml').decode())['package']
            if (manifest.get('name'), manifest.get('version')) != (crates[digest]['name'], crates[digest]['version']):
                raise ValueError('Release payload manifest differs from Cargo lock identity')
            result[digest] = release_payload_provenance(cache, supplement, payloads[digest], digest)
            continue
        if digest not in content_matches and digest not in backfills:
            vcs = json.loads(archive_file(cache / digest, '.cargo_vcs_info.json'))
            if vcs['git']['sha1'] != supplement['commit']:
                raise ValueError('Supplemental notice source is not the crate publication revision')
            result[digest] = {'basis': 'cargo-vcs-publication-commit', 'commit': supplement['commit']}
            continue
        config = backfills[digest] if digest in backfills else content_matches[digest]
        prefix = PurePosixPath(config['source_directory'])
        if prefix.is_absolute() or '..' in prefix.parts or str(prefix) != config['source_directory']:
            raise ValueError('Unsafe crate source directory')
        files = archive_inventory(cache / digest)
        publication = None
        if digest in backfills:
            if '.cargo_vcs_info.json' not in files:
                raise ValueError('A later notice requires original publication metadata')
            vcs = json.loads(archive_file(cache / digest, '.cargo_vcs_info.json'))
            commit = config.get('publication_commit', '')
            if (not re.fullmatch('[a-f0-9]{40}', commit) or vcs['git']['sha1'] != commit
                    or commit == supplement['commit'] or not config.get('evidence')
                    or not all(str(u).startswith('https://') for u in config['evidence'])):
                raise ValueError('Later notice does not preserve the original publication revision')
            publication = {'commit': commit, **files['.cargo_vcs_info.json']}
        elif '.cargo_vcs_info.json' in files:
            raise ValueError('Content matching cannot override crate publication metadata')
        # Only Cargo packaging metadata may differ. Its exact bytes must be
        # reviewed and pinned individually; no code/binary/glob exceptions.
        generated = config['packaging_files']
        if not {'Cargo.toml'} <= set(generated) <= {'Cargo.toml', 'Cargo.lock'}:
            raise ValueError('Only explicit Cargo packaging metadata may differ')
        if any(name not in files or files[name]['sha256'] != value for name, value in generated.items()):
            raise ValueError('Cargo packaging metadata differs from reviewed bytes')
        if 'Cargo.toml.orig' not in files or not any(n.startswith('src/') for n in files):
            raise ValueError('Content match requires the original manifest and source')
        manifest = tomllib.loads(archive_file(cache / digest, 'Cargo.toml').decode())['package']
        original = tomllib.loads(archive_file(cache / digest, 'Cargo.toml.orig').decode())['package']
        if (manifest.get('name'), manifest.get('version')) != (crates[digest]['name'], crates[digest]['version']):
            raise ValueError('Crate manifest differs from Cargo lock identity')
        if any(manifest.get(k) != original.get(k) for k in ['name', 'version', 'license', 'repository']):
            raise ValueError('Cargo packaging changed package or license identity')
        if source_files is None:
            source_files = archive_inventory(cache / supplement['sha256'])
        if config.get('metadata_changes') and publication is None:
            raise ValueError('Metadata differences require explicit later-notice publication evidence')
        metadata = notice_metadata_differences(cache, supplement, digest, config, files, source_files, prefix)
        matched = {}
        for name, record in files.items():
            if name in generated or name in metadata or (publication is not None and name == '.cargo_vcs_info.json'):
                continue
            target = str(prefix / ('Cargo.toml' if name == 'Cargo.toml.orig' else name))
            if source_files.get(target) != record:
                raise ValueError('Published crate file differs from supplemental source: ' + name)
            matched[name] = {'source_path': target, **record}
        notices = config['notice_paths']
        recognized = {str(PurePosixPath(n['path']).relative_to(PurePosixPath(n['path']).parts[0]))
                      for n in license_evidence(cache / supplement['sha256'])['notices']}
        if not notices or len(notices) != len(set(notices)) or not set(notices) <= recognized:
            raise ValueError('Content match requires explicit original notice files')
        result[digest] = {'basis': 'published-files-match', 'commit': supplement['commit'],
                          'publication_commit_proven': False, 'matched_files': matched,
                          'packaging_files': {name: files[name] for name in generated},
                          'notices': {name: source_files[name] for name in notices}}
        if publication is not None:
            result[digest].update(basis='published-files-match-with-later-notice',
                                  publication_metadata=publication, notice_evidence=config['evidence'])
        if metadata:
            result[digest].update(basis='later-notice-with-metadata-differences', metadata_changes=metadata)
    return result


def go_vendor_inventory(path):
    with tarfile.open(path) as tar:
        matches = [m for m in tar if len(PurePosixPath(m.name).parts) == 3 and m.name.endswith('/vendor/modules.txt')]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError('Missing vendored Go dependency sources')
        modules = {}
        root = PurePosixPath(matches[0].name).parts[0]
        for line in tar.extractfile(matches[0]).read().decode().splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0] == '#' and fields[2].startswith('v'):
                record = {'version': fields[2]}
                if len(fields) == 5 and fields[3] == '=>' and fields[4].startswith('./'):
                    path = PurePosixPath(fields[4])
                    if '..' in path.parts or path.is_absolute():
                        raise ValueError('Unsafe vendored workspace path')
                    member = tar.getmember(str(PurePosixPath(root) / path / 'go.mod'))
                    if not member.isfile():
                        raise ValueError('Missing vendored workspace source')
                    record['workspace_source'] = str(path)
                modules[fields[1]] = record
        return modules


def go_build_inputs(path, names=('go.mod', 'go.sum', 'vendor/modules.txt')):
    result = {}
    with tarfile.open(path) as tar:
        members = tar.getmembers()
        for name in names:
            matches = [m for m in members if PurePosixPath(m.name).parts[1:] == PurePosixPath(name).parts]
            if not matches and (name == 'go.work.sum' or name.endswith('/go.sum')):
                result[name] = None  # Newly materialized by the pinned dependency update.
                continue
            if len(matches) != 1 or not matches[0].isfile():
                raise ValueError('Missing or ambiguous root Go build input: ' + name)
            result[name] = hashlib.file_digest(tar.extractfile(matches[0]), 'sha256').hexdigest()
    return result


def collect(cache, apt_inputs=None):
    lock = json.loads(LOCK.read_text())
    updates = {name: go_dependencies.read_lock(digest, name) for name, digest in lock.get('go_dependency_updates', {}).items()}
    entries = [{**entry, 'name': name, 'kind': 'runtime-source' if 'commit' in entry
                else entry.get('source_kind', 'go-standard-library')}
               for name, entry in lock['sources'].items()]
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda e: fetch(cache, e), entries))
    cargo = cargo_inventory(cache / lock['sources']['dfdaemon']['sha256'], lock.get('cargo_git_sources', {}))
    entries.extend(cargo)
    entries.extend({**e, 'kind': 'supplemental-notice-source'} for e in lock.get('supplemental_sources', []))
    entries.extend(payload_entries(lock.get('supplemental_sources', [])))
    for config in updates.values():
        entries.extend(go_dependencies.source_entries(config))
    if apt_inputs:
        for source in apt_inputs['sources']:
            for entry in source['files']:
                entries.append({**entry, 'kind': 'ubuntu-source', 'package': source['name'], 'version': source['version']})
    unique = {entry['sha256']: entry for entry in entries}
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda e: fetch(cache, e), unique.values()))
    print('Verified source objects:', len(unique), flush=True)
    for entry in entries:
        if entry['kind'] not in ['ubuntu-source', 'go-module-metadata']:
            entry['licenses'] = license_evidence(cache / entry['sha256'],
                lock.get('embedded_go_notices', {}).get(entry['sha256'], []))
        if entry['kind'] == 'supplemental-notice-source':
            entry['notice_provenance'] = supplemental_provenance(cache, entry, cargo)
        if entry['kind'] == 'runtime-source' and entry['name'] in ['containerd', 'kubelet', 'crictl']:
            entry['go_vendor_modules'] = go_vendor_inventory(cache / entry['sha256'])
            if entry['name'] in updates:
                entry['go_build_inputs'] = go_build_inputs(cache / entry['sha256'], updates[entry['name']]['manifests'])
                entry['upstream_go_build_inputs'] = entry['go_build_inputs']
                entry['upstream_go_vendor_modules'] = entry['go_vendor_modules']
                entry['go_build_inputs'] = go_dependencies.build_inputs(updates[entry['name']])
                entry['go_vendor_modules'] = go_dependencies.vendor_modules(updates[entry['name']])
        if entry['kind'] == 'runtime-source' and entry['name'] == 'dfdaemon':
            entry['cargo_lock_sha256'] = hashlib.sha256(archive_file(cache / entry['sha256'], 'Cargo.lock')).hexdigest()
    return {'schema': 1, 'source_lock_sha256': sha256(LOCK), 'entries': entries, 'go_dependency_updates': updates,
            'cargo_relationship': 'Archived source lock closure includes target/build/test dependencies. '
                                  'The separate source-build receipt and disk scan identify the compiled runtime inventory.'}


def verify(directory, apt_inputs, lock_path=LOCK):
    """Verify contents, not just a self-reported archive digest, at promotion."""
    index_path = directory / 'source-index.json'
    archive = directory / 'corresponding-source.tar.zst'
    if any(p.is_symlink() or not p.is_file() for p in [index_path, archive]):
        raise ValueError('Missing or unsafe corresponding source')
    index = json.loads(index_path.read_text())
    lock = json.loads(lock_path.read_text())
    if index.get('schema') != 1 or index.get('source_lock_sha256') != sha256(lock_path):
        raise ValueError('Sources differ from approved source lock')
    entries = index['entries']
    actual = {e['sha256']: e for e in entries}
    # Different module versions can legitimately share identical go.mod bytes.
    # Archive each content-addressed object once, but retain every pinned origin.
    origins = {}
    for entry in entries:
        origins.setdefault(entry['sha256'], []).append(entry)
    updates = {name: go_dependencies.read_lock(digest, name) for name, digest in lock.get('go_dependency_updates', {}).items()}
    if index.get('go_dependency_updates', {}) != updates:
        raise ValueError('Go dependency update differs from approved source inputs')
    go_entries = [e for config in updates.values() for e in go_dependencies.source_entries(config)]
    if not set(lock.get('embedded_go_notices', {})) <= {
            e['sha256'] for e in go_entries if e['kind'] == 'go-module-source'}:
        raise ValueError('Embedded notices must refer to a pinned Go source ZIP')
    required = (list(lock['sources'].values()) + lock.get('supplemental_sources', [])
                + payload_entries(lock.get('supplemental_sources', []))
                + go_entries
                + [f for s in apt_inputs['sources'] for f in s['files']])
    if any(not any(all(candidate.get(k) == v for k, v in entry.items())
                   for candidate in origins.get(entry['sha256'], [])) for entry in required):
        raise ValueError('Corresponding source is incomplete or changed')
    seen = set()
    cargo_lock = None
    supplements = lock.get('supplemental_sources', [])
    proof_objects = {s['sha256'] for s in supplements} | {d for s in supplements for d in s['for_crates']}
    proof_objects.update(e['sha256'] for e in payload_entries(supplements))
    proof_objects.update(e['sha256'] for e in go_entries if e['kind'] == 'go-module-source')
    with tempfile.TemporaryDirectory(prefix='outerspace-notice-proof-') as temporary, \
            subprocess.Popen(['zstd', '-dc', str(archive)], stdout=subprocess.PIPE) as decoder:
        proof_cache = Path(temporary)
        try:
            with tarfile.open(fileobj=decoder.stdout, mode='r|') as tar:
                for member in tar:
                    if not member.isfile() or member.name in seen:
                        raise ValueError('Unsafe or duplicate corresponding source entry')
                    seen.add(member.name)
                    stream = tar.extractfile(member)
                    if member.name == 'source-index.json':
                        if stream.read() != index_path.read_bytes():
                            raise ValueError('Embedded source index differs')
                        continue
                    digest = member.name.removeprefix('objects/')
                    if member.name != 'objects/' + digest or digest not in actual:
                        raise ValueError('Unexpected corresponding source object')
                    # dfdaemon's source proves the registry closure, including
                    # crates without dependency metadata in the stripped binary.
                    runtime = next((e for e in entries if e['sha256'] == digest and e['kind'] == 'runtime-source'), None)
                    if runtime or digest in proof_objects:
                        data = stream.read()
                        if hashlib.sha256(data).hexdigest() != digest:
                            raise ValueError('Source object checksum mismatch')
                        if digest in proof_objects:
                            (proof_cache / digest).write_bytes(data)
                    if runtime:
                        with tempfile.NamedTemporaryFile() as temporary:
                            temporary.write(data); temporary.flush()
                            if runtime['name'] == 'dfdaemon':
                                cargo_lock = cargo_inventory(Path(temporary.name), lock.get('cargo_git_sources', {}))
                                if runtime.get('cargo_lock_sha256') != hashlib.sha256(
                                        archive_file(Path(temporary.name), 'Cargo.lock')).hexdigest():
                                    raise ValueError('Runtime Cargo lock digest differs from archived source')
                            elif runtime['name'] in ['containerd', 'kubelet', 'crictl']:
                                updated = runtime['name'] in updates
                                vendor_key = 'upstream_go_vendor_modules' if updated else 'go_vendor_modules'
                                if runtime.get(vendor_key) != go_vendor_inventory(Path(temporary.name)):
                                    raise ValueError('Vendored Go source inventory differs')
                                if updated:
                                    input_key = 'upstream_go_build_inputs' if updated else 'go_build_inputs'
                                    if runtime.get(input_key) != go_build_inputs(Path(temporary.name), updates[runtime['name']]['manifests']):
                                        raise ValueError('Compiled Go input digests differ from archived source')
                                    if (runtime.get('go_build_inputs') != go_dependencies.build_inputs(updates[runtime['name']])
                                            or runtime.get('go_vendor_modules') != go_dependencies.vendor_modules(updates[runtime['name']])):
                                        raise ValueError('Patched Go source inventory differs from approved update')
                    elif digest not in proof_objects and hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                        raise ValueError('Source object checksum mismatch')
                    if 'size' in actual[digest] and member.size != actual[digest]['size']:
                        raise ValueError('Source object size mismatch')
            if decoder.wait():
                raise ValueError('Corresponding source decompression failed')
            if seen != {'source-index.json'} | {'objects/' + d for d in actual} or cargo_lock is None:
                raise ValueError('Incomplete corresponding source archive')
            for supplement in supplements:
                expected = supplemental_provenance(proof_cache, supplement, cargo_lock)
                if actual[supplement['sha256']].get('notice_provenance') != expected:
                    raise ValueError('Supplemental notice provenance differs from archived contents')
            for digest in proof_objects:
                if actual[digest].get('licenses') != license_evidence(proof_cache / digest,
                        lock.get('embedded_go_notices', {}).get(digest, [])):
                    raise ValueError('Supplemental notice inventory differs from archived contents')
        finally:
            if decoder.poll() is None:
                decoder.terminate(); decoder.wait()
    if any(e['sha256'] not in actual or any(actual[e['sha256']].get(k) != v for k, v in e.items()) for e in cargo_lock):
        raise ValueError('Missing or altered transitive Cargo source')
    return {'objects': len(actual), 'archive_sha256': sha256(archive), 'index_sha256': sha256(index_path)}


def bundle(cache, output, index):
    objects = {e['sha256']: e for e in index['entries']}
    destination = output / 'corresponding-source.tar.zst'
    temporary = destination.with_suffix('.partial')
    if temporary.exists() or temporary.is_symlink():
        raise ValueError('Remove interrupted source archive before regeneration')
    try:
        with subprocess.Popen(['zstd', '-T0', '-q', '-o', str(temporary)], stdin=subprocess.PIPE) as compressor:
            with tarfile.open(fileobj=compressor.stdin, mode='w|') as tar:
                for digest, entry in sorted(objects.items()):
                    path = fetch(cache, entry)
                    member = tarfile.TarInfo('objects/' + digest)
                    member.size = path.stat().st_size
                    member.mode = 0o644
                    with path.open('rb') as stream:
                        tar.addfile(member, stream)
                data = (json.dumps(index, indent=2) + '\n').encode()
                member = tarfile.TarInfo('source-index.json')
                member.size = len(data)
                member.mode = 0o644
                tar.addfile(member, io.BytesIO(data))
            compressor.stdin.close()
            if compressor.wait():
                raise ValueError('Source archive compression failed')
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return sha256(destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apt-inputs', type=Path)
    parser.add_argument('--download-only', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    apt_inputs = json.loads(args.apt_inputs.read_text()) if args.apt_inputs else None
    index = collect(args.cache, apt_inputs)
    (args.output / 'source-index.json').write_text(json.dumps(index, indent=2) + '\n')
    if not args.download_only:
        bundle(args.cache, args.output, index)
        verify(args.output, apt_inputs or {'sources': []})
