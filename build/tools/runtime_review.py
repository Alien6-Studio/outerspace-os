# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Recheck previously approved runtime facts against each CPU image's bytes."""
import go_runtime_build
import runtime_build
from profiles import ROOT, sha256
from sbom import read_json
from kernel_review import digest

MATERIALS = ('build/inputs.lock.json', 'build/runtime/dragonfly.lock.json',
             'build/runtime/crictl.lock.json', 'build/runtime/crictl-dependencies.lock.json',
             'build/tools/runtime_build.py', 'build/tools/go_runtime_build.py',
             'build/tools/go_dependencies.py', 'build/sbom/sources.lock.json')
SELECTOR = ('id', 'namespace', 'package', 'version', 'type', 'paths')


def material_identity():
    return {name: sha256(ROOT / name) for name in MATERIALS}


def predicates(case, directory, identity, raw, apt):
    files = {f['location']['path']: f for f in raw['files']}
    bindings = {}
    for path in case['binary_paths']:
        f = files.get(path, {})
        hashes = [d['value'] for d in f.get('digests', []) if d['algorithm'] == 'sha256']
        if f.get('metadata', {}).get('type') != 'RegularFile' or len(hashes) != 1:
            raise ValueError('Reviewed runtime executable is missing or ambiguous')
        bindings[path] = hashes[0]
    kind = case['predicate']
    if kind in ('fixed-runc-source', 'windows-only-go'):
        packages = [p for p in apt['packages'] if p['name'] == 'runc']
        expected = {'name': 'runc', 'version': '1.3.4-0ubuntu1~24.04.1',
                    'source': 'runc-app', 'source_version': '1.3.4-0ubuntu1~24.04.1',
                    'architecture': identity['architecture']}
        if (len(packages) != 1 or any(packages[0].get(k) != v for k, v in expected.items())
                or any(apt['executable_owners'].get(path) != 'runc'
                       or files[path].get('executable', {}).get('format') != 'elf' for path in bindings)):
            raise ValueError('Reviewed signed Linux runc package does not match')
    elif kind == 'dnssec-not-compiled':
        report = runtime_build.verify_receipt(directory, identity['architecture'], packaged=True)
        features = {}
        for package in case['compiled_features']:
            entries = [a for a in report['compiled_artifacts'] if a['package_id'].endswith('#' + package)]
            if len(entries) != 1:
                raise ValueError('Missing or ambiguous DNSSEC compilation evidence')
            features[package] = sorted(entries[0]['features'])
        if (features != case['compiled_features'] or bindings != {'/usr/bin/dfdaemon': report['binary_sha256']}):
            raise ValueError('DNSSEC compilation or runtime bytes changed')
    elif kind == 'docker-daemon-absent':
        report = go_runtime_build.verify_receipt(directory, identity['architecture'], packaged=True)
        modules = [a for a in raw['artifacts'] if a['name'] == 'github.com/docker/docker'
                   and [p['path'] for p in a['locations']] == ['/usr/bin/crictl']]
        if (bindings != {'/usr/bin/crictl': report['binary_sha256']} or len(modules) != 1
                or sorted(modules[0].get('metadata', {}).get('symbols', {})) != case['compiled_packages']):
            raise ValueError('Docker API-only dependency proof changed')
    else:
        raise ValueError('Unsupported runtime review predicate')
    return bindings


def materialize(directory, identity, scan, policy, scope, finding):
    reviews = policy.get('runtime_reviews', [])
    if (not reviews or identity['hardware_profile'] != 'cpu' or identity['profile'] not in ('agent', 'inference')
            or identity['architecture'] not in ('amd64', 'arm64')):
        return []
    raw = read_json(directory / 'distribution.sbom.syft.json')
    apt = read_json(directory / 'apt-inputs.json')
    result = []
    for review in reviews:
        if (review.get('schema') != 1 or review.get('scope') != {'hardware_profile': 'cpu',
                'profiles': ['agent', 'inference'], 'architectures': ['amd64', 'arm64']}
                or review.get('approved_by') not in policy['exception_approvers']):
            raise ValueError('Unaccountable runtime source review')
        if review.get('materials') != material_identity():
            continue
        for match in scan['matches']:
            f = finding(match)
            selected = [c for c in review['cases'] if c['selector'] == {k: f[k] for k in SELECTOR}]
            if not selected:
                continue
            if len(selected) != 1:
                raise ValueError('Ambiguous runtime review')
            case = selected[0]
            bindings = predicates(case, directory, identity, raw, apt)
            result.append({**{k: review[k] for k in ['approved_by', 'owner', 'reviewed_at', 'expires_at']},
                **{k: case[k] for k in ['decision', 'rationale', 'evidence']},
                'finding_sha256': f['key'], 'advisory': f['id'], 'scope': scope,
                'binary_sha256': bindings, 'source_review_sha256': digest(review)})
    return result
