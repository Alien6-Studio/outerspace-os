#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Scan immutable inventories offline and re-evaluate expiring release decisions."""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from profiles import ROOT, sha256
from sbom import read_json, write_json

LOCK = ROOT / 'build/sbom/grype.lock.json'
CONFIG = ROOT / 'build/sbom/grype.yaml'
KERNEL_CONFIG = ROOT / 'build/sbom/grype-kernel.yaml'
POLICY = ROOT / 'build/security/policy.json'
DEFAULT_IGNORE = ROOT / 'build/sbom/grype-default-ignore.json'
FILES = ('vulnerabilities.grype.json', 'vulnerability-database.json', 'kernel-vulnerabilities.grype.json')
REPORT = 'security-review.json'


def exception_scope(identity):
    return {**{k: identity[k] for k in ['profile', 'hardware_profile', 'architecture', 'components_lock_sha256']},
            'inputs_lock_sha256': sha256(ROOT / 'build/inputs.lock.json'),
            'runtime_build_lock_sha256': sha256(ROOT / 'build/runtime/dragonfly.lock.json'),
            'go_runtime_build_lock_sha256': sha256(ROOT / 'build/runtime/crictl.lock.json'),
            'containerd_build_lock_sha256': sha256(ROOT / 'build/runtime/containerd.lock.json'),
            'kubelet_build_lock_sha256': sha256(ROOT / 'build/runtime/kubelet.lock.json'),
            'sources_lock_sha256': sha256(ROOT / 'build/sbom/sources.lock.json'),
            'kernel_build_lock_sha256': sha256(ROOT / 'build/kernel/kernel.lock.json')}


def time(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Security timestamps require an explicit timezone')
    return parsed.astimezone(timezone.utc)


def finding(match):
    a, v = match['artifact'], match['vulnerability']
    value = {'id': v['id'], 'namespace': v['namespace'], 'package': a['name'],
             'version': a['version'], 'type': a['type'], 'purl': a.get('purl', ''),
             'paths': sorted({p['path'] for p in a.get('locations') or []})}
    value['key'] = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    value.update(severity=v['severity'], fix=v.get('fix', {}), advisory=v['dataSource'])
    return value


def validate_scan(scan, database, policy, now):
    descriptor = scan['descriptor']
    if descriptor['name'] != 'grype' or descriptor['version'] != read_json(LOCK)['version']:
        raise ValueError('Unapproved vulnerability scanner')
    built, scanned = time(database['built']), time(descriptor['timestamp'])
    if (database.get('valid') is not True or built > now + timedelta(minutes=5)
            or scanned > now + timedelta(minutes=5) or scanned < built
            or now - built > timedelta(hours=policy['database_max_age_hours'])
            or now - scanned > timedelta(hours=policy['scan_max_age_hours'])):
        raise ValueError('Invalid or stale vulnerability evidence; rescan the same candidate')
    if not re.fullmatch('[a-f0-9]{64}', database.get('sha256', '')):
        raise ValueError('Missing exact vulnerability database digest')
    # Pin the scanner's built-in header-only rules; none may hide an actual
    # match in this distribution. Exceptions belong to the reviewed policy.
    configuration = descriptor.get('configuration', {})
    if configuration.get('ignore') != read_json(DEFAULT_IGNORE) or scan.get('ignoredMatches'):
        raise ValueError('Unreviewed scanner ignore rules are prohibited')
    if any(configuration.get(k) for k in ['only-fixed', 'only-notfixed', 'ignore-wontfix', 'exclude', 'vex-documents']):
        raise ValueError('Filtered vulnerability scans cannot qualify an image')
    db_status = descriptor.get('db', {}).get('status', {})
    if any(db_status.get(k) != database.get(k) for k in ['schemaVersion', 'built', 'from', 'valid']):
        raise ValueError('Scan does not use the recorded vulnerability database')


def evaluate(scan, database, identity, policy, now, kernel_scan=None, compiled_exceptions=()):
    if policy.get('schema') != 1 or not policy.get('owner') or not policy.get('blocking_severities'):
        raise ValueError('Missing vulnerability review policy')
    for current in [scan] + ([kernel_scan] if kernel_scan is not None else []):
        validate_scan(current, database, policy, now)
    exceptions = {}
    scope = exception_scope(identity)
    kernel_release = read_json(ROOT / 'build/kernel/kernel.lock.json')['release']
    kernel_paths = {'/usr/lib/modules/' + kernel_release + '/vmlinuz', '/usr/lib/modules/' + kernel_release + '/config'}
    for e in [*policy['exceptions'], *compiled_exceptions]:
        if (not re.fullmatch('[a-f0-9]{64}', e.get('finding_sha256', ''))
                or e.get('approved_by') not in policy['exception_approvers'] or not e.get('owner')
                or e.get('decision') not in ['not-affected', 'accepted-risk']
                or len(e.get('rationale', '')) < 40 or not e.get('evidence')
                or not all(str(u).startswith('https://') for u in e['evidence'])):
            raise ValueError('Unaccountable vulnerability exception')
        binaries = e.get('binary_sha256', {})
        if not isinstance(binaries, dict) or any(
                not (re.fullmatch('/usr/s?bin/[A-Za-z0-9_.-]+', p) or p in kernel_paths)
                or not re.fullmatch('[a-f0-9]{64}', digest) for p, digest in binaries.items()):
            raise ValueError('Invalid vulnerability exception binary binding')
        start, expires = time(e['reviewed_at']), time(e['expires_at'])
        if not start <= now < expires or expires - start > timedelta(days=policy['exception_max_days']):
            raise ValueError('Expired, future or overlong vulnerability exception')
        if e.get('scope') != scope:
            continue
        if e['finding_sha256'] in exceptions:
            raise ValueError('Duplicate vulnerability exception')
        exceptions[e['finding_sha256']] = e
    findings = [finding(m) for current in [scan] + ([kernel_scan] if kernel_scan is not None else [])
                for m in current['matches']]
    if len({f['key'] for f in findings}) != len(findings):
        raise ValueError('Duplicate finding across vulnerability inventories')
    if any(f['severity'] not in ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'] for f in findings):
        raise ValueError('Unrecognized vulnerability severity requires review')
    decisions = []
    used = set()
    for f in findings:
        exception = exceptions.get(f['key'])
        if exception:
            if (f['package'] == 'linux_kernel'
                    and not kernel_paths.issubset(exception.get('binary_sha256', {}))):
                raise ValueError('Kernel decision must bind both compiled image and configuration')
            used.add(f['key'])
        blocked = f['severity'] in policy['blocking_severities'] and exception is None
        decisions.append({**f, 'decision': exception['decision'] if exception else
                          ('blocked' if blocked else 'below-release-threshold'),
                          'exception': exception, 'owner': exception['owner'] if exception else policy['owner']})
    if set(exceptions) != used:
        raise ValueError('Unused scoped exception must be removed or re-reviewed')
    return {'status': 'blocked' if any(d['decision'] == 'blocked' for d in decisions) else 'passed',
            'counts': dict(sorted(Counter(d['severity'] for d in decisions).items())),
            'decisions': decisions, 'automatic_ignored_matches': len(scan.get('ignoredMatches', []))}


def review(directory, identity, policy, now):
    import kernel_review
    import runtime_review
    scan = read_json(directory / FILES[0])
    kernel_scan = read_json(directory / FILES[2])
    compiled = kernel_review.materialize(directory, identity, kernel_scan, policy,
                                         exception_scope(identity), finding)
    compiled += runtime_review.materialize(directory, identity, scan, policy,
                                          exception_scope(identity), finding)
    return evaluate(scan, read_json(directory / FILES[1]), identity,
                    policy, now, kernel_scan=kernel_scan, compiled_exceptions=compiled)


def verify_exception_binaries(directory, review):
    bindings = [d['exception']['binary_sha256'] for d in review['decisions']
                if d.get('exception') and d['exception'].get('binary_sha256')]
    if not bindings:
        return
    files = read_json(directory / 'distribution.sbom.syft.json')['files']
    for binding in bindings:
        for path, digest in binding.items():
            matches = [f for f in files if f['location']['path'] == path]
            if (len(matches) != 1 or matches[0]['metadata']['type'] != 'RegularFile'
                    or [d['value'] for d in matches[0].get('digests', []) if d['algorithm'] == 'sha256'] != [digest]):
                raise ValueError('Vulnerability exception does not apply to these executable bytes')


def scanner_receipt(identity):
    scanner = Path('/usr/local/bin/grype')
    receipt = read_json(scanner.with_suffix('.json'))
    lock = read_json(LOCK)
    if (receipt['version'] != lock['version'] or receipt['architecture'] != identity['architecture']
            or receipt['artifact'] != lock['artifacts'][identity['architecture']]
            or receipt['binary_sha256'] != sha256(scanner)):
        raise ValueError('Vulnerability scanner differs from approved input')
    return receipt


def scan(output, database_path):
    identity = read_json(output / 'build-identity.json')
    receipt = scanner_receipt(identity)
    (output / REPORT).unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix='outerspace-grype-') as temporary:
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': temporary, 'LANG': 'C.UTF-8',
               'GRYPE_DB_CACHE_DIR': str(database_path)}
        # Network refresh is a separate command; scan always disables auto-update.
        database = json.loads(subprocess.check_output(['grype', 'db', 'status', '-o', 'json',
            '--config', str(CONFIG)], env=env, text=True))
        actual = Path(database['path'])
        if not actual.resolve().is_relative_to(database_path.resolve()) or actual.is_symlink():
            raise ValueError('Unexpected vulnerability database path')
        database['sha256'] = sha256(actual)
        with (output / FILES[0]).open('w') as stream:
            subprocess.run(['grype', 'sbom:' + str(output / 'distribution.sbom.syft.json'),
                '--config', str(CONFIG), '-o', 'json'], env=env, stdout=stream, check=True)
        with (output / FILES[2]).open('w') as stream:
            subprocess.run(['grype', 'sbom:' + str(output / 'kernel.sbom.syft.json'),
                '--config', str(KERNEL_CONFIG), '-o', 'json'], env=env, stdout=stream, check=True)
        if sha256(actual) != database['sha256']:
            raise ValueError('Vulnerability database changed during scan')
        write_json(output / FILES[1], database)
    evaluation = review(output, identity, read_json(POLICY), datetime.now(timezone.utc))
    verify_exception_binaries(output, evaluation)
    report = {'schema': 1, 'identity': identity, 'scanner': receipt,
              'scanner_lock_sha256': sha256(LOCK), 'scanner_config_sha256': sha256(CONFIG),
              'kernel_scanner_config_sha256': sha256(KERNEL_CONFIG),
              'kernel_sbom_sha256': sha256(output / 'kernel.sbom.syft.json'),
              'scanner_defaults_sha256': sha256(DEFAULT_IGNORE),
              'policy_sha256': sha256(POLICY), 'sbom_sha256': sha256(output / 'distribution.sbom.syft.json'),
              'files': {n: sha256(output / n) for n in FILES}, 'review': evaluation}
    write_json(output / REPORT, report)
    print(json.dumps({'status': evaluation['status'], 'counts': evaluation['counts']}, indent=2))


def verify(directory, identity, require_pass=False, now=None):
    report = read_json(directory / REPORT)
    if (report.get('schema') != 1 or report.get('identity') != identity
            or report.get('scanner_lock_sha256') != sha256(LOCK)
            or report.get('scanner_config_sha256') != sha256(CONFIG)
            or report.get('kernel_scanner_config_sha256') != sha256(KERNEL_CONFIG)
            or report.get('kernel_sbom_sha256') != sha256(directory / 'kernel.sbom.syft.json')
            or report.get('scanner_defaults_sha256') != sha256(DEFAULT_IGNORE)
            or report.get('policy_sha256') != sha256(POLICY)
            or report.get('sbom_sha256') != sha256(directory / 'distribution.sbom.syft.json')
            or set(report.get('files', {})) != set(FILES)):
        raise ValueError('Vulnerability evidence identity or policy differs')
    for name, digest in report['files'].items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256(path) != digest:
            raise ValueError('Vulnerability evidence integrity failure')
    evaluation = review(directory, identity, read_json(POLICY), now or datetime.now(timezone.utc))
    if evaluation != report['review']:
        raise ValueError('Vulnerability decision differs from scanner evidence')
    verify_exception_binaries(directory, evaluation)
    receipt, lock = report['scanner'], read_json(LOCK)
    if (receipt['version'] != lock['version'] or receipt['architecture'] != identity['architecture']
            or receipt['artifact'] != lock['artifacts'][identity['architecture']]
            or not re.fullmatch('[a-f0-9]{64}', receipt['binary_sha256'])):
        raise ValueError('Vulnerability scanner receipt differs')
    if require_pass and evaluation['status'] != 'passed':
        raise ValueError('Unresolved vulnerability findings block promotion')
    return {'report_sha256': sha256(directory / REPORT), 'status': evaluation['status'], 'counts': evaluation['counts']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--database', type=Path, default=Path('/cache/grype-db'))
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--require-pass', action='store_true')
    args = parser.parse_args()
    if not args.verify:
        scan(args.output, args.database)
    verify(args.output, read_json(args.output / 'build-identity.json'), args.require_pass)
