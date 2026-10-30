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
POLICY = ROOT / 'build/security/policy.json'
DEFAULT_IGNORE = ROOT / 'build/sbom/grype-default-ignore.json'
FILES = ('vulnerabilities.grype.json', 'vulnerability-database.json')
REPORT = 'security-review.json'


def exception_scope(identity):
    return {**{k: identity[k] for k in ['profile', 'hardware_profile', 'architecture', 'components_lock_sha256']},
            'inputs_lock_sha256': sha256(ROOT / 'build/inputs.lock.json'),
            'runtime_build_lock_sha256': sha256(ROOT / 'build/runtime/dragonfly.lock.json'),
            'go_runtime_build_lock_sha256': sha256(ROOT / 'build/runtime/crictl.lock.json'),
            'containerd_build_lock_sha256': sha256(ROOT / 'build/runtime/containerd.lock.json'),
            'kubelet_build_lock_sha256': sha256(ROOT / 'build/runtime/kubelet.lock.json'),
            'sources_lock_sha256': sha256(ROOT / 'build/sbom/sources.lock.json')}


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


def evaluate(scan, database, identity, policy, now):
    if policy.get('schema') != 1 or not policy.get('owner') or not policy.get('blocking_severities'):
        raise ValueError('Missing vulnerability review policy')
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
    exceptions = {}
    scope = exception_scope(identity)
    for e in policy['exceptions']:
        if (not re.fullmatch('[a-f0-9]{64}', e.get('finding_key', ''))
                or e.get('approved_by') not in policy['exception_approvers'] or not e.get('owner')
                or e.get('decision') not in ['not-affected', 'accepted-risk']
                or len(e.get('rationale', '')) < 40 or not e.get('evidence')
                or not all(str(u).startswith('https://') for u in e['evidence'])):
            raise ValueError('Unaccountable vulnerability exception')
        start, expires = time(e['reviewed_at']), time(e['expires_at'])
        if not start <= now < expires or expires - start > timedelta(days=policy['exception_max_days']):
            raise ValueError('Expired, future or overlong vulnerability exception')
        if e.get('scope') != scope:
            continue
        if e['finding_key'] in exceptions:
            raise ValueError('Duplicate vulnerability exception')
        exceptions[e['finding_key']] = e
    findings = [finding(m) for m in scan['matches']]
    if any(f['severity'] not in ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'] for f in findings):
        raise ValueError('Unrecognized vulnerability severity requires review')
    decisions = []
    used = set()
    for f in findings:
        exception = exceptions.get(f['key'])
        if exception:
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
        if sha256(actual) != database['sha256']:
            raise ValueError('Vulnerability database changed during scan')
        write_json(output / FILES[1], database)
    evaluation = evaluate(read_json(output / FILES[0]), database, identity, read_json(POLICY), datetime.now(timezone.utc))
    report = {'schema': 1, 'identity': identity, 'scanner': receipt,
              'scanner_lock_sha256': sha256(LOCK), 'scanner_config_sha256': sha256(CONFIG),
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
            or report.get('scanner_defaults_sha256') != sha256(DEFAULT_IGNORE)
            or report.get('policy_sha256') != sha256(POLICY)
            or report.get('sbom_sha256') != sha256(directory / 'distribution.sbom.syft.json')
            or set(report.get('files', {})) != set(FILES)):
        raise ValueError('Vulnerability evidence identity or policy differs')
    for name, digest in report['files'].items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256(path) != digest:
            raise ValueError('Vulnerability evidence integrity failure')
    evaluation = evaluate(read_json(directory / FILES[0]), read_json(directory / FILES[1]), identity,
                          read_json(POLICY), now or datetime.now(timezone.utc))
    if evaluation != report['review']:
        raise ValueError('Vulnerability decision differs from scanner evidence')
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
