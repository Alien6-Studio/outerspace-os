#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Check live default-branch Dependabot alerts before expensive candidate work."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
SHA = re.compile(r'[a-f0-9]{40}')
DIGEST = re.compile(r'[a-f0-9]{64}')


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (AttributeError, TypeError, ValueError):
        raise ValueError('Invalid review timestamp') from None
    if result.tzinfo is None:
        raise ValueError('Review timestamps require a timezone')
    return result.astimezone(timezone.utc)


def material_paths(manifest):
    path = PurePosixPath(manifest)
    if (path.is_absolute() or str(path) != manifest or any(p in ('', '.', '..') for p in path.parts)
            or not path.parts):
        raise ValueError('Unsafe Dependabot manifest path')
    required = {manifest, 'build/inputs.lock.json', 'build/sbom/sources.lock.json'}
    for component in ('containerd', 'crictl', 'kubelet'):
        if manifest.startswith('build/runtime/' + component + '/'):
            required.update({'build/runtime/' + component + '.lock.json',
                             'build/runtime/' + component + '-dependencies.lock.json',
                             'build/tools/go_runtime_build.py', 'build/tools/go_dependencies.py',
                             'build/tools/runtime_build.py'})
    return required


def material_digests(root, manifest):
    result = {}
    for name in sorted(material_paths(manifest)):
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Missing or unsafe review material: ' + name)
        if not path.exists():
            if name == manifest or re.fullmatch(r'build/runtime/(containerd|crictl|kubelet)(-dependencies)?\.lock\.json', name):
                result[name] = 'absent'
                continue
            raise ValueError('Missing or unsafe review material: ' + name)
        if not path.is_file():
            raise ValueError('Missing or unsafe review material: ' + name)
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def alert_record(alert):
    try:
        package = alert['dependency']['package']['name']
        manifest = alert['dependency']['manifest_path']
        advisory = alert['security_advisory']
        severities = [alert['security_vulnerability'].get('severity'), advisory.get('severity')]
        ranks = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3, 'unknown': 4}
        normalized = [value.lower() if isinstance(value, str) and value.lower() in ranks else 'unknown'
                      for value in severities]
        severity = max(normalized, key=lambda value: ranks[value])
        record = {'number': alert['number'], 'state': alert['state'], 'ghsa': advisory['ghsa_id'],
                  'package': package, 'manifest': manifest, 'severity': severity,
                  'advisory_updated_at': advisory['updated_at'],
                  'alert_updated_at': alert['updated_at'],
                  'vulnerable_range': alert['security_vulnerability']['vulnerable_version_range'],
                  'first_patched_version': (alert['security_vulnerability'].get('first_patched_version') or {}).get('identifier'),
                  'url': alert['html_url']}
    except (KeyError, TypeError, AttributeError):
        raise ValueError('Incomplete Dependabot alert') from None
    if (not isinstance(record['number'], int) or record['number'] < 1
            or record['state'] not in ('open', 'dismissed', 'auto_dismissed')
            or not re.fullmatch(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', record['ghsa'])
            or not isinstance(package, str) or not package or not isinstance(manifest, str)
            or not isinstance(record['vulnerable_range'], str) or not record['vulnerable_range'].strip()
            or urlsplit(record['url']).scheme != 'https'):
        raise ValueError('Invalid Dependabot alert')
    timestamp(record['advisory_updated_at'])
    timestamp(record['alert_updated_at'])
    material_paths(manifest)
    if record['severity'] not in ('critical', 'high', 'medium', 'low'):
        record['severity'] = 'unknown'
    return record


def target_go_version(root, record):
    """Show the target lock's selected version; this is not a vulnerability decision."""
    for component in ('containerd', 'crictl', 'kubelet'):
        if record['manifest'].startswith('build/runtime/' + component + '/'):
            try:
                data = json.loads((root / 'build/runtime' / (component + '-dependencies.lock.json')).read_text())
                if data.get('schema') != 1 or data.get('component') != component:
                    return None
                matches = [module['version'] for module in data['modules'] if module['path'] == record['package']]
                return matches[0] if len(matches) == 1 and isinstance(matches[0], str) else None
            except (OSError, KeyError, TypeError, ValueError):
                return None
    return None


def reviewed(record, review, root, policy, now):
    expected = {'number': record['number'], 'ghsa': record['ghsa'],
                'package': record['package'], 'manifest': record['manifest'],
                'severity': record['severity'], 'advisory_updated_at': record['advisory_updated_at'],
                'alert_updated_at': record['alert_updated_at'], 'vulnerable_range': record['vulnerable_range']}
    if any(review.get(key) != value for key, value in expected.items()):
        return False
    if (review.get('decision') not in ('not-affected', 'accepted-risk')
            or review.get('approved_by') not in policy['exception_approvers']
            or not isinstance(review.get('owner'), str) or not review['owner'].strip()
            or not isinstance(review.get('rationale'), str) or len(review['rationale'].strip()) < 30):
        return False
    evidence = review.get('evidence')
    if (not isinstance(evidence, list) or not evidence or any(
            not isinstance(item, str) or urlsplit(item).scheme != 'https' or not urlsplit(item).netloc
            for item in evidence)):
        return False
    try:
        start, end = timestamp(review.get('reviewed_at')), timestamp(review.get('expires_at'))
        materials = material_digests(root, record['manifest'])
    except ValueError:
        return False
    if not (start <= now < end and end - start <= timedelta(days=policy['exception_max_days'])):
        return False
    return review.get('materials') == materials


def evaluate(alerts, reviews, root, policy, now):
    if not isinstance(alerts, list) or reviews.get('schema') != 1 or not isinstance(reviews.get('reviews'), list):
        raise ValueError('Invalid alert or review list')
    approvers = policy.get('exception_approvers')
    days = policy.get('exception_max_days')
    levels = policy.get('blocking_severities')
    if (not isinstance(approvers, list) or not approvers or not isinstance(days, int) or not 0 < days <= 30
            or not isinstance(levels, list) or any(not isinstance(level, str) for level in levels)):
        raise ValueError('Invalid security review policy')
    blocked_levels = {level.lower() for level in levels}
    if (not {'critical', 'high', 'unknown'} <= blocked_levels
            or not blocked_levels <= {'critical', 'high', 'medium', 'low', 'unknown'}):
        raise ValueError('Security policy must block Critical, High and Unknown findings')
    by_number = {}
    for review in reviews['reviews']:
        if not isinstance(review, dict) or not isinstance(review.get('number'), int) or review['number'] in by_number:
            raise ValueError('Invalid or duplicate Dependabot review')
        by_number[review['number']] = review
    records, seen = [], set()
    for raw in alerts:
        record = alert_record(raw)
        if timestamp(record['advisory_updated_at']) > now or timestamp(record['alert_updated_at']) > now:
            raise ValueError('Dependabot alert timestamp is in the future')
        if record['number'] in seen:
            raise ValueError('Duplicate Dependabot alert')
        seen.add(record['number'])
        record['target_version'] = target_go_version(root, record)
        record['decision'] = 'unreviewed'
        review = by_number.get(record['number'])
        if review and reviewed(record, review, root, policy, now):
            record['decision'] = review['decision']
            record['expires_at'] = review['expires_at']
        records.append(record)
    blockers = [r['number'] for r in records
                if r['severity'] in blocked_levels and r['decision'] == 'unreviewed']
    return {'status': 'blocked' if blockers else 'pass', 'blockers': blockers,
            'alerts': sorted(records, key=lambda r: r['number'])}


def gh_json(*args):
    result = subprocess.run(['gh', 'api', *args], capture_output=True, text=True)
    if result.returncode:
        raise ValueError('GitHub API unavailable or token lacks Dependabot alerts read permission')
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ValueError('GitHub API returned invalid JSON') from None


def require_alerts_enabled(repo):
    result = subprocess.run(['gh', 'api', '--silent', 'repos/' + repo + '/vulnerability-alerts'],
                            capture_output=True, text=True)
    if result.returncode:
        raise ValueError('Dependabot alerts disabled or token lacks administration read permission')


def github_snapshot(repo, commit, *, preview=False):
    if not REPO.fullmatch(repo) or not SHA.fullmatch(commit):
        raise ValueError('Expected repository owner/name and full commit SHA')
    metadata = gh_json('repos/' + repo)
    require_alerts_enabled(repo)
    branch = metadata.get('default_branch')
    if not isinstance(branch, str) or not branch:
        raise ValueError('Missing GitHub default branch')
    endpoint = 'repos/' + repo + '/commits/' + quote(branch, safe='')
    default_head = gh_json(endpoint).get('sha')
    if not isinstance(default_head, str) or not SHA.fullmatch(default_head):
        raise ValueError('Missing default branch commit')
    if not preview and default_head != commit:
        raise ValueError('Candidate must match the current default branch for Dependabot alert scope')
    pages = gh_json('--paginate', '--slurp', 'repos/' + repo
                    + '/dependabot/alerts?state=open,dismissed,auto_dismissed&per_page=100')
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ValueError('Invalid paginated Dependabot alert response')
    if gh_json(endpoint).get('sha') != default_head:
        raise ValueError('Default branch changed while reading Dependabot alerts')
    return branch, default_head, [item for page in pages for item in page]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--preview', action='store_true', help='Report default-branch alerts without qualifying this commit')
    args = parser.parse_args()
    try:
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        if head != args.commit:
            raise ValueError('Checked-out source does not match the candidate commit')
        dirty = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT, text=True)
        if dirty:
            raise ValueError('Dependabot preflight requires a clean committed source tree')
        branch, default_head, alerts = github_snapshot(args.repo, args.commit, preview=args.preview)
        now = datetime.now(timezone.utc)
        result = evaluate(alerts, json.loads((ROOT / 'build/release/dependabot-reviews.json').read_text()),
                          ROOT, json.loads((ROOT / 'build/security/policy.json').read_text()), now)
        report = {'schema': 1, 'repository': args.repo, 'default_branch': branch,
                  'default_branch_commit': default_head, 'commit': args.commit, 'preview': args.preview,
                  'evaluated_at': now.isoformat(), **result}
        if args.preview:
            report['status'] = 'preview'
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'alerts': len(result['alerts']),
                          'blocking_alerts': result['blockers'], 'report': str(args.report)}))
        if result['blockers'] and not args.preview:
            parser.exit(1, 'Dependabot preflight blocked: review or fix the listed alerts.\n')
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError, TypeError) as exc:
        parser.exit(1, 'Dependabot preflight refused: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
