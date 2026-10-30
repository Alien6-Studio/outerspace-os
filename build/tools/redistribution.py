#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Prepare a source-bound notice review; never equate detection with approval."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

from profiles import ROOT, sha256
from sbom import read_json, write_json

POLICY = ROOT / 'build/licenses/reviews.json'
REPORT = 'redistribution-review.json'


def notice_decisions(identity, index, reviews):
    """Resolve only an approved source/license choice, never the whole image."""
    resolved = {}
    entries = {e['sha256']: e for e in index['entries']}
    for decision in reviews.get('notice_decisions', []):
        digest = decision.get('source_sha256', '')
        license_file = decision.get('distributed_license', {})
        approved_at = datetime.fromisoformat(decision['approved_at'].replace('Z', '+00:00'))
        if (not re.fullmatch('[a-f0-9]{64}', digest)
                or decision.get('approved_by') not in reviews['approvers']
                or approved_at.tzinfo is None or decision.get('scope') != {'hardware_profile': 'cpu'}
                or decision.get('decision') != 'select-declared-license'
                or len(decision.get('rationale', '')) < 80 or not decision.get('evidence')
                or not all(str(u).startswith('https://') for u in decision['evidence'])
                or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]*', license_file.get('path', ''))
                or not re.fullmatch('[a-f0-9]{64}', license_file.get('sha256', ''))):
            raise ValueError('Incomplete or unaccountable source notice decision')
        if digest not in entries or identity['hardware_profile'] != 'cpu':
            continue
        entry = entries[digest]
        declared = entry.get('licenses', {}).get('declared_licenses', [])
        # This intentionally accepts only a simple OR of atomic SPDX identifiers.
        # AND, WITH and parenthesized expressions require a separate full review.
        expression = decision.get('declared_license', '')
        selected = decision.get('selected_license', '')
        if (entry['name'] != decision.get('name') or entry.get('version') != decision.get('version')
                or expression not in declared
                or not re.fullmatch('[A-Za-z0-9.-]+(?: OR [A-Za-z0-9.-]+)*', expression)
                or selected not in expression.split(' OR ')):
            raise ValueError('Selected license is not granted by the exact source archive')
        if digest in resolved:
            raise ValueError('Ambiguous source notice decision')
        resolved[digest] = decision
    return resolved


def verify_notice_files(directory, review):
    for decision in review['resolved_notice_decisions']:
        notice = decision['distributed_license']
        path = directory / notice['path']
        if path.is_symlink() or not path.is_file() or sha256(path) != notice['sha256']:
            raise ValueError('Selected license text is missing or changed')


def assess(identity, apt, index, reviews):
    # Notice content, not tar timestamps, determines whether a review applies.
    scope = {k: identity[k] for k in ['profile', 'hardware_profile', 'architecture', 'components_lock_sha256']}
    subject = {'scope': scope, 'source_lock_sha256': index['source_lock_sha256'],
               'apt': [{k: p[k] for k in ['name', 'version', 'source', 'source_version', 'notice_sha256']}
                       for p in apt['packages']],
               'sources': sorted({e['sha256'] for e in index['entries']})}
    digest = hashlib.sha256(json.dumps(subject, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    recovered = {digest for e in index['entries'] if e['kind'] == 'supplemental-notice-source'
                 and e.get('licenses', {}).get('notices') for digest in e['for_crates']}
    recovered_payloads = {p['payload_sha256'] for e in index['entries']
                          if e['kind'] == 'supplemental-notice-source' and e.get('licenses', {}).get('notices')
                          for p in e.get('notice_provenance', {}).values()
                          if p.get('basis') == 'complete-upstream-release-payload-match' and p.get('notices')}
    missing_notices = [{'name': e['name'], 'version': e.get('version'), 'sha256': e['sha256']}
                       # Go proxy metadata accompanies its complete module ZIP,
                       # whose original notices are assessed separately.
                       for e in index['entries'] if e['kind'] not in ['ubuntu-source', 'go-module-metadata']
                       and e['sha256'] not in (recovered | recovered_payloads) and not e.get('licenses', {}).get('notices')]
    resolved = notice_decisions(identity, index, reviews)
    unresolved = [e for e in missing_notices if e['sha256'] not in resolved]
    matching = [r for r in reviews['reviews'] if r.get('subject_sha256') == digest]
    if len(matching) > 1:
        raise ValueError('Ambiguous redistribution review')
    approval = matching[0] if matching else None
    if approval is not None:
        if (approval.get('approved_by') not in reviews['approvers']
                or approval.get('decision') != 'redistributable'
                or len(approval.get('rationale', '')) < 80 or not approval.get('evidence')
                or not all(str(u).startswith('https://') for u in approval['evidence'])
                or approval.get('unresolved_notices') != []
                or set(approval.get('notice_resolutions', {})) != {e['sha256'] for e in unresolved}):
            raise ValueError('Incomplete or unaccountable redistribution approval')
        for resolution in approval['notice_resolutions'].values():
            if (not isinstance(resolution, dict) or len(resolution.get('rationale', '')) < 40
                    or not resolution.get('evidence')
                    or not all(str(u).startswith('https://') for u in resolution['evidence'])):
                raise ValueError('Missing source-specific notice resolution evidence')
    return {'status': 'passed' if approval else 'review-required', 'subject_sha256': digest,
            'subject': subject, 'approval': approval, 'source_objects': len(subject['sources']),
            'apt_notices': len(apt['packages']), 'source_archives_without_notice_files': missing_notices,
            'resolved_notice_decisions': [resolved[digest] for digest in sorted(resolved)],
            'unresolved_source_notices': unresolved,
            'crates_with_recovered_notices': len(recovered),
            'obligations': ['Distribute corresponding-source.tar.zst and original source.tar.zst alongside binaries.',
                            'Keep APT copyright/common-license notices and upstream vendored LICENSE/NOTICE files.',
                            'Review license conditions and any missing notice evidence before public distribution.',
                            'Apache-2.0 covers original project code, not the Ubuntu distribution or upstream dependencies.'],
            'rust_limit': index['cargo_relationship']}


def generate(output):
    identity = read_json(output / 'build-identity.json')
    review = assess(identity, read_json(output / 'apt-inputs.json'), read_json(output / 'source-index.json'), read_json(POLICY))
    verify_notice_files(output, review)
    write_json(output / REPORT, {'schema': 1, 'identity': identity, 'policy_sha256': sha256(POLICY),
                                'review': review})


def verify(directory, identity, require_pass=False):
    report = read_json(directory / REPORT)
    expected = assess(identity, read_json(directory / 'apt-inputs.json'), read_json(directory / 'source-index.json'), read_json(POLICY))
    verify_notice_files(directory, expected)
    if (report.get('schema') != 1 or report.get('identity') != identity
            or report.get('policy_sha256') != sha256(POLICY) or report.get('review') != expected):
        raise ValueError('Redistribution review does not apply to this image')
    if require_pass and expected['status'] != 'passed':
        raise ValueError('Corresponding-source and notice review required before publication')
    return {'report_sha256': sha256(directory / REPORT), 'status': expected['status'],
            'subject_sha256': expected['subject_sha256']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--require-pass', action='store_true')
    args = parser.parse_args()
    if not args.verify:
        generate(args.output)
    verify(args.output, read_json(args.output / 'build-identity.json'), args.require_pass)
