#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Prepare a source-bound notice review; never equate detection with approval."""
import argparse
import hashlib
import json
from pathlib import Path

from profiles import ROOT, sha256
from sbom import read_json, write_json

POLICY = ROOT / 'build/licenses/reviews.json'
REPORT = 'redistribution-review.json'


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
    missing_notices = [{'name': e['name'], 'version': e.get('version'), 'sha256': e['sha256']}
                       for e in index['entries'] if e['kind'] != 'ubuntu-source'
                       and e['sha256'] not in recovered and not e.get('licenses', {}).get('notices')]
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
                or set(approval.get('notice_resolutions', {})) != {e['sha256'] for e in missing_notices}):
            raise ValueError('Incomplete or unaccountable redistribution approval')
        for resolution in approval['notice_resolutions'].values():
            if (not isinstance(resolution, dict) or len(resolution.get('rationale', '')) < 40
                    or not resolution.get('evidence')
                    or not all(str(u).startswith('https://') for u in resolution['evidence'])):
                raise ValueError('Missing source-specific notice resolution evidence')
    return {'status': 'passed' if approval else 'review-required', 'subject_sha256': digest,
            'subject': subject, 'approval': approval, 'source_objects': len(subject['sources']),
            'apt_notices': len(apt['packages']), 'source_archives_without_notice_files': missing_notices,
            'crates_with_recovered_notices': len(recovered),
            'obligations': ['Distribute corresponding-source.tar.zst and original source.tar.zst alongside binaries.',
                            'Keep APT copyright/common-license notices and upstream vendored LICENSE/NOTICE files.',
                            'Review license conditions and any missing notice evidence before public distribution.',
                            'Apache-2.0 covers original project code, not the Ubuntu distribution or upstream dependencies.'],
            'rust_limit': index['cargo_relationship']}


def generate(output):
    identity = read_json(output / 'build-identity.json')
    review = assess(identity, read_json(output / 'apt-inputs.json'), read_json(output / 'source-index.json'), read_json(POLICY))
    write_json(output / REPORT, {'schema': 1, 'identity': identity, 'policy_sha256': sha256(POLICY),
                                'review': review})


def verify(directory, identity, require_pass=False):
    report = read_json(directory / REPORT)
    expected = assess(identity, read_json(directory / 'apt-inputs.json'), read_json(directory / 'source-index.json'), read_json(POLICY))
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
