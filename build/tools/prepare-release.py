#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Validate external qualification evidence and stage immutable CI candidates."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tarfile
from package import sha256
from release import ROOT, validate_release, parse_version, release_notes
from sbom import verify_inventory
import supply_chain
import security
import attestations
import redistribution
import dependabot_preflight


def dependabot_accepted_risks(report, repo, commit):
    """Surface explicitly accepted Dependabot risks in the draft release notes."""
    if (report.get('schema') != 1 or report.get('repository') != repo
            or report.get('commit') != commit or report.get('default_branch_commit') != commit
            or report.get('preview') is not False or report.get('status') != 'pass'
            or report.get('blockers') != [] or not isinstance(report.get('alerts'), list)):
        raise ValueError('A passing current-source Dependabot promotion report is required')
    now = datetime.now(timezone.utc)
    checked = dependabot_preflight.timestamp(report.get('evaluated_at'))
    if not 0 <= (now - checked).total_seconds() <= 900:
        raise ValueError('Dependabot promotion report must be recent')
    result = set()
    for item in report['alerts']:
        if (not isinstance(item, dict) or item.get('decision') not in ('unreviewed', 'not-affected', 'accepted-risk')
                or item.get('severity') not in ('critical', 'high', 'medium', 'low', 'unknown')
                or (item.get('severity') in ('critical', 'high', 'unknown') and item['decision'] == 'unreviewed')):
            raise ValueError('Invalid or unreviewed Dependabot finding in promotion report')
        if item['decision'] != 'unreviewed' and dependabot_preflight.timestamp(item.get('expires_at')) <= now:
            raise ValueError('Dependabot review has expired')
        if item.get('decision') == 'accepted-risk':
            review = item.get('review', {})
            if (not isinstance(review.get('rationale'), str) or not review['rationale'].strip()
                    or not isinstance(review.get('approved_by'), str) or not review['approved_by'].strip()
                    or not isinstance(item.get('expires_at'), str)
                    or not re.fullmatch(r'GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', item.get('ghsa', ''))):
                raise ValueError('Incomplete accepted Dependabot risk in promotion report')
            result.add(f"{item['ghsa']} (approved by {review['approved_by']}, expires {item['expires_at']}): {review['rationale']}")
    return result


def gh_json(*args):
    return json.loads(subprocess.check_output(['gh', *args], text=True))


def verify_bundle(bundle, version, commit, artifact, *, development=False):
    if development and parse_version(version) != 'dev':
        raise ValueError('Only development images may be tested with unresolved release reviews')
    if (bundle / 'build-metadata.json').is_symlink():
        raise ValueError('Candidate metadata must not be a symlink')
    metadata = json.loads((bundle / 'build-metadata.json').read_text())
    identity = metadata.get('identity', {})
    if (metadata.get('schema') != 2 or identity != artifact['identity']
            or (identity.get('version'), identity.get('commit')) != (version, commit)):
        raise ValueError('Candidate inventory does not match the qualified release')
    inventory = bundle / 'SHA256SUMS'
    if inventory.is_symlink() or sha256(inventory) != artifact.get('sha256sums'):
        raise ValueError('Evidence must bind the exact SHA256SUMS of each candidate')
    listed = set()
    for line in inventory.read_text().splitlines():
        digest, name = line.split('  ', 1)
        if not re.fullmatch(r'[0-9a-f]{64}', digest) or Path(name).name != name or name in {'.', '..'}:
            raise ValueError('Invalid checksum inventory')
        path = bundle / name
        if path.is_symlink() or not path.is_file() or sha256(path) != digest:
            raise ValueError(f'Candidate integrity failure: {name}')
        if name in listed:
            raise ValueError('Duplicate checksum entry')
        listed.add(name)
    if listed | {'SHA256SUMS'} != {p.name for p in bundle.iterdir()}:
        raise ValueError('Unverified extra file in candidate bundle')
    manifests = list(bundle.glob('*.manifest'))
    if len(manifests) != 1:
        raise ValueError('Exactly one installed package manifest is required')
    if metadata.get('supply_chain') != verify_inventory(bundle, identity, manifests[0], bundle / 'components.lock.json'):
        raise ValueError('Candidate SBOM differs from qualified inventory')
    if metadata.get('distribution_inventory') != supply_chain.verify(bundle, identity, manifests[0]):
        raise ValueError('Candidate sources or provenance differ')
    if metadata.get('security_review') != security.verify(bundle, identity, require_pass=not development):
        raise ValueError('Candidate security review differs')
    if metadata.get('redistribution_review') != redistribution.verify(bundle, identity, require_pass=not development):
        raise ValueError('Candidate redistribution review differs')


def main():
    tag = os.environ['TAG']
    run_id = os.environ['CANDIDATE_RUN']
    if not re.fullmatch(r'[1-9][0-9]*', run_id):
        raise ValueError('Expected numeric candidate workflow run ID')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    version = (ROOT / 'VERSION').read_text().strip()
    evidence = json.loads(os.environ['EVIDENCE_JSON'])
    policy = json.loads((ROOT / 'build/release/policy.json').read_text())
    validate_release(version, tag, commit, evidence, policy)
    dependabot = json.loads((ROOT / 'out/dependabot-promotion.json').read_text())
    dependabot_risks = dependabot_accepted_risks(dependabot, os.environ['GH_REPO'], commit)
    if str(evidence.get('candidate_run')) != run_id:
        raise ValueError('Evidence must qualify this candidate run, not just its source commit')
    run = gh_json('api', f'repos/{os.environ["GH_REPO"]}/actions/runs/{run_id}')
    if run['conclusion'] != 'success' or run['path'] != '.github/workflows/candidate.yml' or run['event'] != 'workflow_dispatch':
        raise ValueError('Expected a successful Candidate images run')
    if run['head_sha'] != commit or run['head_branch'] != tag:
        raise ValueError('Candidate workflow and qualified source must be the same tag revision')
    assets = ROOT / 'out/release-assets'
    assets.parent.mkdir(exist_ok=True)
    assets.mkdir(exist_ok=False)
    accepted_risks = dependabot_risks
    for artifact in evidence['artifacts']:
        identity = artifact['identity']
        key = f'{identity["profile"]}-{identity["hardware_profile"]}-{identity["architecture"]}'
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['gh', 'run', 'download', run_id, '--name', f'candidate-{key}', '--dir', directory], check=True)
            source = Path(directory)
            inventories = list(source.rglob('build-metadata.json'))
            if len(inventories) != 1:
                raise ValueError('Expected exactly one candidate bundle per artifact')
            metadata_path = inventories[0]
            bundle = metadata_path.parent
            signatures = list(source.rglob('candidate-attestation.jsonl'))
            if len(signatures) != 1:
                raise ValueError('Exactly one trusted candidate attestation is required')
            attestations.verify(bundle / 'SHA256SUMS', signatures[0], commit, tag, run_id)
            verify_bundle(bundle, version, commit, artifact)
            decisions = json.loads((bundle / security.REPORT).read_text())['review']['decisions']
            for decision in decisions:
                if decision['decision'] == 'accepted-risk':
                    exception = decision['exception']
                    accepted_risks.add(f"{decision['id']} (expires {exception['expires_at']}): {exception['rationale']}")
            archive = assets / f'outerspace-{version}-{key}.tar'
            with tarfile.open(archive, 'w') as tar:
                for path in sorted(bundle.iterdir()):
                    if not path.is_file() or path.is_symlink():
                        raise ValueError('Unexpected bundle entry')
                    tar.add(path, arcname=path.name, recursive=False)
            (assets / f'{archive.name}.sha256').write_text(f'{sha256(archive)}  {archive.name}\n')
            (assets / f'{archive.name}.attestation.jsonl').write_bytes(signatures[0].read_bytes())
    (assets / 'qualification-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    notes = release_notes(evidence)
    if accepted_risks:
        notes += '\nAccepted, time-limited risks\n\n' + '\n'.join('- ' + risk for risk in sorted(accepted_risks)) + '\n'
    (ROOT / 'out/release-notes.txt').write_text(notes)


if __name__ == '__main__':
    main()
