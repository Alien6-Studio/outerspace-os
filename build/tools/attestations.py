#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Verify GitHub keyless provenance against an explicitly trusted candidate job."""
import json
import argparse
from pathlib import Path
import re
import subprocess

REPOSITORY = 'Alien6-Studio/outerspace-os'
WORKFLOW = REPOSITORY + '/.github/workflows/candidate.yml'


def verify(checksums, bundle, commit, tag, run_id):
    if (not re.fullmatch('[a-f0-9]{40}', commit) or not re.fullmatch(r'v[0-9A-Za-z.+-]+', tag)
            or not re.fullmatch('[1-9][0-9]*', str(run_id))):
        raise ValueError('Invalid attestation qualification identity')
    for path in [checksums, bundle]:
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing or unsafe signed inventory')
    # gh verifies the certificate chain, transparency proof, signature AND
    # artifact digest. Certificate constraints are independent of the predicate.
    result = json.loads(subprocess.check_output([
        'gh', 'attestation', 'verify', str(checksums), '--bundle', str(bundle),
        '--repo', REPOSITORY, '--signer-repo', REPOSITORY, '--signer-workflow', WORKFLOW,
        '--signer-digest', commit, '--source-digest', commit, '--source-ref', 'refs/tags/' + tag,
        '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
        '--deny-self-hosted-runners', '--predicate-type', 'https://slsa.dev/provenance/v1',
        '--format', 'json'], text=True))
    prefix = f'https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/'
    for item in result:
        statement = item['verificationResult']['statement']
        invocation = statement['predicate']['runDetails']['metadata']['invocationId']
        if invocation.startswith(prefix) and re.fullmatch('[1-9][0-9]*', invocation[len(prefix):]):
            return {'repository': REPOSITORY, 'workflow': WORKFLOW, 'commit': commit,
                    'tag': tag, 'invocation': invocation}
    raise ValueError('Attestation does not identify the qualified workflow run')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checksums', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.checksums, args.bundle, args.commit, args.tag, args.run), indent=2))
