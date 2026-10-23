#!/usr/bin/env python3
"""Validate external qualification evidence and stage immutable CI candidates."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tarfile
from package import sha256
from release import ROOT, validate_release


def gh_json(*args):
    return json.loads(subprocess.check_output(['gh', *args], text=True))


def verify_bundle(bundle, version, commit, arch, expected):
    metadata = json.loads((bundle / 'build-metadata.json').read_text())
    if (metadata['version'], metadata['commit'], metadata['architecture']) != (version, commit, arch):
        raise ValueError('Candidate inventory does not match the qualified release')
    inventory = bundle / 'SHA256SUMS'
    if inventory.is_symlink() or sha256(inventory) != expected:
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


def main():
    tag = os.environ['TAG']
    run_id = os.environ['CANDIDATE_RUN']
    if not re.fullmatch(r'[1-9][0-9]*', run_id):
        raise ValueError('Expected numeric candidate workflow run ID')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    version = (ROOT / 'VERSION').read_text().strip()
    evidence = json.loads(os.environ['EVIDENCE_JSON'])
    policy = json.loads((ROOT / 'release/policy.json').read_text())
    validate_release(version, tag, commit, evidence, policy)
    if str(evidence.get('candidate_run')) != run_id:
        raise ValueError('Evidence must qualify this candidate run, not just its source commit')
    run = gh_json('api', f'repos/{os.environ["GH_REPO"]}/actions/runs/{run_id}')
    if run['conclusion'] != 'success' or run['path'] != '.github/workflows/candidate.yml' or run['event'] != 'workflow_dispatch':
        raise ValueError('Expected a successful Candidate images run')
    # workflow_dispatch's head_sha can identify the workflow ref rather than the
    # checked-out tag. The per-architecture inventories bind the built source SHA.
    assets = ROOT / 'release-assets'
    assets.mkdir(exist_ok=False)
    for arch in ['amd64', 'arm64']:
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['gh', 'run', 'download', run_id, '--name', f'candidate-{arch}', '--dir', directory], check=True)
            source = Path(directory)
            metadata_path = next(source.rglob('build-metadata.json'))
            bundle = metadata_path.parent
            verify_bundle(bundle, version, commit, arch, evidence.get('candidate_checksums', {}).get(arch))
            archive = assets / f'outerspace-{version}-{arch}.tar'
            with tarfile.open(archive, 'w') as tar:
                for path in sorted(bundle.iterdir()):
                    if not path.is_file() or path.is_symlink():
                        raise ValueError('Unexpected bundle entry')
                    tar.add(path, arcname=path.name, recursive=False)
            (assets / f'{archive.name}.sha256').write_text(f'{sha256(archive)}  {archive.name}\n')
    (assets / 'qualification-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    if not (ROOT / f'release/notes/{version}.md').is_file():
        raise ValueError('Version-specific release notes are required')


if __name__ == '__main__':
    main()
