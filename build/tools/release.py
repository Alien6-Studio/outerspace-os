#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Validate release identity and evidence before creating even a draft release."""
import argparse
import json
from pathlib import Path
import re
from profiles import selection

ROOT = Path(__file__).resolve().parents[2]
VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(dev|alpha|beta|rc)\.(0|[1-9][0-9]*))?")


def parse_version(version):
    match = VERSION_PATTERN.fullmatch(version)
    if not match:
        raise ValueError("Use MAJOR.MINOR.PATCH[-dev.N|-alpha.N|-beta.N|-rc.N]")
    stage = match[4] or "stable"
    if stage in {"alpha", "beta", "rc"} and int(match[5]) < 1:
        raise ValueError("Public prerelease sequence numbers start at 1")
    return stage


def release_notes(evidence):
    notes = evidence.get('release_notes', {})
    fields = ['summary', 'changes', 'install', 'limitations', 'support']
    if (not isinstance(notes, dict) or set(notes) != set(fields)
            or any(not isinstance(notes[name], str) or not notes[name].strip()
                   or '\x00' in notes[name] for name in fields)):
        raise ValueError('Complete release notes are required in the qualification JSON')
    matrix = ['- ' + '/'.join(artifact['identity'][name] for name in
                              ['profile', 'hardware_profile', 'architecture'])
              + ': ' + artifact['identity']['raw_image_sha256']
              for artifact in evidence['artifacts']]
    return ('OuterSpace OS ' + evidence['version'] + '\n\n' + notes['summary'].strip()
            + '\n\nSource: ' + evidence['commit'] + '\n\nQualified images (SHA256):\n'
            + '\n'.join(matrix) + '\n\n'
            + '\n\n'.join(name.title() + ':\n' + notes[name].strip() for name in fields[1:]) + '\n')


def validate_release(version, tag, commit, evidence, policy):
    stage = parse_version(version)
    if tag != "v" + version:
        raise ValueError("Release tag must exactly match VERSION")
    if stage == "dev":
        raise ValueError("Development snapshots cannot be published as releases")
    if evidence.get("version") != version or evidence.get("commit") != commit:
        raise ValueError("Evidence must identify this exact version and commit")
    if policy.get('schema') != 2 or evidence.get('schema') != 2 or not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('Profile-bound schema 2 evidence and a full source commit are required')
    expected = {(item['profile'], item['hardware_profile'], item['architecture']) for item in policy['artifacts']}
    seen = set()
    failures = []
    for artifact in evidence.get('artifacts', []):
        identity = artifact.get('identity', {})
        selected = selection(identity.get('profile'), identity.get('hardware_profile'), identity.get('architecture', 'invalid'))
        key = (selected['profile'], selected['hardware_profile'], selected['architecture'])
        if key not in expected or key in seen:
            raise ValueError('Unknown or duplicate profile/hardware/architecture artifact')
        seen.add(key)
        if identity.get('version') != version or identity.get('commit') != commit:
            raise ValueError('Artifact must identify this exact version and commit')
        for field in ['raw_image_sha256', 'uki_sha256', 'verity_root_hash', 'manifest_sha256',
                      'components_lock_sha256', 'source_archive_sha256']:
            if not re.fullmatch(r'[a-f0-9]{64}', identity.get(field, '')):
                raise ValueError(f'Missing exact image identity: {field}')
        if not re.fullmatch(r'[a-f0-9]{64}', artifact.get('sha256sums', '')):
            raise ValueError('Each candidate needs its qualified SHA256SUMS digest')
        capabilities = artifact.get('capabilities', [])
        if (not isinstance(capabilities, list) or any(not isinstance(c, str) for c in capabilities)
                or len(set(capabilities)) != len(capabilities)):
            raise ValueError('Capabilities must be a unique list')
        mandatory = set(policy['profiles'][key[0]]['required_capabilities'])
        if not mandatory.issubset(capabilities):
            raise ValueError('Mandatory profile capabilities cannot be omitted')
        required = set(policy['stages'][stage])
        for capability in capabilities:
            definition = policy['capabilities'].get(capability)
            if (not definition or key[0] not in definition['profiles']
                    or key[1] not in definition['hardware']):
                raise ValueError(f'Unsupported capability for this profile/hardware: {capability}')
            required.update(definition['gates'])
        for name in sorted(required):
            gate = artifact.get('gates', {}).get(name, {})
            if (gate.get('status') != 'passed' or not isinstance(gate.get('evidence'), str)
                    or not gate['evidence'].strip() or gate.get('subject') != identity):
                failures.append('/'.join(key) + ':' + name)
    if seen != expected:
        raise ValueError('Evidence must qualify every required profile/hardware/architecture artifact')
    if failures:
        raise ValueError("Release gates not satisfied: " + ", ".join(failures))
    release_notes(evidence)
    return stage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        version = (ROOT / "VERSION").read_text().strip()
        stage = validate_release(version, args.tag, args.commit, json.loads(args.evidence.read_text()),
                                 json.loads((ROOT / "build/release/policy.json").read_text()))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Release refused: {exc}\n")
    print(json.dumps({"version": version, "stage": stage, "prerelease": stage != "stable"}))


if __name__ == "__main__":
    main()
