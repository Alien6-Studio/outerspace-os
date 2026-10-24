# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import hashlib
from pathlib import Path
import sys

BUILD_TOOLS = Path(__file__).resolve().parents[2] / 'build/tools'
sys.path.insert(0, str(BUILD_TOOLS))
import profiles


def identity(profile='agent', arch=None, version='0.1.0-alpha.1'):
    value = profiles.image_identity(profile, 'cpu', arch or profiles.architecture(), 'a' * 40)
    value['version'] = version
    for field in ['raw_image_sha256', 'uki_sha256', 'verity_root_hash', 'manifest_sha256', 'source_archive_sha256']:
        value[field] = hashlib.sha256(f'{profile}:{value["architecture"]}:{field}'.encode()).hexdigest()
    return value


def qualification(policy):
    evidence = {'schema': 2, 'version': '0.1.0-alpha.1', 'commit': 'a' * 40, 'artifacts': []}
    for selected in policy['artifacts']:
        subject = identity(selected['profile'], selected['architecture'])
        capabilities = policy['profiles'][selected['profile']]['required_capabilities'][:]
        gates = set(policy['stages']['alpha'])
        for capability in capabilities:
            gates.update(policy['capabilities'][capability]['gates'])
        evidence['artifacts'].append({'identity': subject, 'capabilities': capabilities, 'sha256sums': 'b' * 64,
                                     'gates': {gate: {'status': 'passed', 'evidence': 'synthetic-test-only',
                                                      'subject': copy.deepcopy(subject)} for gate in gates}})
    return evidence
