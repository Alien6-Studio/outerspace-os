# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Apply finite owner decisions only after checking the actual compiled kernel."""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

import kernel_build
import kernel_inventory
from profiles import ROOT, sha256
from sbom import read_json

MATERIALS = ('build/kernel/kernel.lock.json', 'build/kernel/release-key.gpg',
             'build/tools/kernel_build.py', 'build/tools/kernel_inventory.py',
             'build/sbom/sources.lock.json', 'src/components.lock.json',
             'src/image/mkosi.conf', 'src/image/mkosi.postinst')


def material_identity():
    return {name: sha256(ROOT / name) for name in MATERIALS}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def command_line(directory, identity):
    candidates = list(directory.glob('*.efi'))
    if (len(candidates) != 1 or candidates[0].is_symlink()
            or sha256(candidates[0]) != identity['uki_sha256']):
        raise ValueError('Kernel command line is not from the qualified UKI')
    with tempfile.TemporaryDirectory(prefix='kernel-review-') as temporary:
        path = Path(temporary)
        subprocess.run(['objcopy', '--dump-section', '.cmdline=' + str(path / 'cmdline'),
                        str(candidates[0]), str(path / 'inspected.efi')],
                       check=True, capture_output=True)
        return (path / 'cmdline').read_bytes().rstrip(b'\0').decode().split()


def predicates(case, arch, config, report, raw, cmdline):
    required = {**case.get('config', {}), **case.get('architecture_config', {}).get(arch, {})}
    if any(not re.fullmatch('CONFIG_[A-Z0-9_]+', key) or value not in ('y', 'm', 'n')
           for key, value in required.items()):
        raise ValueError('Invalid reviewed kernel configuration predicate')
    if any(config.get(key, 'n') != value for key, value in required.items()):
        raise ValueError('Kernel configuration does not satisfy the approved decision')
    if case.get('patch_sha256') and case['patch_sha256'] not in {p['sha256'] for p in report['patches']}:
        raise ValueError('Reviewed kernel correction is missing')
    if case.get('kaslr_required') and arch == 'amd64':
        if config.get('CONFIG_RANDOMIZE_BASE') != 'y' or any(w.split('=', 1)[0] == 'nokaslr' for w in cmdline):
            raise ValueError('Reviewed x86 attack-vector protection is disabled')
    if case.get('stock_network_only'):
        # This predicate narrows an explicit risk acceptance; it does not claim
        # that absence of these clients is a universal fix for VPN side channels.
        if case['decision'] != 'accepted-risk':
            raise ValueError('Stock-network limitation requires explicit risk acceptance')
        vpn = ('openvpn', 'wireguard', 'strongswan', 'libreswan', 'tailscale', 'zerotier', 'vpnc', 'openconnect')
        if (any(any(v in a['name'].lower() for v in vpn) for a in raw['artifacts'])
                or any(any(v in f['location']['path'].lower() for v in vpn)
                       or f['location']['path'].endswith('.netdev') for f in raw['files'])):
            raise ValueError('Image exceeds the approved stock-network scope')


def materialize(directory, identity, kernel_scan, policy, scope, finding):
    reviews = policy.get('kernel_reviews', [])
    if not reviews:
        return []
    if (identity['hardware_profile'] != 'cpu' or identity['profile'] not in ('agent', 'inference')
            or identity['architecture'] not in ('amd64', 'arm64')):
        return []
    raw = read_json(directory / 'distribution.sbom.syft.json')
    proof = kernel_inventory.correspondence(directory, identity, raw, read_json(directory / 'source-index.json'))
    report = read_json(directory / 'kernel-build.json')
    config = kernel_build.config_values(directory / 'kernel.config')
    expected_materials = material_identity()
    result, seen = [], set()
    for review in reviews:
        if (review.get('schema') != 1 or review.get('scope') != {'hardware_profile': 'cpu',
                'profiles': ['agent', 'inference'], 'architectures': ['amd64', 'arm64']}
                or review.get('approved_by') not in policy['exception_approvers']
                or not review.get('owner') or not review.get('cases')):
            raise ValueError('Unaccountable kernel source review')
        if review.get('materials') != expected_materials:
            # Changed source/recipe must never inherit a previous decision.
            continue
        cases = review['cases']
        if len({c['id'] for c in cases}) != len(cases):
            raise ValueError('Ambiguous reviewed kernel advisory')
        cmdline = command_line(directory, identity) if identity['architecture'] == 'amd64' and any(
            c.get('kaslr_required') for c in cases) else []
        for match in kernel_scan['matches']:
            f = finding(match)
            selected = [case for case in cases if case['id'] == f['id']]
            if not selected:
                continue
            if (f['package'] != 'linux_kernel' or f['version'] != proof['version'] or f['type'] != 'binary'
                    or f['namespace'] != 'nvd:cpe' or f['purl'] != 'pkg:generic/linux@' + proof['version']
                    or f['paths'] != ['/usr/lib/modules/' + proof['release'] + '/vmlinuz']):
                raise ValueError('Kernel finding differs from the reviewed source identity')
            if f['key'] in seen:
                raise ValueError('Duplicate applicable kernel source review')
            seen.add(f['key'])
            case = selected[0]
            predicates(case, identity['architecture'], config, report, raw, cmdline)
            base = 'usr/lib/modules/' + proof['release'] + '/'
            result.append({**{k: review[k] for k in ['approved_by', 'owner', 'reviewed_at', 'expires_at']},
                **{k: case[k] for k in ['decision', 'rationale', 'evidence']},
                'finding_sha256': f['key'], 'advisory': f['id'], 'scope': scope,
                'binary_sha256': {'/' + base + name: proof['files'][base + name] for name in ['vmlinuz', 'config']},
                'source_review_sha256': digest(review), 'kernel_receipt_sha256': proof['receipt_sha256']})
    return result
