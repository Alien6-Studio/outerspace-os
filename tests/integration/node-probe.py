# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Read-only lab probe. Never output a token or a private key."""
import hashlib
import json
import os
from pathlib import Path
import re
import ssl

root = Path('/host')
state = os.statvfs(root / 'var')
pki = root / 'var/lib/kubelet/pki'
current = pki / 'kubelet-client-current.pem'
target = current.readlink()
if target.name != str(target).split('/')[-1] or '..' in target.parts:
    raise ValueError('Unexpected certificate path')
pem = (pki / target.name).read_text()
certificate = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S).group()
fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
shadow = {line.split(':')[0]: line.split(':')[1] for line in (root / 'etc/shadow').read_text().splitlines()}
config = (root / 'var/lib/kubelet/kubeconfig').read_text()
assert 'kubelet-client-current.pem' in config and not re.search(r'^\s*token:', config, re.M)
assert all(shadow[name].startswith(('!', '*')) for name in ['root', 'outerspace'])
print(json.dumps({
    'identity': json.loads((root / 'usr/share/outerspace/image-identity.json').read_text()),
    'hostname': (root / 'var/lib/outerspace/hostname').read_text().strip(),
    'machine_id': (root / 'etc/machine-id').read_text().strip(),
    'boot_id': (root / 'proc/sys/kernel/random/boot_id').read_text().strip(),
    'client_certificate_sha256': fingerprint,
    'bootstrap_present': (root / 'var/lib/kubelet/bootstrap-kubeconfig').exists(),
    'accounts_locked': True,
    'state_capacity_bytes': state.f_blocks * state.f_frsize,
    'state_available_bytes': state.f_bavail * state.f_frsize,
}))
