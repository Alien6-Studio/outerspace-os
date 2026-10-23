#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Boot the GPT disk through UEFI twice, retaining only a disposable overlay."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from profiles import marker, verify_identity

ESP = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
FIRMWARE = {
    'aarch64': ('qemu-system-aarch64', 'virt', 'max',
                '/usr/share/AAVMF/AAVMF_CODE.fd', '/usr/share/AAVMF/AAVMF_VARS.fd'),
    'x86_64': ('qemu-system-x86_64', 'q35', 'max',
               '/usr/share/OVMF/OVMF_CODE_4M.fd', '/usr/share/OVMF/OVMF_VARS_4M.fd'),
}


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_fat_geometry(sector, logical_sector):
    if len(sector) < 512 or sector[510:512] != b'\x55\xaa':
        raise ValueError('Invalid EFI filesystem boot sector')
    filesystem_sector = struct.unpack_from('<H', sector, 11)[0]
    if logical_sector != 512 or filesystem_sector != logical_sector:
        raise ValueError('EFI FAT and GPT must both use 512-byte logical sectors')
    sectors_per_cluster = sector[13]
    reserved = struct.unpack_from('<H', sector, 14)[0]
    fats = sector[16]
    total = struct.unpack_from('<I', sector, 32)[0]
    fat_size = struct.unpack_from('<I', sector, 36)[0]
    if not sectors_per_cluster or not fats or not fat_size:
        raise ValueError('Invalid EFI FAT32 geometry')
    clusters = (total - reserved - fats * fat_size) // sectors_per_cluster
    if clusters < 65525:
        raise ValueError('EFI FAT32 filesystem has too few clusters for firmware')


def check_disk_geometry(disk):
    result = subprocess.run(['sfdisk', '--json', str(disk)], check=True, capture_output=True, text=True)
    table = json.loads(result.stdout)['partitiontable']
    partitions = [p for p in table['partitions'] if p['type'].lower() == ESP]
    if table['label'] != 'gpt' or len(partitions) != 1:
        raise ValueError('Expected a GPT disk with exactly one EFI System Partition')
    logical_sector = table['sectorsize']
    offset = partitions[0]['start'] * logical_sector
    with disk.open('rb') as stream:
        stream.seek(offset)
        check_fat_geometry(stream.read(512), logical_sector)


def qemu_command(arch, overlay, variables, machine_uuid, phase, nonce):
    binary, machine, cpu, code, _ = FIRMWARE[arch]
    return [binary, '-machine', machine, '-cpu', cpu, '-accel', 'tcg',
            '-m', '1536', '-smp', '2', '-nographic', '-no-reboot',
            '-uuid', machine_uuid, '-boot', 'order=c,strict=on',
            '-drive', f'if=pflash,format=raw,readonly=on,file={code}',
            '-drive', f'if=pflash,format=raw,file={variables}',
            '-drive', f'if=virtio,format=qcow2,file={overlay}',
            '-nic', 'user,model=virtio-net-pci',
            '-smbios', 'type=11,value=io.systemd.stub.kernel-cmdline-extra='
            f'outerspace.selftest=1 outerspace.selftest.phase={phase} outerspace.selftest.nonce={nonce}']


def verify_log(content, returncode, phase):
    required = ['OUTERSPACE_SELFTEST_OK', 'OUTERSPACE_UEFI_OK',
                f'OUTERSPACE_PERSISTENCE_{phase.upper()}_OK']
    if returncode or 'OUTERSPACE_SELFTEST_FAIL' in content or any(marker not in content for marker in required):
        raise RuntimeError(f'UEFI {phase} verification failed')


def boot(output, profile, hardware):
    output = output.resolve()
    identity = verify_identity(output, profile, hardware)
    disk = output / 'outerspace.raw'
    if disk.is_symlink() or not disk.is_file():
        raise ValueError('Expected a regular build/outerspace.raw image')
    report_path = output / 'uefi-smoke.json'
    report_path.unlink(missing_ok=True)
    combined = output / 'boot-smoke.log'
    combined.write_text('OuterSpace UEFI qualification started\n')
    arch = platform.machine()
    if arch not in FIRMWARE:
        raise ValueError(f'Unsupported host: {arch}')
    _, _, _, code, template = FIRMWARE[arch]
    check_disk_geometry(disk)
    image_hash = sha256(disk)
    nonce = uuid.uuid4().hex
    machine_uuid = str(uuid.uuid4())
    with tempfile.TemporaryDirectory(prefix='outerspace-uefi-') as directory:
        variables = Path(directory) / 'vars.fd'
        overlay = Path(directory) / 'disk.qcow2'
        shutil.copyfile(template, variables)
        subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'raw',
                        '-b', str(disk), str(overlay)], check=True)
        for phase in ['prepare', 'verify']:
            log_path = output / f'boot-uefi-{phase}.log'
            print(f'UEFI {phase}: firmware → systemd-boot → UKI → verity root', flush=True)
            try:
                with log_path.open('w') as log:
                    result = subprocess.run(qemu_command(arch, overlay, variables, machine_uuid, phase, nonce),
                                            stdout=log, stderr=subprocess.STDOUT, timeout=600)
            except subprocess.TimeoutExpired:
                raise RuntimeError(f'UEFI {phase} timed out; inspect {log_path.name}') from None
            finally:
                content = log_path.read_text(errors='replace')
                with combined.open('a') as log:
                    log.write(f'\n=== UEFI {phase} ===\n' + content)
            print(content[-6000:], flush=True)
            verify_log(content, result.returncode, phase)
            if marker(identity) not in content:
                raise RuntimeError('Booted image profile/source identity does not match the build')
    if sha256(disk) != image_hash:
        raise RuntimeError('The source disk changed during qualification')
    report = {'schema': 2, 'status': 'passed', 'identity': identity,
              'architecture': {'aarch64': 'arm64', 'x86_64': 'amd64'}[arch],
              'image_sha256': image_hash, 'firmware_sha256': sha256(Path(code)),
              'boot': 'UEFI firmware → systemd-boot → on-disk UKI → dm-verity root',
              'secure_boot': False, 'power_cycles': 2,
              'persistence': ['nonce', 'hostname', 'machine-id'],
              'machine_id_source': 'Stable QEMU VM UUID; physical-host machine-id persistence is not qualified',
              'limits': ['No Secure Boot qualification', 'No physical hardware qualification',
                         'No Kubernetes enrollment or workload qualification'],
              'logs': {name: sha256(output / name) for name in
                       ['boot-smoke.log', 'boot-uefi-prepare.log', 'boot-uefi-verify.log']}}
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print('OUTERSPACE_UEFI_PERSISTENCE_OK')


if __name__ == '__main__':
    boot(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
