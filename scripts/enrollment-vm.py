#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Disposable UEFI worker on a bridged TAP; runs only inside the lab runner."""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import time
import uuid

spec = importlib.util.spec_from_file_location('uefi', Path(__file__).with_name('boot-uefi.py'))
uefi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uefi)


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def qmp(command):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect('/state/qmp.sock')
        stream = connection.makefile('rwb', buffering=0)
        json.loads(stream.readline())
        for operation in ['qmp_capabilities', command]:
            stream.write((json.dumps({'execute': operation}) + '\n').encode())
            while True:
                response = json.loads(stream.readline())
                if 'error' in response:
                    raise RuntimeError(response['error'])
                if 'return' in response:
                    break


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'poweroff'])
    parser.add_argument('--config-drive', action='store_true')
    args = parser.parse_args()
    if args.action == 'poweroff':
        qmp('system_powerdown')
        return
    state = Path('/state')
    if not (state / 'disk.qcow2').exists():
        address = json.loads(run('ip', '-j', '-4', 'addr', 'show', 'dev', 'eth0'))[0]['addr_info'][0]
        runner = address['local']
        prefix = address['prefixlen']
        gateway = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default'))[0]['gateway']
        run('ip', 'link', 'add', 'br0', 'type', 'bridge')
        run('ip', 'addr', 'flush', 'dev', 'eth0')
        run('ip', 'link', 'set', 'eth0', 'master', 'br0')
        run('ip', 'addr', 'add', f'{runner}/{prefix}', 'dev', 'br0')
        run('ip', 'link', 'set', 'br0', 'up')
        run('ip', 'route', 'replace', 'default', 'via', gateway, 'dev', 'br0')
        run('ip', 'tuntap', 'add', 'dev', 'tap0', 'mode', 'tap')
        run('ip', 'link', 'set', 'tap0', 'master', 'br0')
        run('ip', 'link', 'set', 'tap0', 'up')
        mask = str(ipaddress.IPv4Network(f'0.0.0.0/{prefix}').netmask)
        run('dnsmasq', '--interface=br0', '--bind-interfaces', '--no-resolv',
            '--server=127.0.0.11', f'--listen-address={runner}',
            '--dhcp-authoritative', f'--dhcp-range=172.30.80.10,172.30.80.10,{mask},1h',
            '--dhcp-host=52:54:00:80:00:10,172.30.80.10',
            f'--dhcp-option=3,{gateway}', f'--dhcp-option=6,{runner}',
            '--user=root', '--pid-file=/state/dnsmasq.pid', '--dhcp-leasefile=/state/dnsmasq.leases')
        shutil.copyfile(uefi.FIRMWARE[platform.machine()][4], state / 'vars.fd')
        run('qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'raw', '-b', '/state/packaged.raw', '/state/disk.qcow2')
        (state / 'uuid').write_text(str(uuid.uuid4()))
    args_qemu = uefi.qemu_command(platform.machine(), '/state/disk.qcow2', '/state/vars.fd',
                                 (state / 'uuid').read_text(), 'unused', 'unused')
    # Enrollment boots never use the selftest's shutdown hook or an external kernel.
    args_qemu = args_qemu[:-2]
    args_qemu += ['-smbios', 'type=11,value=io.systemd.stub.kernel-cmdline-extra=systemd.journald.forward_to_console=1']
    nic = args_qemu.index('-nic')
    args_qemu[nic:nic + 2] = ['-netdev', 'tap,id=net0,ifname=tap0,script=no,downscript=no',
                              '-device', 'virtio-net-pci,netdev=net0,mac=52:54:00:80:00:10']
    args_qemu[args_qemu.index('-m') + 1] = '4096'
    args_qemu[args_qemu.index('-smp') + 1] = '4'
    args_qemu += ['-qmp', 'unix:/state/qmp.sock,server=on,wait=off',
                  '-pidfile', '/state/qemu.pid']
    if args.config_drive:
        args_qemu += ['-drive', 'if=virtio,format=raw,readonly=on,file=/state/node-config.raw']
    (state / ('qemu-command-enroll.json' if args.config_drive else 'qemu-command-recover.json')).write_text(json.dumps(args_qemu, indent=2) + '\n')
    with (state / ('boot-enroll.log' if args.config_drive else 'boot-recover.log')).open('w') as log:
        process = subprocess.Popen(args_qemu, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        if (state / 'qmp.sock').exists():
            return
        if process.poll() is not None:
            raise RuntimeError('QEMU exited; inspect the private lab boot log')
        time.sleep(.1)
    raise RuntimeError('QEMU monitor did not become ready')


if __name__ == '__main__':
    main()
