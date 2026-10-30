# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import gzip
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare_kernel', Path(__file__).resolve().parents[2] / 'build/tools/prepare-kernel.py')
kernel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel)


class KernelPreparationTests(unittest.TestCase):
    def test_missing_cilium_netlink_and_socket_interfaces_fail_before_assembly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'boot').mkdir()
            config = root / 'boot/config-test'
            for missing in ['CONFIG_XFRM_USER', 'CONFIG_INET_UDP_DIAG', 'CONFIG_NETFILTER_XT_TARGET_TPROXY',
                            'CONFIG_IP_ADVANCED_ROUTER', 'CONFIG_IP_MULTIPLE_TABLES', 'CONFIG_IPV6_MULTIPLE_TABLES',
                            'CONFIG_CGROUP_NET_CLASSID']:
                config.write_text(''.join(name + '=y\n' for name in kernel.REQUIRED if name != missing))
                with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, missing):
                    kernel.check_kernel(root)

    def image(self):
        data = bytearray(128)
        data[:2] = b'MZ'
        data[56:60] = b'ARMd'
        struct.pack_into('<I', data, 60, 64)
        data[64:68] = b'PE\0\0'
        struct.pack_into('<H', data, 68, 0xaa64)
        return bytes(data)

    def test_decompresses_arm64_and_preserves_both_input_hashes(self):
        payload = self.image()
        original = gzip.compress(payload)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'boot').mkdir()
            path = root / 'boot/vmlinuz-test'
            path.write_bytes(original)
            module = root / 'usr/lib/modules/test/vmlinuz'
            module.parent.mkdir(parents=True)
            module.write_bytes(original)
            kernel.prepare(root, 'arm64')
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(module.read_bytes(), payload)
            self.assertTrue(path.samefile(module))
            record = json.loads((root / 'usr/share/outerspace/kernel-preparation.json').read_text())['kernels'][0]
            self.assertNotEqual(record['package_payload_sha256'], record['efi_payload_sha256'])

    def test_leaves_x86_compression_and_uncompressed_arm_unchanged(self):
        compressed = gzip.compress(b'x86 kernel')
        self.assertEqual(kernel.normalize(compressed, 'x86-64'), (compressed, 'unchanged'))
        self.assertEqual(kernel.normalize(self.image(), 'arm64'), (self.image(), 'unchanged'))

    def test_rejects_non_efi_and_wrong_architecture_payloads(self):
        wrong = bytearray(self.image())
        struct.pack_into('<H', wrong, 68, 0x8664)
        for data in [b'not a kernel', gzip.compress(b'not an EFI kernel'), bytes(wrong)]:
            with self.subTest(data=data[:8]):
                with self.assertRaises(ValueError):
                    kernel.normalize(data, 'arm64')
