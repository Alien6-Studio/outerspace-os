# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
from pathlib import Path
import struct
import unittest
from image_fixtures import profiles

spec = importlib.util.spec_from_file_location('boot_uefi', Path(__file__).resolve().parents[2] / 'tests/harness/boot-uefi.py')
uefi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uefi)


class UEFIBootTests(unittest.TestCase):
    def sector(self, size=512, sectors=524288):
        data = bytearray(512)
        data[510:512] = b'\x55\xaa'
        struct.pack_into('<H', data, 11, size)
        data[13] = 1
        struct.pack_into('<H', data, 14, 32)
        data[16] = 2
        struct.pack_into('<I', data, 32, sectors)
        struct.pack_into('<I', data, 36, 4096)
        return data

    def test_rejects_the_observed_fat_and_disk_sector_mismatch(self):
        uefi.check_fat_geometry(self.sector(), 512)
        with self.assertRaisesRegex(ValueError, 'logical sectors'):
            uefi.check_fat_geometry(self.sector(size=4096), 512)
        with self.assertRaisesRegex(ValueError, 'few clusters'):
            uefi.check_fat_geometry(self.sector(sectors=65536), 512)

    def test_never_loads_an_external_kernel_or_disposable_disk_per_boot(self):
        for arch in uefi.FIRMWARE:
            args = uefi.qemu_command(arch, '/tmp/shared.qcow2', '/tmp/shared-vars.fd', 'uuid', 'verify', 'nonce')
            for bypass in ['-kernel', '-initrd', '-append', '-snapshot']:
                self.assertNotIn(bypass, args)
            self.assertIn('if=virtio,format=qcow2,file=/tmp/shared.qcow2', args)
            self.assertIn('if=pflash,format=raw,file=/tmp/shared-vars.fd', args)

    def test_rejects_an_inference_image_that_inherits_the_small_agent_state_disk(self):
        table = {'sectorsize': 512, 'partitions': [{'name': 'OOS_STATE', 'size': 2 * 1024**3 // 512}]}
        uefi.check_state_geometry(table, 'agent')
        with self.assertRaisesRegex(ValueError, 'undersized'):
            uefi.check_state_geometry(table, 'inference')
        table['partitions'][0]['size'] = 8 * 1024**3 // 512
        uefi.check_state_geometry(table, 'inference')
        table['partitions'].append(dict(table['partitions'][0]))
        with self.assertRaises(ValueError):
            uefi.check_state_geometry(table, 'inference')

    def test_requires_the_second_boot_and_all_checks_to_pass(self):
        content = 'OUTERSPACE_SELFTEST_OK\nOUTERSPACE_UEFI_OK\nOUTERSPACE_PERSISTENCE_PREPARE_OK\n'
        uefi.verify_log(content, 0, 'prepare')
        with self.assertRaises(RuntimeError):
            uefi.verify_log(content, 0, 'verify')
        for bad_content, code in [(content + 'OUTERSPACE_SELFTEST_FAIL', 0), (content, 1)]:
            with self.assertRaises(RuntimeError):
                uefi.verify_log(bad_content, code, 'prepare')
