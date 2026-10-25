# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
import copy
import json
from pathlib import Path
import struct
import unittest
from image_fixtures import profiles, identity, idle_log, idle_record

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
            self.assertEqual(args[args.index('-m') + 1], '4096')
            self.assertEqual(args[args.index('-smp') + 1], '4')
            self.assertIn('outerspace.selftest.baseline=1', args[-1])

    def test_idle_host_uses_actual_clock_units_and_excludes_wait_steal_and_duplicate_guest_time(self):
        subject = identity()
        logs = {phase: idle_log(subject, phase) for phase in ['prepare', 'verify']}
        report = uefi.idle_host_report(logs, subject)
        for boot in report['boots'].values():
            self.assertEqual(boot['guest_busy_cpu_percent']['median'], 0.375)
            self.assertEqual(boot['memory_unavailable_bytes']['samples'], 4)
            self.assertEqual(len(boot['intervals']), 3)
            self.assertEqual(boot['intervals'][0]['service_cpu_seconds']['outerspace-selftest'], 0.001)
        records = {phase: idle_record(subject, phase) for phase in logs}
        for record in records.values():
            record['clock_ticks_per_second'] = 1000
            for sample in record['samples']:
                sample['cpu_ticks'] = [value * 10 for value in sample['cpu_ticks']]
        self.assertEqual(self.idle_report(subject, records)['boots']['prepare']['guest_busy_cpu_percent']['median'], 0.375)

    def idle_report(self, subject, records):
        return uefi.idle_host_report({phase: 'OUTERSPACE_IDLE_HOST ' + json.dumps(record) for phase, record in records.items()}, subject)

    def test_idle_host_refuses_cross_source_loaded_forged_or_reused_boot_records(self):
        subject = identity()
        records = {phase: idle_record(subject, phase) for phase in ['prepare', 'verify']}
        for key, value in [('commit', 'b' * 40), ('nonce', 'f' * 32), ('boot_id', records['prepare']['boot_id']),
                           ('sandboxes', 1), ('containers', False), ('kubelet_active', True), ('p2p_active', True),
                           ('vcpus', 2), ('clock_ticks_per_second', 0)]:
            changed = copy.deepcopy(records)
            changed['verify'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.idle_report(subject, changed)
        for bad_logs in [{'prepare': idle_log(subject, 'prepare'), 'verify': ''},
                         {'prepare': idle_log(subject, 'prepare') * 2, 'verify': idle_log(subject, 'verify')}]:
            with self.assertRaises(ValueError):
                uefi.idle_host_report(bad_logs, subject)

    def test_idle_host_refuses_shortened_windows_nonfinite_or_incomplete_counters_and_service_restart(self):
        subject = identity()
        records = {phase: idle_record(subject, phase) for phase in ['prepare', 'verify']}
        changes = [('settle_started_uptime_seconds', 61), ('samples', records['prepare']['samples'][:3])]
        for key, value in changes:
            changed = copy.deepcopy(records)
            changed['prepare'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.idle_report(subject, changed)
        for change in [lambda s: s.update(uptime_seconds=float('nan')),
                       lambda s: s.update(uptime_seconds=125),
                       lambda s: s['cpu_ticks'].__setitem__(0, 0),
                       lambda s: s['memory_bytes'].pop('Slab'),
                       lambda s: s['memory_bytes'].update(MemAvailable=float('inf')),
                       lambda s: s['services'].update(containerd=None),
                       lambda s: s['services']['outerspace-selftest'].update(cpu_usage_usec=0)]:
            changed = copy.deepcopy(records)
            change(changed['prepare']['samples'][1])
            with self.assertRaises(ValueError):
                self.idle_report(subject, changed)

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
