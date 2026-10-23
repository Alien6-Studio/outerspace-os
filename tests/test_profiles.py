# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import subprocess
import unittest
from image_fixtures import profiles


class ProfileSelectionTests(unittest.TestCase):
    def test_mkosi_and_os_architecture_names_share_canonical_identity(self):
        for name, expected in [('x86-64', 'amd64'), ('x86_64', 'amd64'), ('amd64', 'amd64'),
                               ('aarch64', 'arm64'), ('arm64', 'arm64')]:
            with self.subTest(name=name):
                self.assertEqual(profiles.selection('agent', 'cpu', name)['architecture'], expected)

    def test_profile_is_required_before_any_docker_operation(self):
        for command in [['make', 'build'], ['make', 'smoke'], ['make', 'package'],
                        ['make', 'PROFILE=unknown', 'build']]:
            with self.subTest(command=command):
                result = subprocess.run(command, cwd=profiles.ROOT, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('invalid choice', result.stderr)

    def test_unknown_architecture_and_hardware_are_refused(self):
        for args in [('agent', 'gpu-nvidia', 'amd64'), ('inference', 'cpu', 'sparc')]:
            with self.subTest(args=args), self.assertRaises(ValueError): profiles.selection(*args)

    def test_profile_identity_is_distinct_without_forking_components(self):
        agent = profiles.image_identity('agent', 'cpu', 'amd64', 'a' * 40)
        inference = profiles.image_identity('inference', 'cpu', 'amd64', 'a' * 40)
        self.assertNotEqual(agent, inference)
        self.assertEqual(agent['components_lock_sha256'], inference['components_lock_sha256'])
        self.assertEqual(agent['host_features'], inference['host_features'])
