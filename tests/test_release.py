# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("release", Path(__file__).resolve().parents[1] / "scripts/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseGateTests(unittest.TestCase):
    policy = {"stages": {"alpha": ["boot"], "stable": ["boot", "signed_boot", "cis_audit"]}}

    def test_valid_alpha_is_marked_as_prerelease(self):
        evidence = {"version": "0.1.0-alpha.1", "commit": "abc", "gates": {"boot": {"status": "passed", "evidence": "ci/run/123"}}}
        self.assertEqual(release.validate_release("0.1.0-alpha.1", "v0.1.0-alpha.1", "abc", evidence, self.policy), "alpha")

    def test_no_dev_snapshot_can_be_mistaken_for_a_release(self):
        with self.assertRaises(ValueError):
            release.validate_release("0.1.0-dev.0", "v0.1.0-dev.0", "abc", {}, self.policy)

    def test_stable_fails_without_all_evidence(self):
        evidence = {"version": "0.1.0", "commit": "abc", "gates": {"boot": {"status": "passed", "evidence": "ci/123"}}}
        with self.assertRaisesRegex(ValueError, "signed_boot, cis_audit"):
            release.validate_release("0.1.0", "v0.1.0", "abc", evidence, self.policy)

    def test_rejects_reused_evidence_and_mismatched_tag(self):
        evidence = {"version": "0.1.0-alpha.1", "commit": "old", "gates": {}}
        with self.assertRaisesRegex(ValueError, "exact version and commit"):
            release.validate_release("0.1.0-alpha.1", "v0.1.0-alpha.1", "new", evidence, self.policy)
        with self.assertRaisesRegex(ValueError, "exactly match"):
            release.validate_release("0.1.0-alpha.1", "v0.1.0", "old", evidence, self.policy)

    def test_rejects_ambiguous_versions(self):
        for version in ["latest", "01.0.0", "1.0", "v1.0.0", "1.0.0-beta", "1.0.0-rc.0"]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.parse_version(version)
