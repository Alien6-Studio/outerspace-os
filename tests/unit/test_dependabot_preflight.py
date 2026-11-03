# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import fnmatch
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'build/tools'))
import dependabot_preflight as preflight


class DependabotPreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.now = datetime(2026, 11, 3, tzinfo=timezone.utc)
        self.policy = {'exception_approvers': ['reviewer'], 'exception_max_days': 30,
                       'blocking_severities': ['Critical', 'High', 'Unknown']}
        self.alert = {
            'number': 10, 'state': 'open', 'html_url': 'https://github.com/example/repo/security/dependabot/10',
            'updated_at': '2026-11-01T00:00:00Z',
            'dependency': {'package': {'name': 'example.org/module'},
                           'manifest_path': 'build/runtime/crictl/go.mod'},
            'security_advisory': {'ghsa_id': 'GHSA-abcd-2345-6789', 'severity': 'high',
                                  'updated_at': '2026-10-31T00:00:00Z'},
            'security_vulnerability': {'severity': 'high', 'vulnerable_version_range': '< 2.0.0'},
        }
        for name in preflight.material_paths(self.alert['dependency']['manifest_path']):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('locked ' + name)
        self.review = {
            'number': 10, 'ghsa': 'GHSA-abcd-2345-6789', 'package': 'example.org/module',
            'manifest': 'build/runtime/crictl/go.mod', 'decision': 'not-affected', 'severity': 'high',
            'advisory_updated_at': '2026-10-31T00:00:00Z', 'alert_updated_at': '2026-11-01T00:00:00Z',
            'vulnerable_range': '< 2.0.0',
            'owner': 'reviewer', 'approved_by': 'reviewer',
            'reviewed_at': (self.now - timedelta(days=1)).isoformat(),
            'expires_at': (self.now + timedelta(days=5)).isoformat(),
            'rationale': 'The affected daemon is not included in this specific executable.',
            'evidence': ['https://example.org/evidence'],
            'materials': preflight.material_digests(self.root, 'build/runtime/crictl/go.mod'),
        }

    def evaluate(self, alerts, reviews):
        return preflight.evaluate(alerts, {'schema': 1, 'reviews': reviews}, self.root, self.policy, self.now)

    def test_unreviewed_high_and_unknown_block_but_low_is_reported(self):
        low, unknown = copy.deepcopy(self.alert), copy.deepcopy(self.alert)
        low['number'], low['security_vulnerability']['severity'] = 11, 'low'
        low['security_advisory']['severity'] = 'low'
        unknown['number'], unknown['security_vulnerability']['severity'] = 12, 'unrecognized'
        result = self.evaluate([self.alert, low, unknown], [])
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['blockers'], [10, 12])
        self.assertEqual(len(result['alerts']), 3)

    def test_uses_the_more_severe_advisory_and_blocks_missing_severity(self):
        alert = copy.deepcopy(self.alert)
        alert['security_vulnerability']['severity'] = 'low'
        self.assertEqual(self.evaluate([alert], [])['blockers'], [10])
        del alert['security_advisory']['severity']
        result = self.evaluate([alert], [])
        self.assertEqual(result['alerts'][0]['severity'], 'unknown')
        self.assertEqual(result['blockers'], [10])

    def test_policy_can_raise_but_not_lower_minimum_blocking_threshold(self):
        alert = copy.deepcopy(self.alert)
        alert['security_advisory']['severity'] = alert['security_vulnerability']['severity'] = 'medium'
        self.assertEqual(self.evaluate([alert], [])['status'], 'pass')
        self.policy['blocking_severities'].append('Medium')
        self.assertEqual(self.evaluate([alert], [])['status'], 'blocked')
        self.policy['blocking_severities'].remove('High')
        with self.assertRaises(ValueError):
            self.evaluate([alert], [])

    def test_previewed_target_version_does_not_automatically_resolve_alert(self):
        path = self.root / 'build/runtime/crictl-dependencies.lock.json'
        path.write_text(json.dumps({'schema': 1, 'component': 'crictl',
                                    'modules': [{'path': 'example.org/module', 'version': 'v2.0.0'}]}))
        alert = copy.deepcopy(self.alert)
        alert['security_vulnerability']['first_patched_version'] = {'identifier': '2.0.0'}
        result = self.evaluate([alert], [])
        self.assertEqual(result['alerts'][0]['target_version'], 'v2.0.0')
        self.assertEqual(result['alerts'][0]['first_patched_version'], '2.0.0')
        self.assertEqual(result['blockers'], [10])

    def test_valid_review_is_exact_scoped_and_expires(self):
        result = self.evaluate([self.alert], [self.review])
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['alerts'][0]['review']['approved_by'], 'reviewer')
        self.assertEqual(result['alerts'][0]['review']['rationale'], self.review['rationale'])
        for field, value in [('number', 20), ('ghsa', 'GHSA-eeee-ffff-2222'),
                             ('advisory_updated_at', '2026-10-30T00:00:00Z'),
                             ('alert_updated_at', '2026-10-30T00:00:00Z'),
                             ('vulnerable_range', '< 3.0.0'), ('severity', 'low'),
                             ('approved_by', 'other'), ('decision', 'fixed'),
                             ('expires_at', (self.now - timedelta(seconds=1)).isoformat()),
                             ('rationale', 'short'), ('evidence', ['http://insecure'])]:
            altered = copy.deepcopy(self.review)
            altered[field] = value
            with self.subTest(field=field):
                self.assertEqual(self.evaluate([self.alert], [altered])['status'], 'blocked')
        (self.root / 'build/runtime/crictl/go.mod').write_text('changed dependency')
        self.assertEqual(self.evaluate([self.alert], [self.review])['status'], 'blocked')

    def test_dismissed_high_still_requires_source_bound_review(self):
        for state in ('dismissed', 'auto_dismissed'):
            alert = copy.deepcopy(self.alert)
            alert['state'] = state
            self.assertEqual(self.evaluate([alert], [])['status'], 'blocked')
            self.assertEqual(self.evaluate([alert], [self.review])['status'], 'pass')

    def test_removed_manifest_can_be_reviewed_but_reappearing_invalidates_it(self):
        manifest = self.root / 'build/runtime/crictl/go.mod'
        manifest.unlink()
        review = copy.deepcopy(self.review)
        review['materials'] = preflight.material_digests(self.root, review['manifest'])
        self.assertEqual(review['materials'][review['manifest']], 'absent')
        self.assertEqual(self.evaluate([self.alert], [review])['status'], 'pass')
        manifest.write_text('module restored')
        self.assertEqual(self.evaluate([self.alert], [review])['status'], 'blocked')

    def test_malformed_duplicate_and_unsafe_inputs_fail_closed(self):
        for name in ('../escape', '/absolute', 'build/../escape'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                preflight.material_paths(name)
        with self.assertRaises(ValueError):
            self.evaluate([self.alert, self.alert], [])
        with self.assertRaises(ValueError):
            self.evaluate([self.alert], [self.review, self.review])
        bad = copy.deepcopy(self.alert)
        del bad['security_advisory']
        with self.assertRaises(ValueError):
            self.evaluate([bad], [])

    def test_snapshot_checks_default_branch_before_and_after_paginated_alerts(self):
        commit = 'a' * 40
        responses = [{'default_branch': 'main'}, {'sha': commit}, [[self.alert]], {'sha': commit}]
        with patch.object(preflight, 'require_alerts_enabled'), patch.object(preflight, 'gh_json', side_effect=responses):
            branch, default_head, alerts = preflight.github_snapshot('owner/repo', commit)
        self.assertEqual(branch, 'main')
        self.assertEqual(default_head, commit)
        self.assertEqual(alerts, [self.alert])
        responses[-1] = {'sha': 'b' * 40}
        with patch.object(preflight, 'require_alerts_enabled'), patch.object(preflight, 'gh_json', side_effect=responses), self.assertRaisesRegex(ValueError, 'changed'):
            preflight.github_snapshot('owner/repo', commit)

    def test_preview_may_inspect_another_commit_but_is_not_the_release_check(self):
        default, target = 'a' * 40, 'b' * 40
        responses = [{'default_branch': 'main'}, {'sha': default}, [[]], {'sha': default}]
        with patch.object(preflight, 'require_alerts_enabled'), patch.object(preflight, 'gh_json', side_effect=responses):
            branch, observed, alerts = preflight.github_snapshot('owner/repo', target, preview=True)
        self.assertEqual((branch, observed, alerts), ('main', default, []))
        with patch.object(preflight, 'require_alerts_enabled'), patch.object(preflight, 'gh_json', side_effect=responses), self.assertRaisesRegex(ValueError, 'default branch'):
            preflight.github_snapshot('owner/repo', target)

    def test_api_or_json_failure_is_not_treated_as_no_alerts(self):
        result = type('Result', (), {'returncode': 1, 'stdout': ''})()
        with patch.object(preflight.subprocess, 'run', return_value=result), self.assertRaisesRegex(ValueError, 'permission'):
            preflight.gh_json('some-endpoint')
        result.returncode, result.stdout = 0, '{not json}'
        with patch.object(preflight.subprocess, 'run', return_value=result), self.assertRaisesRegex(ValueError, 'JSON'):
            preflight.gh_json('some-endpoint')
        result.returncode = 1
        with patch.object(preflight.subprocess, 'run', return_value=result), self.assertRaisesRegex(ValueError, 'disabled'):
            preflight.require_alerts_enabled('owner/repo')

    def test_blocked_cli_writes_report_and_preview_never_claims_release_pass(self):
        (self.root / 'build/release').mkdir(parents=True)
        (self.root / 'build/security').mkdir(parents=True)
        (self.root / 'build/release/dependabot-reviews.json').write_text(json.dumps({'schema': 1, 'reviews': []}))
        (self.root / 'build/security/policy.json').write_text(json.dumps(self.policy))
        commit = 'a' * 40
        report = self.root / 'out/report.json'
        args = ['preflight', '--repo', 'owner/repo', '--commit', commit, '--report', str(report)]
        with patch.object(preflight, 'ROOT', self.root), \
                patch.object(preflight.subprocess, 'check_output', side_effect=[commit + '\n', '']), \
                patch.object(preflight, 'github_snapshot', return_value=('main', commit, [self.alert])), \
                patch.object(sys, 'argv', args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as stopped:
            preflight.main()
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(json.loads(report.read_text())['blockers'], [10])
        with patch.object(preflight, 'ROOT', self.root), \
                patch.object(preflight.subprocess, 'check_output', side_effect=[commit + '\n', '']), \
                patch.object(preflight, 'github_snapshot', return_value=('main', 'b' * 40, [])), \
                patch.object(sys, 'argv', args + ['--preview']), redirect_stdout(io.StringIO()):
            preflight.main()
        self.assertEqual(json.loads(report.read_text())['status'], 'preview')

    def test_all_frozen_go_manifests_are_covered_by_the_dependabot_update_exclusion(self):
        root = Path(__file__).resolve().parents[2]
        config = (root / '.github/dependabot.yml').read_text()
        self.assertEqual(config.count('  - package-ecosystem: gomod\n'), 1)
        block = config.split('  - package-ecosystem: gomod\n', 1)[1].split('\n  - package-ecosystem:', 1)[0]
        self.assertIn('    open-pull-requests-limit: 0\n', block)
        self.assertIn('      - dependency-name: "*"\n', block)
        patterns = [line.strip()[2:] for line in block.splitlines()
                    if line.startswith('      - /build/runtime/')]
        manifests = list((root / 'build/runtime').rglob('go.mod'))
        self.assertTrue(manifests)
        for manifest in manifests:
            directory = '/' + str(manifest.parent.relative_to(root))
            with self.subTest(directory=directory):
                self.assertTrue(any(fnmatch.fnmatchcase(directory, pattern) for pattern in patterns))


if __name__ == '__main__':
    unittest.main()
