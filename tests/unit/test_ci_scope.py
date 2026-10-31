# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ci_scope', Path(__file__).resolve().parents[2] / 'build/tools/ci-scope.py')
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


class CIScopeTests(unittest.TestCase):
    def test_required_gate_includes_complete_image_qualification(self):
        workflow = (Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml').read_text()
        gate = workflow.split('  ci:\n', 1)[1]
        self.assertIn('needs: [contracts, image]', gate)
        script = textwrap.dedent(gate.split('        run: |\n', 1)[1])
        for required in ['true', 'false']:
            expected = 'success' if required == 'true' else 'skipped'
            values = {'CONTRACTS': 'success', 'IMAGES_REQUIRED': required,
                      'IMAGE_RESULT': expected}
            passed = subprocess.run(['bash', '-e', '-c', script], env={**os.environ, **values})
            self.assertEqual(passed.returncode, 0)
            for key in ['CONTRACTS', 'IMAGE_RESULT']:
                for result in ['success', 'failure', 'cancelled', 'skipped']:
                    if result == values[key]:
                        continue
                    with self.subTest(required=required, job=key, result=result):
                        changed = {**values, key: result}
                        failed = subprocess.run(['bash', '-e', '-c', script], env={**os.environ, **changed})
                        self.assertNotEqual(failed.returncode, 0)

    def test_native_or_phase_failure_fails_the_image_job(self):
        workflow = (Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml').read_text()
        step = workflow.split('      - name: Qualify the packaged worker on its own kernel\n', 1)[1]
        script = textwrap.dedent(step.split('        run: |\n', 1)[1].split('      - uses:', 1)[0])
        fake_make = 'make() { printf "%s\\n" "${*: -1}"; [[ "${*: -1}" != "$FAIL_TARGET" ]]; };\n'
        for profile, targets in [('agent', ['agent-resources', 'agent-phases']), ('inference', ['cpu-serving'])]:
            for failure in ['', *targets]:
                with self.subTest(profile=profile, failure=failure):
                    result = subprocess.run(['bash', '-e', '-c', fake_make + script.replace('${{ matrix.profile }}', profile)],
                        env={**os.environ, 'FAIL_TARGET': failure}, text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, not failure)
                    self.assertEqual(result.stdout.splitlines(), targets if not failure else targets[:targets.index(failure) + 1])

    def test_docs_only_can_skip_but_mixed_changes_cannot(self):
        # Both sides of a documentation move must remain documentation-only.
        docs = ['README.md', 'build/README.md', 'docs/architecture.md',
                'src/docs/architecture.md', '.github/ISSUE_TEMPLATE/bug_report.yml']
        self.assertFalse(scope.requires_images('pull_request', docs))
        for runtime in ['src/image/mkosi.conf', 'src/components.lock.json', 'tests/targets.mk',
                        'build/targets.mk', '.github/workflows/ci.yml', 'tests/unit/test_release.py', 'VERSION',
                        'src/third_party/containerd/NOTICE', 'new-unknown-file']:
            with self.subTest(path=runtime):
                self.assertTrue(scope.requires_images('pull_request', docs + [runtime]))

    def test_scheduled_manual_unknown_and_empty_changes_build(self):
        for event in ['schedule', 'workflow_dispatch', 'unknown']:
            self.assertTrue(scope.requires_images(event, ['README.md']))
        self.assertTrue(scope.requires_images('push', []))
        for path in ['src/docs/../image/README.md', 'docs/../src/image/README.md',
                     '/README.md', 'src/docs/data.json', 'docs/data.json']:
            self.assertTrue(scope.requires_images('push', [path]))

    def test_promotion_changes_reuse_images_but_never_skip_runtime_or_policy_changes(self):
        paths = ['build/tools/attestations.py', '.github/workflows/release.yml',
                 'build/tools/ci-scope.py', 'tests/unit/test_ci_scope.py',
                 'tests/unit/test_supply_chain.py']
        self.assertFalse(scope.requires_images('pull_request', paths))
        for image_input in ['build/tools/package.py', 'build/tools/prepare-release.py',
                            'build/security/policy.json', 'build/licenses/reviews.json',
                            'build/release/policy.json', 'src/kernel/kernel.config',
                            '.github/workflows/candidate.yml', '.github/workflows/ci.yml', 'VERSION']:
            with self.subTest(path=image_input):
                self.assertTrue(scope.requires_images('pull_request', paths + [image_input]))
        self.assertTrue(scope.requires_images('workflow_dispatch', paths))

    def test_git_diff_includes_deletions_renames_and_unusual_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], text=True).strip()
            git('init', '-q')
            git('config', 'user.email', 'test@example.invalid')
            git('config', 'user.name', 'Test')
            git('config', 'commit.gpgsign', 'false')
            # Isolate fixture commits from developer-machine hooks.
            hooks = root / 'empty-hooks'
            hooks.mkdir()
            git('config', 'core.hooksPath', str(hooks))
            (root / 'README.md').write_text('documentation')
            (root / 'runtime').write_text('runtime')
            git('add', '.')
            git('commit', '-qm', 'base')
            base = git('rev-parse', 'HEAD')
            (root / 'runtime').unlink()
            (root / 'README.md').rename(root / 'new\nfile')
            git('add', '-A')
            git('commit', '-qm', 'change')
            head = git('rev-parse', 'HEAD')
            run = subprocess.run
            with patch.object(scope.subprocess, 'run', side_effect=lambda *a, **k: run(*a, cwd=directory, **k)):
                paths = scope.changed_paths(base, head)
            self.assertEqual(set(paths), {'README.md', 'runtime', 'new\nfile'})
            self.assertTrue(scope.requires_images('pull_request', paths))

    def test_invalid_revision_cannot_become_a_git_option(self):
        for revision in ['', '0' * 40, '--output=/tmp/file']:
            with self.assertRaises(ValueError):
                scope.changed_paths(revision, 'a' * 40)

    def test_cli_falls_back_to_full_build_on_missing_diff(self):
        result = subprocess.run(
            [sys.executable, str(spec.origin), '--event', 'push'],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout, 'images=true\n')
        self.assertIn('classification unavailable', result.stderr)
