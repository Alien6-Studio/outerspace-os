# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ci_scope', Path(__file__).resolve().parents[2] / 'build/tools/ci-scope.py')
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


class CIScopeTests(unittest.TestCase):
    def test_docs_only_can_skip_but_mixed_changes_cannot(self):
        docs = ['README.md', 'build/README.md', 'src/docs/architecture.md', '.github/ISSUE_TEMPLATE/bug_report.yml']
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
        for path in ['src/docs/../image/README.md', '/README.md', 'src/docs/data.json']:
            self.assertTrue(scope.requires_images('push', [path]))

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
