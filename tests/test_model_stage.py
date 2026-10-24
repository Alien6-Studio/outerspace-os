# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('model_stage', Path(__file__).parent / 'integration/model-stage.py')
model_stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model_stage)


class ModelStagingTests(unittest.TestCase):
    payload = b'GGUF' + b'bounded model fixture'

    def test_valid_retained_cache_never_uses_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'model.gguf'
            path.write_bytes(self.payload)
            fingerprint = hashlib.sha256(self.payload).hexdigest()
            with patch.object(model_stage.urllib.request, 'urlopen', side_effect=AssertionError('Offline cache used network')):
                self.assertEqual(model_stage.stage(path, 'http://unreachable.invalid/', len(self.payload), fingerprint), 'verified-cache')
            self.assertEqual(path.read_bytes(), self.payload)

    def test_tampered_or_symlinked_cache_is_refused_without_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'model.gguf'
            fingerprint = hashlib.sha256(self.payload).hexdigest()
            path.write_bytes(self.payload[:-1] + b'!')
            with patch.object(model_stage.urllib.request, 'urlopen') as network:
                with self.assertRaises(ValueError):
                    model_stage.stage(path, 'http://source/', len(self.payload), fingerprint)
                network.assert_not_called()
                link = path.with_name('link.gguf')
                link.symlink_to(path)
                with self.assertRaises(ValueError):
                    model_stage.stage(link, 'http://source/', len(self.payload), fingerprint)
                network.assert_not_called()

    def test_private_download_is_bounded_verified_and_atomic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'model.gguf'
            fingerprint = hashlib.sha256(self.payload).hexdigest()
            with patch.object(model_stage.urllib.request, 'urlopen', return_value=io.BytesIO(self.payload)):
                self.assertEqual(model_stage.stage(path, 'http://source/', len(self.payload), fingerprint), 'private-source')
            self.assertEqual(path.read_bytes(), self.payload)
            for index, invalid in enumerate([self.payload + b'!', self.payload[:-1], b'BAD!' + self.payload[4:]]):
                rejected = root / f'rejected-{index}.gguf'
                with patch.object(model_stage.urllib.request, 'urlopen', return_value=io.BytesIO(invalid)), self.assertRaises(ValueError):
                    model_stage.stage(rejected, 'http://source/', len(self.payload), fingerprint)
                self.assertFalse(rejected.exists())
            self.assertEqual({p.name for p in root.iterdir()}, {'model.gguf'})
