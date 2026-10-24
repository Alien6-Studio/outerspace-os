# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("node_config", ROOT / "build/tools/node-config.py")
node_config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node_config)


class WorkerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ca = self.root / "ca.pem"
        self.ca.write_text("fixture certificate")
        self.token = self.root / "token"
        self.token.write_text("abcdef.0123456789abcdef\n")
        self.output = self.root / "worker"

    def render(self, server="https://api.example.test:6443", dns=None):
        return node_config.render(server, self.ca, self.token, dns or ["10.96.0.10"], "cluster.local", self.output)

    @patch.object(node_config, "validate_ca")
    def test_ca_authentication_dns_and_private_file_modes(self, validate_ca):
        self.render()
        bootstrap = json.loads((self.output / "bootstrap-kubeconfig").read_text())
        self.assertEqual(bootstrap["users"][0]["user"]["token"], "abcdef.0123456789abcdef")
        self.assertNotIn("insecure-skip-tls-verify", bootstrap["clusters"][0]["cluster"])
        kubelet = json.loads((self.output / "kubelet.yaml").read_text())
        self.assertEqual(kubelet["clusterDNS"], ["10.96.0.10"])
        self.assertFalse(kubelet["authentication"]["anonymous"]["enabled"])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for path in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        validate_ca.assert_called_once()

    def test_rejects_insecure_or_credential_bearing_api_before_writing(self):
        for server in ["http://api.test:6443", "https://user:password@api.test", "https://api.test/path", "https://api.test?token=secret", "https://api.test:99999"]:
            with self.subTest(server=server), self.assertRaises(ValueError):
                self.render(server)
        self.assertFalse(self.output.exists())

    def test_rejects_bad_dns_or_token_before_writing(self):
        with self.assertRaises(ValueError):
            self.render(dns=["not-an-ip"])
        self.token.write_text("$(touch /tmp/pwned)")
        with self.assertRaises(ValueError):
            self.render()
        self.assertFalse(self.output.exists())

    def test_rejects_invalid_ca(self):
        with self.assertRaises(ValueError):
            self.render()
        self.assertFalse(self.output.exists())

    @patch.object(node_config, "validate_ca")
    def test_refuses_to_overwrite_existing_identity(self, _):
        self.output.mkdir()
        (self.output / "identity").write_text("existing")
        with self.assertRaises(FileExistsError):
            self.render()
        self.assertEqual((self.output / "identity").read_text(), "existing")

    @patch.object(node_config, "validate_ca")
    def test_retention_and_p2p_registry_routing(self, _):
        node_config.render("https://api.test:6443", self.ca, self.token, ["10.96.0.10"],
                           "cluster.local", self.output, "48h", "https://manager.test:65003", ["docker.io", "ghcr.io"])
        config = json.loads((self.output / "kubelet.yaml").read_text())
        self.assertEqual(config["imageMaximumGCAge"], "48h")
        self.assertEqual(config["imageMinimumGCAge"], "10m")
        hosts = tomllib.loads((self.output / "certs.d/docker.io/hosts.toml").read_text())
        self.assertEqual(hosts["server"], "https://registry-1.docker.io")
        self.assertEqual(hosts["host"]["http://127.0.0.1:4001"]["capabilities"], ["pull"])
        self.assertNotIn("skip_verify", (self.output / "certs.d/docker.io/hosts.toml").read_text())
        peer = json.loads((self.output / "dfdaemon.yaml").read_text())
        self.assertEqual(peer["proxy"]["server"]["ip"], "127.0.0.1")
        self.assertEqual(peer["gc"]["policy"]["taskTTL"], "6h")

    def test_rejects_unsafe_p2p_origins_and_registry_paths(self):
        for manager, registries in [("http://manager.test", ["ghcr.io"]), ("https://manager.test", ["../../escape"]),
                                    ("https://manager.test", ["registry.test:99999"]), ("https://manager.test", [])]:
            with self.subTest(registries=registries), self.assertRaises(ValueError):
                node_config.dragonfly_config(manager, registries, "6h")

    def test_rejects_too_short_or_invalid_retention_before_writing(self):
        for age in ["0s", "5m", "invalid", "-1h"]:
            with self.subTest(age=age), self.assertRaises(ValueError):
                node_config.render("https://api.test", self.ca, self.token, ["10.96.0.10"],
                                   "cluster.local", self.output, age)
        self.assertFalse(self.output.exists())
