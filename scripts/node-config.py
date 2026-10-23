#!/usr/bin/env python3
"""Render a worker config drive without putting a bootstrap token in argv/logs."""
import argparse
import base64
import ipaddress
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit


def https_origin(server):
    endpoint = urlsplit(server)
    if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.username
            or endpoint.password or endpoint.path not in ("", "/")
            or endpoint.query or endpoint.fragment):
        raise ValueError("API server must be an HTTPS origin without credentials")
    # Also validate port syntax/range before writing any sensitive files.
    endpoint.port
    return server.rstrip("/")


def duration_seconds(value):
    if not re.fullmatch(r"(?:[0-9]+[hms])+", value):
        raise ValueError("Durations must use positive hours, minutes or seconds, e.g. 24h or 10m")
    return sum(int(amount) * {"h": 3600, "m": 60, "s": 1}[unit]
               for amount, unit in re.findall(r"([0-9]+)([hms])", value))


def dragonfly_config(manager, registries, cache_ttl):
    manager = https_origin(manager)
    if duration_seconds(cache_ttl) <= 0:
        raise ValueError("P2P cache TTL must be positive")
    hosts = {}
    for registry in registries:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]+)?", registry):
            raise ValueError("P2P registries must be lowercase hostnames, optionally with a port")
        origin = https_origin("https://" + registry)
        if registry == "docker.io":
            origin = "https://registry-1.docker.io"
        # Only blob pulling is delegated; tag resolution and fallback keep origin trust.
        hosts[registry] = (f'server = {json.dumps(origin)}\n\n'
                           '[host."http://127.0.0.1:4001"]\n'
                           '  capabilities = ["pull"]\n'
                           '[host."http://127.0.0.1:4001".header]\n'
                           f'  X-Dragonfly-Registry = [{json.dumps(origin)}]\n')
    if not hosts:
        raise ValueError("At least one explicit P2P registry is required")
    config = {
        "manager": {"addr": manager}, "seedPeer": {"enable": False},
        "server": {"pluginDir": "/var/lib/dragonfly/plugins", "cacheDir": "/var/cache/dragonfly"},
        "download": {"server": {"socketPath": "/run/dragonfly/dfdaemon.sock"}},
        "upload": {"server": {"port": 4000}, "bandwidthLimit": "200MB"},
        "storage": {"dir": "/var/lib/dragonfly", "keep": True},
        "gc": {"interval": "5m", "policy": {
            "taskTTL": cache_ttl, "diskHighThresholdPercent": 70, "diskLowThresholdPercent": 50}},
        "proxy": {"server": {"ip": "127.0.0.1", "port": 4001},
                  "rules": [{"regex": "blobs/sha256.*", "useTLS": True}],
                  "registryMirror": {"addr": "https://registry-1.docker.io"},
                  "disableBackToSource": False},
        "health": {"server": {"ip": "127.0.0.1"}},
        "metrics": {"server": {"ip": "127.0.0.1"}},
        "stats": {"server": {"ip": "127.0.0.1"}},
    }
    return config, hosts


def validate_ca(ca):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cadata=ca)
    except ssl.SSLError as exc:
        raise ValueError("Cluster CA is not a valid PEM certificate") from exc


def render(server, ca_file, token_file, cluster_dns, domain, output,
           image_max_age="24h", dragonfly_manager=None, p2p_registries=(), p2p_cache_ttl="6h"):
    server = https_origin(server)
    if duration_seconds(image_max_age) <= 600:
        raise ValueError("Unused image retention must exceed the 10m minimum GC age")
    if bool(dragonfly_manager) != bool(p2p_registries):
        raise ValueError("Dragonfly requires a manager and at least one explicit registry")
    p2p = dragonfly_config(dragonfly_manager, p2p_registries, p2p_cache_ttl) if dragonfly_manager else None
    dns = [str(ipaddress.ip_address(item)) for item in cluster_dns]
    if not dns or not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", domain):
        raise ValueError("A cluster DNS IP and valid cluster domain are required")
    token = token_file.read_text().strip()
    if not re.fullmatch(r"[a-z0-9]{6}\.[a-z0-9]{16}", token):
        raise ValueError("Invalid Kubernetes bootstrap token format")
    ca = ca_file.read_text()
    validate_ca(ca)
    config = json.loads((Path(__file__).resolve().parents[1] / "image/mkosi.extra/etc/outerspace/kubelet.yaml").read_text())
    config.update(clusterDNS=dns, clusterDomain=domain)
    config["imageMaximumGCAge"] = image_max_age
    bootstrap = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "cluster", "cluster": {
            "server": server.rstrip("/"),
            "certificate-authority-data": base64.b64encode(ca.encode()).decode()}}],
        "users": [{"name": "bootstrap", "user": {"token": token}}],
        "contexts": [{"name": "bootstrap", "context": {"cluster": "cluster", "user": "bootstrap"}}],
        "current-context": "bootstrap",
    }
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, content in {
        "cluster-ca.crt": ca,
        "bootstrap-kubeconfig": json.dumps(bootstrap, indent=2) + "\n",
        "kubelet.yaml": json.dumps(config, indent=2) + "\n",
    }.items():
        path = output / name
        path.touch(mode=0o600, exist_ok=False)
        path.write_text(content)
    if p2p:
        peer, hosts = p2p
        path = output / "dfdaemon.yaml"
        path.touch(mode=0o600)
        path.write_text(json.dumps(peer, indent=2) + "\n")
        for registry, content in hosts.items():
            directory = output / "certs.d" / registry
            directory.mkdir(parents=True, mode=0o700)
            (directory / "hosts.toml").touch(mode=0o600)
            (directory / "hosts.toml").write_text(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-server", required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--cluster-dns", action="append", required=True)
    parser.add_argument("--cluster-domain", default="cluster.local")
    parser.add_argument("--output", type=Path, default=Path("node-config"))
    parser.add_argument("--image-max-age", default="24h", help="Unused image retention, e.g. 24h")
    parser.add_argument("--dragonfly-manager", help="HTTPS Dragonfly Manager endpoint")
    parser.add_argument("--p2p-registry", action="append", default=[], help="Registry hostname to route through the local peer")
    parser.add_argument("--p2p-cache-ttl", default="6h", help="Dragonfly task idle TTL")
    args = parser.parse_args()
    try:
        render(args.api_server, args.ca, args.token_file, args.cluster_dns, args.cluster_domain, args.output,
               args.image_max_age, args.dragonfly_manager, args.p2p_registry, args.p2p_cache_ttl)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Cannot generate node configuration: {exc}\n")
    print(f"Worker configuration written to {args.output} (contains a bootstrap token)")


if __name__ == "__main__":
    main()
