#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Fail the image build if the kernel lacks the selected eBPF/Cilium primitives."""
from pathlib import Path
import sys

REQUIRED = (
    "CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_JIT", "CONFIG_BPF_EVENTS",
    "CONFIG_CGROUPS", "CONFIG_CGROUP_BPF", "CONFIG_NET_CLS_BPF",
    "CONFIG_NET_CLS_ACT", "CONFIG_NET_SCH_INGRESS", "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_PERF_EVENTS", "CONFIG_VXLAN", "CONFIG_GENEVE", "CONFIG_FIB_RULES",
    "CONFIG_SECURITY_APPARMOR", "CONFIG_SECCOMP", "CONFIG_SECCOMP_FILTER",
)


def check(config):
    values = dict(line.split("=", 1) for line in config.splitlines() if line.startswith("CONFIG_") and "=" in line)
    missing = [name for name in REQUIRED if values.get(name) not in ("y", "m")]
    if missing:
        raise ValueError("Kernel lacks required capabilities: " + ", ".join(missing))


if __name__ == "__main__":
    configs = list((Path(sys.argv[1]) / "boot").glob("config-*"))
    if not configs:
        raise SystemExit("No installed kernel configuration found")
    for config in configs:
        check(config.read_text())
        print(f"Kernel capability check passed: {config.name}")
