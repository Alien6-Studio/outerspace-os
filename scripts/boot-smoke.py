#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Boot split kernel/initrd with the UKI command line using QEMU TCG."""
from pathlib import Path
import platform
import subprocess
import sys
import tempfile


def boot(output):
    kernels = list(output.glob("*.efi"))
    disks = list(output.glob("*.raw"))
    linux = list(output.glob("*.vmlinuz"))
    initrds = list(output.glob("*.initrd"))
    if not all(len(items) == 1 for items in [kernels, disks, linux, initrds]):
        raise ValueError("Expected one UKI, raw disk, split vmlinuz and split initrd")
    with tempfile.TemporaryDirectory() as directory:
        cmdline = Path(directory) / "cmdline"
        subprocess.run(["objcopy", "--dump-section", f".cmdline={cmdline}", str(kernels[0]), str(Path(directory) / "inspected.efi")], check=True)
        command_line = cmdline.read_bytes().rstrip(b"\x00").decode() + " outerspace.selftest=1"
    arch = platform.machine()
    args = ["-m", "1024", "-smp", "2", "-nographic", "-no-reboot",
            "-kernel", str(linux[0]), "-initrd", str(initrds[0]),
            "-append", command_line,
            "-drive", f"file={disks[0]},format=raw,if=virtio,snapshot=on",
            "-nic", "user,model=virtio-net-pci"]
    if arch == "aarch64":
        args = ["qemu-system-aarch64", "-machine", "virt", "-cpu", "max"] + args
    elif arch == "x86_64":
        args = ["qemu-system-x86_64", "-machine", "q35", "-accel", "tcg"] + args
    else:
        raise ValueError(f"Unsupported host: {arch}")
    # The UKI's embedded command line supplies the expected verity root hash.
    # A separate release gate must exercise EFI disk boot and Secure Boot.
    with (output / "boot-smoke.log").open("w") as log:
        try:
            result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, timeout=420)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Boot timed out; inspect build/boot-smoke.log") from None
    content = (output / "boot-smoke.log").read_text(errors="replace")
    print(content[-18000:])
    if result.returncode or "OUTERSPACE_SELFTEST_OK" not in content or "OUTERSPACE_SELFTEST_FAIL" in content:
        raise RuntimeError("Boot verification failed")


if __name__ == "__main__":
    boot(Path(sys.argv[1]))
