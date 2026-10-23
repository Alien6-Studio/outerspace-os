FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt ca-certificates curl python3 \
    systemd systemd-container systemd-ukify systemd-boot-efi udev \
    ubuntu-keyring bubblewrap binutils cpio kmod jq \
    btrfs-progs cryptsetup-bin dosfstools e2fsprogs fdisk squashfs-tools \
    util-linux xz-utils zstd mtools qemu-system-x86 qemu-system-arm ovmf qemu-efi-aarch64 \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/systemd/mkosi/archive/refs/tags/v25.3.tar.gz -o /tmp/mkosi.tar.gz \
    && echo '7b039fb3b34e1680173a7f4af1bc24b475465afe335c8b21c213167734061e35  /tmp/mkosi.tar.gz' | sha256sum -c - \
    && mkdir /opt/mkosi && tar -xzf /tmp/mkosi.tar.gz --strip-components=1 -C /opt/mkosi \
    && ln -s /opt/mkosi/bin/mkosi /usr/local/bin/mkosi \
    && rm /tmp/mkosi.tar.gz
ENV PYTHONPATH=/opt/mkosi
RUN apt-get update && apt-get install -y --no-install-recommends systemd-boot \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work/image
