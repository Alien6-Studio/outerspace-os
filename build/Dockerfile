FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

ENV DEBIAN_FRONTEND=noninteractive
COPY build/apt.sources /etc/apt/sources.list.d/ubuntu.sources
# Docker fetches this approved package with HTTPS before the minimal base has
# certificates. Only extract its CA data; normal APT installs the package below.
ADD --checksum=sha256:8a0a754aaafed72cc8efb8c1731808133284a84fbfc76a4fcc73fce9e01b4187 https://snapshot.ubuntu.com/ubuntu/20261027T000000Z/pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.24.04.1_all.deb /tmp/ca.deb
RUN dpkg-deb --extract /tmp/ca.deb /tmp/ca \
    && mkdir -p /etc/ssl/certs \
    && cat /tmp/ca/usr/share/ca-certificates/mozilla/*.crt > /etc/ssl/certs/ca-certificates.crt \
    && rm -rf /tmp/ca /tmp/ca.deb
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt ca-certificates curl python3 \
    systemd systemd-container systemd-ukify systemd-boot-efi udev \
    ubuntu-keyring bubblewrap binutils cpio kmod jq \
    btrfs-progs cryptsetup-bin dosfstools e2fsprogs fdisk squashfs-tools \
    util-linux xz-utils zstd mtools qemu-utils qemu-system-x86 qemu-system-arm ovmf qemu-efi-aarch64 \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/systemd/mkosi/archive/refs/tags/v25.3.tar.gz -o /tmp/mkosi.tar.gz \
    && echo '7b039fb3b34e1680173a7f4af1bc24b475465afe335c8b21c213167734061e35  /tmp/mkosi.tar.gz' | sha256sum -c - \
    && mkdir /opt/mkosi && tar -xzf /tmp/mkosi.tar.gz --strip-components=1 -C /opt/mkosi \
    && ln -s /opt/mkosi/bin/mkosi /usr/local/bin/mkosi \
    && rm /tmp/mkosi.tar.gz
ENV PYTHONPATH=/opt/mkosi
COPY build/inputs.lock.json /opt/outerspace/inputs.lock.json
COPY build/apt.sources /opt/outerspace/sandbox/etc/apt/sources.list.d/mkosi.sources
COPY build/sbom/syft.lock.json /opt/outerspace/syft.lock.json
COPY build/sbom/grype.lock.json /opt/outerspace/grype.lock.json
COPY build/tools/install-syft.py /opt/outerspace/install-syft.py
RUN python3 /opt/outerspace/install-syft.py /opt/outerspace/syft.lock.json /usr/local/bin/syft
RUN python3 /opt/outerspace/install-syft.py /opt/outerspace/grype.lock.json /usr/local/bin/grype
RUN apt-get update && apt-get install -y --no-install-recommends systemd-boot \
    && rm -rf /var/lib/apt/lists/*
RUN dpkg-query --show --showformat='${Package}\t${Version}\t${Architecture}\n' > /opt/outerspace/builder-packages.tsv
WORKDIR /repo
LABEL io.outerspace.tooling=true
