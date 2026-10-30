#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
set -euo pipefail
profile=${1:?Select a profile}
hardware=${2:?Select a hardware profile}
python3 /repo/build/tools/profiles.py directory --profile "$profile" --hardware "$hardware"
cmp /repo/build/inputs.lock.json /opt/outerspace/inputs.lock.json
cmp /repo/build/apt.sources /opt/outerspace/sandbox/etc/apt/sources.list.d/mkosi.sources
profiles="$profile"
if [[ "$hardware" == cpu-full-firmware ]]; then profiles+=,full-firmware; fi
python3 /repo/build/tools/install-components.py fetch /cache/components "$(uname -m)" /repo/src/components.lock.json
arch=$(python3 -c 'import platform; print({"aarch64":"arm64", "x86_64":"amd64"}[platform.machine()])')
python3 /repo/build/tools/runtime_build.py fetch --cache /cache --architecture "$arch"
unshare --net python3 /repo/build/tools/runtime_build.py prepare --cache /cache --architecture "$arch" --output /out
runtime_path=$(python3 /repo/build/tools/runtime_build.py path --cache /cache --architecture "$arch")
python3 /repo/build/tools/go_runtime_build.py fetch --cache /cache --architecture "$arch"
unshare --net python3 /repo/build/tools/go_runtime_build.py prepare --cache /cache --architecture "$arch" --output /out
go_runtime_path=$(python3 /repo/build/tools/go_runtime_build.py path --cache /cache --architecture "$arch")
python3 /repo/build/tools/go_runtime_build.py fetch --cache /cache --architecture "$arch" --component containerd
unshare --net python3 /repo/build/tools/go_runtime_build.py prepare --cache /cache --architecture "$arch" --component containerd --output /out
containerd_path=$(python3 /repo/build/tools/go_runtime_build.py path --cache /cache --architecture "$arch" --component containerd)
# mkosi mounts the repository at /work/src in its script sandbox.
mkosi --directory=/repo/src/image --profile="$profiles" --image-version="$(cat /repo/VERSION)" \
    --environment="OUTERSPACE_SOURCE_COMMIT=${OUTERSPACE_SOURCE_COMMIT:?Missing source identity}" \
    --environment="OUTERSPACE_HARDWARE_PROFILE=$hardware" \
    --environment="OUTERSPACE_RUNTIME_BUILD=/work/src/.cache/${runtime_path#/cache/}" \
    --environment="OUTERSPACE_GO_RUNTIME_BUILD=/work/src/.cache/${go_runtime_path#/cache/}" \
    --environment="OUTERSPACE_CONTAINERD_BUILD=/work/src/.cache/${containerd_path#/cache/}" \
    --build-sources=/repo \
    --sandbox-tree=/opt/outerspace/sandbox \
    --force \
    build
cp /source.tar /out/outerspace-source.tar
python3 /repo/build/tools/profiles.py stamp --root=/out --profile "$profile" --hardware "$hardware" \
    --commit "$OUTERSPACE_SOURCE_COMMIT"
# Scan the completed disk, offline and read-only, with tooling outside the host.
unshare --net python3 /repo/build/tools/sbom.py --output=/out --profile "$profile" --hardware "$hardware" \
    --commit "$OUTERSPACE_SOURCE_COMMIT"
python3 /repo/build/tools/source-bundle.py --cache=/cache/source-inputs --output=/out --apt-inputs=/out/apt-inputs.json
unshare --net python3 /repo/build/tools/supply_chain.py --output=/out
python3 /repo/build/tools/redistribution.py --output=/out
GRYPE_DB_CACHE_DIR=/cache/grype-db grype db update --config /repo/build/sbom/grype.yaml
unshare --net python3 /repo/build/tools/security.py --output=/out --database=/cache/grype-db
