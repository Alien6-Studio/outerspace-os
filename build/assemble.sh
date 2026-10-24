#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
set -euo pipefail
profile=${1:?Select a profile}
hardware=${2:?Select a hardware profile}
python3 /repo/build/tools/profiles.py directory --profile "$profile" --hardware "$hardware"
profiles="$profile"
if [[ "$hardware" == cpu-full-firmware ]]; then profiles+=,full-firmware; fi
python3 /repo/build/tools/install-components.py fetch /cache/components "$(uname -m)" /repo/src/components.lock.json
# mkosi mounts the repository at /work/src in its script sandbox.
mkosi --directory=/repo/src/image --profile="$profiles" --image-version="$(cat /repo/VERSION)" \
    --environment="OUTERSPACE_SOURCE_COMMIT=${OUTERSPACE_SOURCE_COMMIT:?Missing source identity}" \
    --environment="OUTERSPACE_HARDWARE_PROFILE=$hardware" \
    --build-sources=/repo \
    --force \
    build
cp /source.tar /out/outerspace-source.tar
python3 /repo/build/tools/profiles.py stamp --root=/out --profile "$profile" --hardware "$hardware" \
    --commit "$OUTERSPACE_SOURCE_COMMIT"
