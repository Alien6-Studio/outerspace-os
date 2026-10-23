#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
set -euo pipefail
profile=${1:?Select a profile}
hardware=${2:?Select a hardware profile}
python3 /work/scripts/profiles.py directory --profile "$profile" --hardware "$hardware"
profiles="$profile"
if [[ "$hardware" == cpu-full-firmware ]]; then profiles+=,full-firmware; fi
python3 /work/scripts/install-components.py fetch /cache/components "$(uname -m)" /work/components.lock.json
mkosi --directory=/work/image --profile="$profiles" --image-version="$(cat /work/VERSION)" \
    --environment="OUTERSPACE_SOURCE_COMMIT=${OUTERSPACE_SOURCE_COMMIT:?Missing source identity}" \
    --environment="OUTERSPACE_HARDWARE_PROFILE=$hardware" \
    --build-sources=/work \
    --force \
    build
cp /source.tar /out/outerspace-source.tar
python3 /work/scripts/profiles.py stamp --root=/out --profile "$profile" --hardware "$hardware" \
    --commit "$OUTERSPACE_SOURCE_COMMIT"
