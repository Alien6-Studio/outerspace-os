#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
profile=${1:-}
hardware=${2:-cpu}
directory=$(python3 "$repo/scripts/profiles.py" directory --profile "$profile" --hardware "$hardware")
case "${3:-uefi}" in
    uefi) script=boot-uefi.py ;;
    split) script=boot-smoke.py ;;
    *) echo 'Usage: smoke.sh PROFILE HARDWARE [uefi|split]' >&2; exit 2 ;;
esac
exec docker run --rm --cap-drop=ALL --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$repo,dst=/work,readonly" \
    --mount "type=bind,src=$repo/build/$directory,dst=/out" \
    "${OUTERSPACE_BUILDER:-outerspace-builder:dev}" \
    python3 "/work/scripts/$script" /out "$profile" "$hardware"
