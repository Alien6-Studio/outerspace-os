#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
case "${1:-uefi}" in
    uefi) script=boot-uefi.py ;;
    split) script=boot-smoke.py ;;
    *) echo 'Usage: smoke.sh [uefi|split]' >&2; exit 2 ;;
esac
exec docker run --rm --cap-drop=ALL --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$repo,dst=/work,readonly" \
    --mount "type=bind,src=$repo/build,dst=/out" \
    "${OUTERSPACE_BUILDER:-outerspace-builder:dev}" \
    python3 "/work/scripts/$script" /out
