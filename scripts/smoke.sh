#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
exec docker run --rm --cap-drop=ALL --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$repo,dst=/work,readonly" \
    --mount "type=bind,src=$repo/build,dst=/out" \
    "${OUTERSPACE_BUILDER:-outerspace-builder:dev}" \
    python3 /work/scripts/boot-smoke.py /out
