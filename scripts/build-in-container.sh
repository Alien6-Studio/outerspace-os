#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
set -euo pipefail
python3 /work/scripts/install-components.py fetch /cache/components "$(uname -m)" /work/components.lock.json
exec mkosi --directory=/work/image \
    --build-sources=/work \
    --force \
    "$@" build
