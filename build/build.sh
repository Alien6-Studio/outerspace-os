#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
builder=${OUTERSPACE_BUILDER:-outerspace-builder:dev}
profile=${1:-}
hardware=${2:-cpu}
directory=$("${PYTHON:-python3}" "$repo/build/tools/profiles.py" directory --profile "$profile" --hardware "$hardware")
if [[ $# -gt 2 || -n $(git -C "$repo" status --porcelain --untracked-files=normal) ]]; then
    echo 'Build requires a committed source tree and an explicit profile.' >&2
    exit 1
fi
commit=$(git -C "$repo" rev-parse HEAD)
output="$repo/out/$directory"
mkdir -p "$output" "$repo/.cache"
source_tree=$(mktemp -d "${TMPDIR:-/tmp}/outerspace-source.XXXXXX")
cleanup_source() {
    # Docker Desktop can return before releasing a nested read-only bind mount.
    for attempt in 1 2 3 4 5; do
        if rm -rf "$source_tree" 2>/dev/null; then return; fi
        sleep 1
    done
    rm -rf "$source_tree"
}
trap cleanup_source EXIT
git -C "$repo" archive --format=tar --output="$source_tree/source.tar" "$commit"
mkdir -p "$source_tree/tree/.cache"
tar -xf "$source_tree/source.tar" -C "$source_tree/tree"
if ! docker image inspect "$builder" >/dev/null 2>&1; then
    docker build -t "$builder" -f "$repo/build/Dockerfile" "$repo"
fi
# Privileges are confined to the disposable Linux builder. No host devices or
# Docker socket are mounted. mkosi needs mount/user namespaces to assemble an OS.
docker run --rm --privileged \
    --env "OUTERSPACE_SOURCE_COMMIT=$commit" \
    --mount "type=bind,src=$source_tree/tree,dst=/repo,readonly" \
    --mount "type=bind,src=$source_tree/source.tar,dst=/source.tar,readonly" \
    --mount "type=bind,src=$repo/.cache,dst=/repo/.cache,readonly" \
    --mount "type=bind,src=$output,dst=/out" \
    --mount "type=bind,src=$repo/.cache,dst=/cache" \
    "$builder" bash /repo/build/assemble.sh "$profile" "$hardware"
