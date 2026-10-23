#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
builder=${OUTERSPACE_BUILDER:-outerspace-builder:dev}
profile=${1:-}
hardware=${2:-cpu}
directory=$(python3 "$repo/scripts/profiles.py" directory --profile "$profile" --hardware "$hardware")
if [[ $# -gt 2 || -n $(git -C "$repo" status --porcelain --untracked-files=normal) ]]; then
    echo 'Build requires a committed source tree and an explicit profile.' >&2
    exit 1
fi
commit=$(git -C "$repo" rev-parse HEAD)
output="$repo/build/$directory"
mkdir -p "$output" "$repo/.cache"
source_tree=$(mktemp -d "${TMPDIR:-/tmp}/outerspace-source.XXXXXX")
trap 'rm -rf "$source_tree"' EXIT
git -C "$repo" archive --format=tar --output="$source_tree/source.tar" "$commit"
mkdir -p "$source_tree/tree/.cache"
tar -xf "$source_tree/source.tar" -C "$source_tree/tree"
if ! docker image inspect "$builder" >/dev/null 2>&1; then
    docker build -t "$builder" -f "$repo/build-support/Dockerfile" "$repo"
fi
# Privileges are confined to the disposable Linux builder. No host devices or
# Docker socket are mounted. mkosi needs mount/user namespaces to assemble an OS.
docker run --rm --privileged \
    --env "OUTERSPACE_SOURCE_COMMIT=$commit" \
    --mount "type=bind,src=$source_tree/tree,dst=/work,readonly" \
    --mount "type=bind,src=$source_tree/source.tar,dst=/source.tar,readonly" \
    --mount "type=bind,src=$repo/.cache,dst=/work/.cache,readonly" \
    --mount "type=bind,src=$output,dst=/out" \
    --mount "type=bind,src=$repo/.cache,dst=/cache" \
    "$builder" bash /work/scripts/build-in-container.sh "$profile" "$hardware"
