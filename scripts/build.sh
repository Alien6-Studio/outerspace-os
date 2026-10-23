#!/bin/bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
builder=${OUTERSPACE_BUILDER:-outerspace-builder:dev}
mkdir -p "$repo/build" "$repo/.cache"
if ! docker image inspect "$builder" >/dev/null 2>&1; then
    docker build -t "$builder" -f "$repo/build-support/Dockerfile" "$repo"
fi
# Privileges are confined to the disposable Linux builder. No host devices or
# Docker socket are mounted. mkosi needs mount/user namespaces to assemble an OS.
exec docker run --rm --privileged \
    --mount "type=bind,src=$repo,dst=/work,readonly" \
    --mount "type=bind,src=$repo/build,dst=/out" \
    --mount "type=bind,src=$repo/.cache,dst=/cache" \
    "$builder" bash /work/scripts/build-in-container.sh "$@"
