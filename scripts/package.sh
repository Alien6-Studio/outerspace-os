#!/bin/bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
# Source commit must be explicit: do not label dirty local builds as committed.
if [[ -n $(git -C "$repo" status --porcelain --untracked-files=normal) ]]; then
    echo 'Commit the source before packaging a candidate.' >&2
    exit 1
fi
commit=$(git -C "$repo" rev-parse HEAD)
exec docker run --rm --cap-drop=ALL \
    --mount "type=bind,src=$repo,dst=/work,readonly" \
    --mount "type=bind,src=$repo/build,dst=/out" \
    "${OUTERSPACE_BUILDER:-outerspace-builder:dev}" \
    python3 /work/scripts/package.py --commit "$commit"
